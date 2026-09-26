//
//  JWTClaimsTests.swift
//  WXYCAuthTests
//
//  Pins the JWT payload decoder's error taxonomy, its base64url padding
//  behavior, and — the load-bearing one — `JWTClaims`'s at-rest coding, which
//  is an installed-build storage format and not merely a wire shape.
//
//  Created by Jake on 08/28/26.
//  Copyright © 2026 WXYC. All rights reserved.
//

import Foundation
import Testing

@testable import WXYCAuth

/// Builds a JWT whose payload segment is `json`, base64url-encoded without
/// padding — the encoding real providers emit, and the one the decoder has to
/// re-pad before Foundation will touch it.
private func makeJWT(payloadJSON json: String) -> String {
    let payload = Data(json.utf8).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
    return "header.\(payload).signature"
}

@Suite("JWTDecoder")
struct JWTDecoderTests {
    @Test("a token without exactly three segments is .malformed", arguments: [
        "", "onlyone", "two.segments", "four.segments.here.now",
    ])
    func malformed(token: String) {
        #expect(throws: JWTDecodeError.malformed) { try JWTDecoder.decode(token) }
    }

    @Test("a payload segment that is not base64url is .base64DecodeFailed")
    func base64DecodeFailed() {
        #expect(throws: JWTDecodeError.base64DecodeFailed) {
            try JWTDecoder.decode("header.!!not base64!!.signature")
        }
    }

    @Test("valid base64url that isn't the claims shape is .payloadDecodeFailed")
    func payloadDecodeFailed() {
        #expect(throws: JWTDecodeError.payloadDecodeFailed) {
            try JWTDecoder.decode(makeJWT(payloadJSON: #"{"sub":"dj"}"#))  // no exp
        }
    }

    /// Each JSON length below lands on a different `count % 4` for the encoded
    /// segment, so between them they exercise every re-padding branch. A
    /// decoder that skips padding fails on three of the four.
    // `email` is required, so these carry one; the four `sub` lengths still
    // differ by a byte each, which is what keeps all four padding remainders
    // covered.
    @Test("base64url payloads decode at every padding remainder", arguments: [
        #"{"exp":1800000000,"email":"dj@wxyc.org","sub":"a"}"#,
        #"{"exp":1800000000,"email":"dj@wxyc.org","sub":"ab"}"#,
        #"{"exp":1800000000,"email":"dj@wxyc.org","sub":"abc"}"#,
        #"{"exp":1800000000,"email":"dj@wxyc.org","sub":"abcd"}"#,
    ])
    func paddingRemainders(json: String) throws {
        let claims = try JWTDecoder.decode(makeJWT(payloadJSON: json))
        #expect(claims.expiration == Date(timeIntervalSince1970: 1_800_000_000))
    }

    @Test("base64url's - and _ substitutions are reversed before decoding")
    func urlSafeAlphabet() throws {
        // "ÿÿ>" and "?" round-trip through the + and / positions of the
        // standard alphabet, so a decoder that forgets the substitution fails.
        let json = #"{"exp":1800000000,"email":"dj@wxyc.org","sub":"\#(String("ÿÿ>?"))"}"#
        let claims = try JWTDecoder.decode(makeJWT(payloadJSON: json))
        #expect(claims.sub == "ÿÿ>?")
    }

    @Test("sub and role are absent-tolerant; email and exp are required")
    func optionalClaims() throws {
        let json = #"{"exp":1800000000,"email":"dj@wxyc.org"}"#
        let claims = try JWTDecoder.decode(makeJWT(payloadJSON: json))
        #expect(claims.sub == nil)
        #expect(claims.role == nil)
        // Typed `String`, not inferred: this binding stops compiling if
        // `email` is ever relaxed back to `String?`, which is the whole of
        // what its non-optionality buys a caller. A value assertion cannot
        // tell the two types apart.
        let email: String = claims.email
        #expect(email == "dj@wxyc.org")
    }

    /// Backend-Service cannot omit this claim — `buildJwtPayload` spreads
    /// better-auth's user record, where `email` is a required column, and the
    /// anonymous plugin synthesizes an address rather than leaving it out — so
    /// a token without a usable one is refused here instead of handing every
    /// caller a `nil`. Both shapes are covered because an omitted claim and an
    /// explicit `null` are different wire facts that `decodeIfPresent` used to
    /// collapse into the same value.
    @Test("a token with no usable email claim is .payloadDecodeFailed", arguments: [
        #"{"exp":1800000000,"sub":"dj-42","role":"dj"}"#,
        #"{"exp":1800000000,"sub":"dj-42","email":null,"role":"dj"}"#,
    ])
    func emailIsRequired(json: String) {
        #expect(throws: JWTDecodeError.payloadDecodeFailed) {
            try JWTDecoder.decode(makeJWT(payloadJSON: json))
        }
    }

    @Test("all four claims are read")
    func fullClaims() throws {
        let json = #"{"sub":"dj-42","email":"dj@wxyc.org","role":"dj","exp":1800000000}"#
        let claims = try JWTDecoder.decode(makeJWT(payloadJSON: json))
        #expect(claims == JWTClaims(
            sub: "dj-42",
            email: "dj@wxyc.org",
            role: "dj",
            exp: Date(timeIntervalSince1970: 1_800_000_000)
        ))
    }
}

@Suite("JWTClaims at-rest coding")
struct JWTClaimsCodingTests {
    /// wxyc-dj-ios persists this JSON to the Keychain as its issue-#57 offline
    /// grace anchor, so `exp` is an **at-rest** format, not just a wire shape:
    /// a synthesized `Codable` would ride the consumer's date strategy
    /// (`.iso8601` under dj-ios's `JSONCoders`) and silently orphan every
    /// installed build's stored anchor. This is that guard — a byte-for-byte
    /// decode of a captured legacy anchor.
    @Test("a captured legacy dj-ios grace anchor decodes unchanged")
    func legacyGraceAnchorDecodes() throws {
        let captured = #"{"sub":"dj-42","email":"dj@wxyc.org","role":"dj","exp":1800000000}"#
        let claims = try JSONDecoder().decode(JWTClaims.self, from: Data(captured.utf8))
        #expect(claims.sub == "dj-42")
        #expect(claims.email == "dj@wxyc.org")
        #expect(claims.role == "dj")
        #expect(claims.exp == Date(timeIntervalSince1970: 1_800_000_000))
    }

    @Test("exp encodes as epoch seconds, not an ISO-8601 string")
    func expEncodesAsEpochSeconds() throws {
        let claims = JWTClaims(sub: nil, email: "dj@wxyc.org", role: nil, exp: Date(timeIntervalSince1970: 1_800_000_000))
        let json = try JSONEncoder().encode(claims)
        let object = try #require(try JSONSerialization.jsonObject(with: json) as? [String: Any])
        #expect(object["exp"] as? TimeInterval == 1_800_000_000)
    }

    /// The encoder must not ride the *caller's* date strategy either — dj-ios
    /// encodes the anchor through a `JSONCoders.encoder` configured `.iso8601`,
    /// and a synthesized `encode(to:)` would honor it.
    @Test("exp ignores an encoder configured for ISO-8601 dates")
    func expIgnoresEncoderDateStrategy() throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let claims = JWTClaims(sub: nil, email: "dj@wxyc.org", role: nil, exp: Date(timeIntervalSince1970: 1_800_000_000))
        let object = try JSONSerialization.jsonObject(with: try encoder.encode(claims)) as? [String: Any]
        #expect(object?["exp"] as? TimeInterval == 1_800_000_000)
    }

    @Test("round-trips through encode and decode")
    func roundTrip() throws {
        let claims = JWTClaims(sub: "dj-42", email: "dj@wxyc.org", role: "dj", exp: Date(timeIntervalSince1970: 1_800_000_000))
        let decoded = try JSONDecoder().decode(JWTClaims.self, from: try JSONEncoder().encode(claims))
        #expect(decoded == claims)
    }
}

//
//  JWTClaims.swift
//  WXYCAuth
//
//  Client-side JWT payload decoding: the claims both apps read, and the
//  signature-free decoder that produces them. The server validates the
//  signature against JWKS on every request; nothing here is a security check.
//
//  Created by Jake on 08/28/26.
//  Copyright © 2026 WXYC. All rights reserved.
//

import Foundation

/// The payload claims Backend-Service issues, as both consumers read them.
///
/// `sub` and `role` are optional; `email` and `exp` are not.
///
/// The consumers do read disjoint subsets — wxyc-dj-ios reads
/// `sub`/`email`/`role`, wxyc-ios-64 reads `exp` alone — but a claim going
/// unread is a reason to tolerate its *absence* only where the server can
/// actually omit it. For `email` it cannot: Backend-Service's `definePayload`
/// is `buildJwtPayload(user, …)`, which spreads better-auth's user record into
/// the payload, and `email` is a required column there. **An anonymous session
/// is not the exception it looks like** — better-auth's anonymous plugin
/// synthesizes `temp-<id>@anonymous.wxyc.org` whenever `emailDomainName` is
/// set, which `auth.definition.ts` sets, so ios-64's cold-start path carries
/// one too. (An earlier revision of this comment claimed the opposite and used
/// it to justify the optionality; it was wrong about `email` and right only
/// about `role`.) A token without the claim is therefore not a session either
/// app can represent, and decoding it to a `nil` pushes that hole into every
/// caller instead of refusing it at the boundary.
///
/// `role`'s optionality is the load-bearing one, and it *is* about a genuinely
/// absent claim: the same `buildJwtPayload` sets it only when the `auth_member`
/// lookup returns a row, so a user with no membership has no role claim at all.
///
/// Two costs follow from requiring `email`, both accepted. A token missing it
/// fails the *whole* decode, which both consumers' JWT legs treat as transient
/// and re-mintable (dj-ios's issue-#53 pending window), so it defers a JWT
/// rather than signing anyone out. And because this type is also an at-rest
/// format (below), a dj-ios grace anchor persisted without the claim stops
/// decoding, costing that install one offline cold-launch restore; every anchor
/// written from a real server token carries it, so that is expected to be
/// unreachable in practice.
///
/// **`exp`'s coding is hand-written on purpose, and must stay that way.**
/// wxyc-dj-ios persists this JSON into the Keychain as its issue-#57 offline
/// grace anchor, so the encoding is an *at-rest* format, not just a wire shape.
/// A synthesized `Codable` would ride whatever `dateEncodingStrategy` the
/// caller's encoder carries — `.iso8601` under dj-ios's `JSONCoders` — and
/// silently orphan every installed build's stored anchor, which reads as "the
/// DJ was signed out by an update" and is unrecoverable offline. Coding
/// `exp` by hand as epoch seconds pins the format to this file.
public struct JWTClaims: Codable, Sendable, Equatable {
    public let sub: String?
    public let email: String
    public let role: String?
    public let exp: Date

    /// `exp` under the name the orchestrators read it by. Ships as a property
    /// on the struct rather than arriving via a consumer-side extension
    /// because a `typealias` (how dj-ios adopts this type in Phase C) can add
    /// neither a property nor an initializer.
    public var expiration: Date { exp }

    public init(sub: String?, email: String, role: String?, exp: Date) {
        self.sub = sub
        self.email = email
        self.role = role
        self.exp = exp
    }

    private enum CodingKeys: String, CodingKey {
        case sub, email, role, exp
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        sub = try container.decodeIfPresent(String.self, forKey: .sub)
        email = try container.decode(String.self, forKey: .email)
        role = try container.decodeIfPresent(String.self, forKey: .role)
        exp = Date(timeIntervalSince1970: try container.decode(TimeInterval.self, forKey: .exp))
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(sub, forKey: .sub)
        try container.encode(email, forKey: .email)
        try container.encodeIfPresent(role, forKey: .role)
        try container.encode(exp.timeIntervalSince1970, forKey: .exp)
    }
}

/// Why a token could not be read. Three cases, deliberately: wxyc-dj-ios's
/// `JWTDecodeError` has exactly these and its tests assert by case, so the
/// Phase C adoption is a `typealias` rather than a rewrite of every catch arm.
public enum JWTDecodeError: Error, Sendable, Equatable {
    /// Not `header.payload.signature`.
    case malformed
    /// The payload segment is not decodable base64url.
    case base64DecodeFailed
    /// The payload decoded to bytes that are not ``JWTClaims``.
    case payloadDecodeFailed
}

public enum JWTDecoder {
    /// Reads a token's claims **without verifying its signature**.
    public static func decode(_ token: String) throws -> JWTClaims {
        let segments = token.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3 else { throw JWTDecodeError.malformed }
        guard let data = base64URLDecode(String(segments[1])) else {
            throw JWTDecodeError.base64DecodeFailed
        }
        do {
            return try JSONDecoder().decode(JWTClaims.self, from: data)
        } catch {
            throw JWTDecodeError.payloadDecodeFailed
        }
    }

    /// base64url → `Data`: reverse the URL-safe substitutions, then restore the
    /// padding real providers strip. Foundation's decoder rejects an unpadded
    /// string outright, so the re-pad is not cosmetic.
    static func base64URLDecode(_ input: String) -> Data? {
        var standard = input.replacing("-", with: "+").replacing("_", with: "/")
        let remainder = standard.count % 4
        if remainder > 0 { standard.append(String(repeating: "=", count: 4 - remainder)) }
        return Data(base64Encoded: standard)
    }
}

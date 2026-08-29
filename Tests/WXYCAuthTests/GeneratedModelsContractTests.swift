//
//  GeneratedModelsContractTests.swift
//  WXYCAuthTests
//
//  Pins the facts about the vendored api.yaml-generated auth models that this
//  package's hand-written code depends on. These are not tests of the generator
//  — scripts/verify-api-types.sh already proves the tree matches the pinned
//  contract byte for byte. They are tests of the *decisions taken because of*
//  what the contract says, each of which would otherwise silently stop being
//  true on a pin bump: which fields are required, which enum tolerates an
//  unknown value, and which schema is deliberately NOT used.
//
//  Created by Jake on 08/28/26.
//  Copyright © 2026 WXYC. All rights reserved.
//

import Foundation
import Testing
@testable import WXYCAuth
import WXYCAuthTesting

@Suite("Generated auth model contract")
struct GeneratedModelsContractTests {

    // MARK: - Required fields the wire client leans on

    @Test("AuthErrorResponse requires `message`, which is what makes error-body detection discriminating")
    func errorBodyRequiresMessage() throws {
        // The better-auth vocabulary decodes.
        let betterAuth = try #require(AuthWireErrorBody(decoding: Data(#"{"message":"nope","code":"INVALID_OTP"}"#.utf8)))
        #expect(betterAuth.message == "nope")
        #expect(betterAuth.code == "INVALID_OTP")

        // Backend-Service's own routes and its Express limiter answer in a
        // DIFFERENT vocabulary. It must not decode — a required `message` is
        // the only thing separating "a better-auth error the caller can render"
        // from "some other JSON object", and if the schema ever relaxed it this
        // would start returning an all-nil value that reads like a successful
        // parse. `AuthWireError.status`'s doc comment promises this behavior.
        #expect(AuthWireErrorBody(decoding: Data(#"{"error":"Too many requests"}"#.utf8)) == nil)

        // `code` is genuinely optional — better-auth omits it on some paths.
        let codeless = try #require(AuthWireErrorBody(decoding: Data(#"{"message":"nope"}"#.utf8)))
        #expect(codeless.code == nil)
    }

    @Test("AuthTokenResponse is the JWT mint's declared body and needs only `token`")
    func tokenResponseNeedsOnlyToken() throws {
        let decoded = try JSONDecoder().decode(AuthTokenResponse.self, from: Data(#"{"token":"header.payload.signature"}"#.utf8))
        #expect(decoded.token == "header.payload.signature")
    }

    @Test("LookupEmailResponse carries a nullable email, so a no-match answer parses rather than throwing")
    func lookupEmailDecodesExplicitNull() throws {
        // The distinction `AuthWireError.missingLookupResult` exists for: the
        // response is well formed, it just said no. If this ever became a decode
        // failure the caller would surface "malformed response" for an ordinary
        // unknown username.
        let decoded = try JSONDecoder().decode(LookupEmailResponse.self, from: Data(#"{"email":null}"#.utf8))
        #expect(decoded.email == nil)
    }

    // MARK: - Why AnonymousSignInBody stays hand-rolled

    @Test("AuthUser requires email, emailVerified and name")
    func authUserRequiresProfileFields() {
        // This is the fact that keeps `AnonymousSignInBody` hand-rolled instead
        // of using the generated `AuthTokenAndUserResult`. Anonymous sign-in is
        // wxyc-ios-64's cold-start path and this package surfaces only `user.id`
        // from it, so decoding the full user would let a benign upstream field
        // change fail every launch for a value nobody reads.
        //
        // If this test ever fails because the schema relaxed these to optional,
        // that is the signal to delete `AnonymousSignInBody` and decode the
        // generated type — not to weaken the assertion.
        for missing in ["email", "emailVerified", "name"] {
            var object: [String: Any] = [
                "id": "anon-1",
                "email": "anon@example.invalid",
                "emailVerified": false,
                "name": "Anonymous",
            ]
            object.removeValue(forKey: missing)
            let data = try! JSONSerialization.data(withJSONObject: object)
            #expect(throws: DecodingError.self, "AuthUser decoded without \(missing)") {
                try JSONDecoder().decode(AuthUser.self, from: data)
            }
        }
    }

    @Test("the anonymous body this client actually decodes ignores every user field but id")
    func anonymousBodyIgnoresProfileFields() async throws {
        // The behavioral half of the assertion above: a realistically sparse
        // anonymous response still signs in.
        let session = StubAuthRequestSession([
            .json(status: 200, #"{"token":"session-abc","user":{"id":"anon-1"}}"#)
        ])
        let client = AuthWireClient(authBaseURL: URL(string: "https://api.example.invalid/auth")!, session: session)

        let result = try await client.signInAnonymously(deviceFingerprint: nil)

        #expect(result.sessionToken == "session-abc")
        #expect(result.userId == "anon-1")
    }

    // MARK: - Enum tolerance, and the Infrastructure it depends on

    @Test("OTPType decodes an unrecognized value rather than throwing")
    func otpTypeToleratesUnknownValues() throws {
        // This is the whole reason `Infrastructure/Models.swift` is vendored:
        // `CaseIterableDefaultsLast` supplies the initializer that maps an
        // unrecognized raw value onto the trailing case, and
        // `UnknownCaseCheckable` is how a caller tells that apart from a real
        // one. A generator or contract change that dropped either would turn a
        // new server-side OTP type into a decode failure.
        let known = try JSONDecoder().decode(OTPType.self, from: Data(#""sign-in""#.utf8))
        #expect(known == .signIn)
        #expect(known.containsUnknownDefaultOpenApiCase == false)

        let unknown = try JSONDecoder().decode(OTPType.self, from: Data(#""some-future-flow""#.utf8))
        #expect(unknown == .unknownDefaultOpenApi)
        #expect(unknown.containsUnknownDefaultOpenApiCase)
    }

    // MARK: - Round-trip

    @Test("AuthSignInResult decodes a password-route body with `url` omitted")
    func signInResultOmitsURLWhenNoCallbackWasSupplied() throws {
        // better-auth passes `url: ctx.body.callbackURL` (undefined) straight
        // into ctx.json, and JSON serialization drops an undefined-valued key —
        // so the key is ABSENT, not present-and-null. The schema documents this
        // and leaves `url` out of `required`; pin it, because a client that
        // assumed present-and-null would fail every headless sign-in.
        let body = """
        {"redirect":false,"token":"session-abc","user":{"id":"u1","email":"dj@wxyc.org","emailVerified":true,"name":"DJ"}}
        """
        let decoded = try JSONDecoder().decode(AuthSignInResult.self, from: Data(body.utf8))
        #expect(decoded.url == nil)
        #expect(decoded.token == "session-abc")
        #expect(decoded.user.email == "dj@wxyc.org")
    }
}

//
//  AuthWireClientTests.swift
//  WXYCAuthTests
//
//  The wire behaviors that are the package's whole reason to exist: session
//  token capture on every credentialed route, the outcome taxonomy's
//  cancellation carve-out, status surfacing without policy, and the cookie-free
//  double guard.
//
//  Created by Jake on 08/28/26.
//  Copyright © 2026 WXYC. All rights reserved.
//

import Foundation
import Testing

@testable import WXYCAuth
import WXYCAuthTesting

private let authBaseURL = URL(string: "https://api.wxyc.test/auth")!

/// A JWT whose payload is `{"sub":"dj-42","exp":1800000000}`, unpadded
/// base64url — the encoding a real provider emits.
private let sampleJWT: String = {
    let payload = Data(#"{"sub":"dj-42","exp":1800000000}"#.utf8).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
    return "header.\(payload).signature"
}()

/// Collects `onOutcome` reports.
private final class OutcomeLog: @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [RequestOutcome] = []

    var outcomes: [RequestOutcome] { lock.withLock { recorded } }

    var hook: @Sendable (RequestOutcome) -> Void {
        { outcome in self.lock.withLock { self.recorded.append(outcome) } }
    }
}

private func makeClient(
    _ session: StubAuthRequestSession,
    defaultHeaders: [String: String] = [:],
    onOutcome: (@Sendable (RequestOutcome) -> Void)? = nil
) -> AuthWireClient {
    AuthWireClient(
        authBaseURL: authBaseURL,
        session: session,
        timeout: 5,
        defaultHeaders: defaultHeaders,
        onOutcome: onOutcome
    )
}

@Suite("Session token capture")
struct SessionTokenCaptureTests {
    /// `bearer()` is a global better-auth plugin, so `set-auth-token` arrives
    /// identically on every credentialed route. All three are asserted because
    /// the shared capture is only a saving if a new route cannot opt out of it.
    @Test("set-auth-token is captured on all three credentialed routes")
    func headerCaptureAcrossRoutes() async throws {
        let responses = { StubAuthRequestSession(.json(#"{}"#, headers: ["set-auth-token": "session-abc"])) }

        var session = responses()
        #expect(try await makeClient(session).signIn(email: "dj@wxyc.org", password: "pw").sessionToken == "session-abc")
        #expect(session.requests.first?.url?.path == "/auth/sign-in/email")

        session = responses()
        #expect(try await makeClient(session).signIn(username: "dj", password: "pw").sessionToken == "session-abc")
        #expect(session.requests.first?.url?.path == "/auth/sign-in/username")

        session = responses()
        #expect(try await makeClient(session).signIn(email: "dj@wxyc.org", otp: "123456").sessionToken == "session-abc")
        #expect(session.requests.first?.url?.path == "/auth/sign-in/email-otp")
    }

    @Test("a response without the header falls back to the body's token")
    func bodyFallback() async throws {
        let session = StubAuthRequestSession(.json(#"{"token":"session-from-body"}"#))
        let result = try await makeClient(session).signIn(email: "dj@wxyc.org", password: "pw")
        #expect(result.sessionToken == "session-from-body")
    }

    @Test("the header wins when both carry a token")
    func headerBeatsBody() async throws {
        let session = StubAuthRequestSession(
            .json(#"{"token":"from-body"}"#, headers: ["set-auth-token": "from-header"])
        )
        let result = try await makeClient(session).signIn(username: "dj", password: "pw")
        #expect(result.sessionToken == "from-header")
    }

    /// An empty header value is not a token. Falling for it would hand the
    /// orchestrator an empty bearer that 401s on the very next request, which
    /// reads as "wrong password" on a sign-in that actually succeeded.
    @Test("an empty header value falls through to the body")
    func emptyHeaderIsNotAToken() async throws {
        let session = StubAuthRequestSession(
            .json(#"{"token":"from-body"}"#, headers: ["set-auth-token": ""])
        )
        #expect(try await makeClient(session).signIn(username: "dj", password: "pw").sessionToken == "from-body")
    }

    @Test("a 2xx carrying no token anywhere is .missingSessionToken")
    func missingSessionToken() async throws {
        let session = StubAuthRequestSession(.json(#"{"ok":true}"#))
        await #expect(throws: AuthWireError.self) {
            try await makeClient(session).signIn(email: "dj@wxyc.org", password: "pw")
        }
        do {
            _ = try await makeClient(StubAuthRequestSession(.json(#"{"ok":true}"#)))
                .signIn(email: "dj@wxyc.org", password: "pw")
        } catch let error as AuthWireError {
            guard case .missingSessionToken = error else {
                Issue.record("expected .missingSessionToken, got \(error)")
                return
            }
        }
    }
}

@Suite("Status surfacing")
struct StatusSurfacingTests {
    /// The wire client classifies **status**, never meaning. dj-ios maps 401 to
    /// "wrong credentials" and 429 to a rate-limit banner; ios-64 maps neither
    /// that way. Both numbers therefore arrive intact.
    @Test("a served non-2xx surfaces its status and body verbatim", arguments: [400, 401, 403, 422, 429, 500])
    func statusPassesThrough(status: Int) async throws {
        let session = StubAuthRequestSession(.json(status: status, #"{"message":"nope","code":"NOPE"}"#))
        do {
            _ = try await makeClient(session).signIn(email: "dj@wxyc.org", password: "pw")
            Issue.record("expected a throw for status \(status)")
        } catch let AuthWireError.status(code, body) {
            #expect(code == status)
            #expect(AuthWireErrorBody(decoding: body) == AuthWireErrorBody(message: "nope", code: "NOPE"))
        }
    }

    /// A 401 on `/auth/token` means the session is gone; a 404 means the route
    /// moved. Conflating them signs a DJ out over a deploy typo, so the numbers
    /// stay distinct all the way to the caller.
    @Test("401 and 404 on /auth/token stay distinguishable", arguments: [401, 404])
    func mintJWTStatuses(status: Int) async throws {
        let session = StubAuthRequestSession(.http(status: status))
        do {
            _ = try await makeClient(session).mintJWT(sessionToken: "session", deviceFingerprint: nil)
            Issue.record("expected a throw")
        } catch let AuthWireError.status(code, _) {
            #expect(code == status)
        }
    }

    /// Backend-Service's own routes and its Express limiter answer `{error: …}`,
    /// which is not better-auth's vocabulary — so the decode returning `nil` is
    /// the expected outcome there, and callers on those paths map by status.
    @Test("a non-better-auth error body simply doesn't decode")
    func foreignErrorVocabulary() {
        #expect(AuthWireErrorBody(decoding: Data(#"{"error":"Too many requests"}"#.utf8)) == nil)
    }
}

@Suite("Outcome reporting")
struct OutcomeReportingTests {
    @Test("a served response reports .answered with its status")
    func answered() async throws {
        let log = OutcomeLog()
        let session = StubAuthRequestSession(.json(#"{}"#, headers: ["set-auth-token": "t"]))
        _ = try await makeClient(session, onOutcome: log.hook).signIn(username: "dj", password: "pw")
        guard case .answered(let status) = log.outcomes.first else {
            Issue.record("expected .answered, got \(log.outcomes)")
            return
        }
        #expect(status == 200)
    }

    @Test("a non-2xx still reports .answered — it is an answer")
    func answeredNonSuccess() async throws {
        let log = OutcomeLog()
        let session = StubAuthRequestSession(.http(status: 401))
        _ = try? await makeClient(session, onOutcome: log.hook).signIn(username: "dj", password: "pw")
        guard case .answered(let status) = log.outcomes.first else {
            Issue.record("expected .answered, got \(log.outcomes)")
            return
        }
        #expect(status == 401)
    }

    @Test("a transport error reports .transportFailure and preserves it")
    func transportFailure() async throws {
        let log = OutcomeLog()
        let session = StubAuthRequestSession(.failure(URLError(.timedOut)))
        do {
            _ = try await makeClient(session, onOutcome: log.hook).signIn(username: "dj", password: "pw")
            Issue.record("expected a throw")
        } catch let AuthWireError.transport(underlying) {
            #expect((underlying as? URLError)?.code == .timedOut)
        }
        guard case .transportFailure(let reported) = log.outcomes.first else {
            Issue.record("expected .transportFailure, got \(log.outcomes)")
            return
        }
        #expect((reported as? URLError)?.code == .timedOut)
    }

    /// The carve-out both apps learned the hard way: a cancelled request is not
    /// evidence about the network. dj-ios's search debounce cancels the
    /// in-flight request on every keystroke, so reporting cancellation as a
    /// transport failure latched its offline state on every keystroke.
    @Test("cancellation reports .cancelled, never .transportFailure", arguments: [
        URLError(.cancelled) as any Error, CancellationError() as any Error,
    ])
    func cancellationCarveOut(error: any Error) async throws {
        let log = OutcomeLog()
        let session = StubAuthRequestSession(.failure(error))
        do {
            _ = try await makeClient(session, onOutcome: log.hook).signIn(username: "dj", password: "pw")
            Issue.record("expected a throw")
        } catch let thrown as AuthWireError {
            guard case .cancelled = thrown else {
                Issue.record("expected .cancelled, got \(thrown)")
                return
            }
        }
        guard case .cancelled = log.outcomes.first else {
            Issue.record("expected .cancelled, got \(log.outcomes)")
            return
        }
    }

    /// A response with no HTTP status is a bug in the client or its stub, not a
    /// network condition — so it is deliberately *not* reported as a transport
    /// failure, which would latch a consumer's offline state on a defect.
    @Test("a non-HTTP response throws without reporting an outcome")
    func nonHTTPResponse() async throws {
        let log = OutcomeLog()
        let session = StubAuthRequestSession(.nonHTTP)
        do {
            _ = try await makeClient(session, onOutcome: log.hook).signIn(username: "dj", password: "pw")
            Issue.record("expected a throw")
        } catch let thrown as AuthWireError {
            guard case .nonHTTPResponse = thrown else {
                Issue.record("expected .nonHTTPResponse, got \(thrown)")
                return
            }
        }
        #expect(log.outcomes.isEmpty)
    }
}

@Suite("JWT exchange")
struct MintJWTTests {
    @Test("the minted token and its decoded claims are returned")
    func mintsAndDecodes() async throws {
        let session = StubAuthRequestSession(.json(#"{"token":"\#(sampleJWT)"}"#))
        let minted = try await makeClient(session).mintJWT(sessionToken: "session", deviceFingerprint: nil)
        #expect(minted.jwt == sampleJWT)
        #expect(minted.claims.sub == "dj-42")
        #expect(minted.claims.expiration == Date(timeIntervalSince1970: 1_800_000_000))
    }

    @Test("the request is a GET bearing the session token")
    func requestShape() async throws {
        let session = StubAuthRequestSession(.json(#"{"token":"\#(sampleJWT)"}"#))
        _ = try await makeClient(session).mintJWT(sessionToken: "session-abc", deviceFingerprint: nil)
        let request = try #require(session.requests.first)
        #expect(request.httpMethod == "GET")
        #expect(request.url?.path == "/auth/token")
        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer session-abc")
    }

    /// The header reads like a rotation and is not one — it is a deterministic
    /// re-encoding of the same, unchanged session token. It is surfaced because
    /// both apps read it, and each then applies its own (opposite, both
    /// correct) policy.
    @Test("a set-auth-token header is surfaced rather than acted on")
    func rotationSurfaced() async throws {
        let session = StubAuthRequestSession(
            .json(#"{"token":"\#(sampleJWT)"}"#, headers: ["set-auth-token": "re-encoded"])
        )
        let minted = try await makeClient(session).mintJWT(sessionToken: "session", deviceFingerprint: nil)
        #expect(minted.rotatedSessionToken == "re-encoded")
    }

    @Test("an absent header surfaces as nil")
    func noRotation() async throws {
        let session = StubAuthRequestSession(.json(#"{"token":"\#(sampleJWT)"}"#))
        let minted = try await makeClient(session).mintJWT(sessionToken: "session", deviceFingerprint: nil)
        #expect(minted.rotatedSessionToken == nil)
    }

    /// The capture is raw: an empty-valued header is `""`, not `nil`, so a
    /// consumer cannot read `if let` as ruling out an empty string. Pinned
    /// because ios-64's `JWTExchangeResult` documents exactly this and a
    /// helpful normalization here would silently change its meaning.
    @Test("an empty header value surfaces as an empty string, not nil")
    func emptyRotationIsNotNil() async throws {
        let session = StubAuthRequestSession(
            .json(#"{"token":"\#(sampleJWT)"}"#, headers: ["set-auth-token": ""])
        )
        let minted = try await makeClient(session).mintJWT(sessionToken: "session", deviceFingerprint: nil)
        #expect(minted.rotatedSessionToken == "")
    }

    @Test("a 2xx body that isn't the token shape is .decoding, not .transport")
    func decodeFailureIsItsOwnPhase() async throws {
        let session = StubAuthRequestSession(.json(#"{"nope":true}"#))
        do {
            _ = try await makeClient(session).mintJWT(sessionToken: "session", deviceFingerprint: nil)
            Issue.record("expected a throw")
        } catch let thrown as AuthWireError {
            guard case .decoding = thrown else {
                Issue.record("expected .decoding, got \(thrown)")
                return
            }
        }
    }

    @Test("an undecodable JWT is .decoding too")
    func undecodableJWT() async throws {
        let session = StubAuthRequestSession(.json(#"{"token":"not-a-jwt"}"#))
        do {
            _ = try await makeClient(session).mintJWT(sessionToken: "session", deviceFingerprint: nil)
            Issue.record("expected a throw")
        } catch let thrown as AuthWireError {
            guard case .decoding = thrown else {
                Issue.record("expected .decoding, got \(thrown)")
                return
            }
        }
    }
}

@Suite("Anonymous sign-in")
struct AnonymousSignInTests {
    @Test("returns the session token and the assigned user id")
    func result() async throws {
        let session = StubAuthRequestSession(
            .json(#"{"token":"anon-session","user":{"id":"user-7"}}"#)
        )
        let result = try await makeClient(session).signInAnonymously(deviceFingerprint: nil)
        #expect(result == AnonymousSignInResult(sessionToken: "anon-session", userId: "user-7"))
    }

    @Test("the header token wins over the body's, as on the credentialed routes")
    func headerPreferred() async throws {
        let session = StubAuthRequestSession(
            .json(#"{"token":"from-body","user":{"id":"user-7"}}"#, headers: ["set-auth-token": "from-header"])
        )
        let result = try await makeClient(session).signInAnonymously(deviceFingerprint: nil)
        #expect(result.sessionToken == "from-header")
    }

    @Test("the device fingerprint rides X-Device-Fingerprint when present")
    func fingerprintHeader() async throws {
        let session = StubAuthRequestSession(.json(#"{"token":"t","user":{"id":"u"}}"#))
        _ = try await makeClient(session).signInAnonymously(deviceFingerprint: "device-uuid")
        #expect(session.requests.first?.value(forHTTPHeaderField: "X-Device-Fingerprint") == "device-uuid")
    }

    /// A missing fingerprint costs the audit-trail association and nothing
    /// else, so the header is omitted rather than sent empty.
    @Test("a nil fingerprint omits the header entirely")
    func noFingerprintHeader() async throws {
        let session = StubAuthRequestSession(.json(#"{"token":"t","user":{"id":"u"}}"#))
        _ = try await makeClient(session).signInAnonymously(deviceFingerprint: nil)
        #expect(session.requests.first?.value(forHTTPHeaderField: "X-Device-Fingerprint") == nil)
    }

    @Test("the fingerprint rides the JWT exchange too")
    func fingerprintOnMint() async throws {
        let session = StubAuthRequestSession(.json(#"{"token":"\#(sampleJWT)"}"#))
        _ = try await makeClient(session).mintJWT(sessionToken: "s", deviceFingerprint: "device-uuid")
        #expect(session.requests.first?.value(forHTTPHeaderField: "X-Device-Fingerprint") == "device-uuid")
    }
}

@Suite("lookup-email")
struct LookUpEmailTests {
    @Test("resolves an identifier to an address")
    func resolves() async throws {
        let session = StubAuthRequestSession(.json(#"{"email":"dj@wxyc.org"}"#))
        #expect(try await makeClient(session).lookUpEmail(identifier: "dj") == "dj@wxyc.org")
        #expect(session.requests.first?.url?.path == "/auth/wxyc/lookup-email")
    }

    /// `{"email": null}` is a well-formed *rejection*, not a malformed
    /// response, and the caller has copy for it — so it must not arrive as a
    /// decode failure.
    @Test("a null or empty address is a rejection, not a decode failure", arguments: [
        #"{"email":null}"#, #"{"email":""}"#, #"{}"#,
    ])
    func noMatch(json: String) async throws {
        let session = StubAuthRequestSession(.json(json))
        do {
            _ = try await makeClient(session).lookUpEmail(identifier: "nobody")
            Issue.record("expected a throw")
        } catch let thrown as AuthWireError {
            guard case .missingLookupResult = thrown else {
                Issue.record("expected .missingLookupResult, got \(thrown)")
                return
            }
        }
    }

    @Test("a rate limit surfaces as a status, for the caller to word")
    func rateLimited() async throws {
        let session = StubAuthRequestSession(.json(status: 429, #"{"error":"Too many requests"}"#))
        do {
            _ = try await makeClient(session).lookUpEmail(identifier: "dj")
            Issue.record("expected a throw")
        } catch let AuthWireError.status(code, _) {
            #expect(code == 429)
        }
    }
}

@Suite("Request shape")
struct RequestShapeTests {
    /// The half of the cookie-free guard that survives an injected session —
    /// which the `AuthRequestSession` seam makes routine, since an adapter over
    /// a consumer's own session type bypasses `makeCookieFreeSession()`
    /// entirely. Asserted across every endpoint, because the guard is only
    /// worth having if a new method cannot forget it.
    @Test("every request suppresses cookie handling")
    func cookiesSuppressedEverywhere() async throws {
        let session = StubAuthRequestSession([
            .json(#"{"token":"t","user":{"id":"u"}}"#, headers: ["set-auth-token": "t"]),
        ])
        let client = makeClient(session)
        _ = try? await client.signIn(email: "dj@wxyc.org", password: "pw")
        _ = try? await client.signIn(username: "dj", password: "pw")
        _ = try? await client.signIn(email: "dj@wxyc.org", otp: "123456")
        _ = try? await client.sendVerificationOTP(email: "dj@wxyc.org")
        _ = try? await client.lookUpEmail(identifier: "dj")
        _ = try? await client.signInAnonymously(deviceFingerprint: nil)
        _ = try? await client.mintJWT(sessionToken: "s", deviceFingerprint: nil)
        _ = try? await client.signOut(sessionToken: "s")

        #expect(session.requests.count == 8)
        #expect(session.requests.allSatisfy { $0.httpShouldHandleCookies == false })
    }

    @Test("the cookie-free session stores, accepts, and sends nothing")
    func cookieFreeSessionConfiguration() {
        let configuration = AuthWireClient.makeCookieFreeSession().configuration
        #expect(configuration.httpCookieStorage == nil)
        #expect(configuration.httpShouldSetCookies == false)
        #expect(configuration.httpCookieAcceptPolicy == .never)
    }

    /// ios-64 sends `Origin` and `User-Agent`; dj-ios sends neither, and adding
    /// an `Origin` to its requests would change which better-auth middleware
    /// they arm. So they are caller data, not a baked-in constant.
    @Test("default headers ride every request")
    func defaultHeaders() async throws {
        let session = StubAuthRequestSession(.json(#"{}"#, headers: ["set-auth-token": "t"]))
        let client = makeClient(session, defaultHeaders: ["Origin": "https://api.wxyc.test", "User-Agent": "WXYC/1.0"])
        _ = try await client.signIn(username: "dj", password: "pw")
        let request = try #require(session.requests.first)
        #expect(request.value(forHTTPHeaderField: "Origin") == "https://api.wxyc.test")
        #expect(request.value(forHTTPHeaderField: "User-Agent") == "WXYC/1.0")
    }

    @Test("credential bodies are JSON with the route's own field names")
    func credentialBodies() async throws {
        let session = StubAuthRequestSession(.json(#"{}"#, headers: ["set-auth-token": "t"]))
        let client = makeClient(session)
        _ = try await client.signIn(email: "dj@wxyc.org", password: "pw")
        _ = try await client.signIn(username: "dj", password: "pw")
        _ = try await client.signIn(email: "dj@wxyc.org", otp: "123456")

        let bodies = try session.requests.map {
            try JSONSerialization.jsonObject(with: try #require($0.httpBody)) as? [String: String]
        }
        #expect(bodies[0] == ["email": "dj@wxyc.org", "password": "pw"])
        #expect(bodies[1] == ["username": "dj", "password": "pw"])
        #expect(bodies[2] == ["email": "dj@wxyc.org", "otp": "123456"])
        #expect(session.requests.allSatisfy { $0.value(forHTTPHeaderField: "Content-Type") == "application/json" })
    }

    @Test("sign-out is a POST bearing the session token")
    func signOutShape() async throws {
        let session = StubAuthRequestSession(.http(status: 200))
        try await makeClient(session).signOut(sessionToken: "session-abc")
        let request = try #require(session.requests.first)
        #expect(request.httpMethod == "POST")
        #expect(request.url?.path == "/auth/sign-out")
        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer session-abc")
    }

    /// A 2xx says nothing about whether the account exists — with sign-up
    /// disabled the server answers success for an unknown address after
    /// discarding the code. Hence `Void`, and hence no assertion here beyond
    /// "it did not throw".
    @Test("send-verification-otp posts the address and returns nothing")
    func sendVerificationOTPShape() async throws {
        let session = StubAuthRequestSession(.json(#"{"success":true}"#))
        try await makeClient(session).sendVerificationOTP(email: "dj@wxyc.org")
        let request = try #require(session.requests.first)
        #expect(request.url?.path == "/auth/email-otp/send-verification-otp")
        let body = try JSONSerialization.jsonObject(with: try #require(request.httpBody)) as? [String: String]
        #expect(body == ["email": "dj@wxyc.org"])
    }
}

//
//  AuthWireClient.swift
//  WXYCAuth
//
//  The better-auth wire mechanics both credentialed WXYC apps implement, once.
//  Stateless: it owns no tokens, touches no Keychain, mutates no app state — it
//  returns facts and the orchestrators decide what they mean.
//
//  Created by Jake on 08/28/26.
//  Copyright © 2026 WXYC. All rights reserved.
//

import Foundation

/// The session token a credentialed sign-in issued.
public struct SignInResult: Sendable, Equatable {
    public let sessionToken: String

    public init(sessionToken: String) {
        self.sessionToken = sessionToken
    }
}

/// The session token an anonymous sign-in issued, plus the user id the server
/// assigned it. wxyc-ios-64 associates that id with its device fingerprint.
public struct AnonymousSignInResult: Sendable, Equatable {
    public let sessionToken: String
    public let userId: String

    public init(sessionToken: String, userId: String) {
        self.sessionToken = sessionToken
        self.userId = userId
    }
}

/// Everything a `/auth/token` exchange produced, so each orchestrator applies
/// its own policy to it.
///
/// `rotatedSessionToken` is the `set-auth-token` header the response carried.
/// **It reads like a rotation and is not one.** Verified against the better-auth
/// build Backend-Service actually loads: the session `token` column is assigned
/// once and never rewritten — `updateSession` uses the existing token purely as
/// a lookup key and touches only `expiresAt`/`updatedAt` — and the header is a
/// deterministic HMAC re-encoding of that same unchanged token. So wxyc-dj-ios
/// persisting it is harmless (an interchangeable re-encoding of what it already
/// holds) and wxyc-ios-64 ignoring it is equally correct. The value is surfaced
/// because both apps read the header; it is not a signal either must act on.
///
/// The capture is raw, with no normalization: an empty-valued header surfaces
/// as `""`, not `nil`. Only a genuinely absent header produces `nil`, so a
/// consumer must not read `if let rotatedSessionToken` as ruling out an empty
/// string.
public struct MintedJWT: Sendable, Equatable {
    public let jwt: String
    public let claims: JWTClaims
    public let rotatedSessionToken: String?

    public init(jwt: String, claims: JWTClaims, rotatedSessionToken: String?) {
        self.jwt = jwt
        self.claims = claims
        self.rotatedSessionToken = rotatedSessionToken
    }
}

/// The better-auth endpoints both apps speak, and nothing else.
///
/// Every method reports to `onOutcome` and throws ``AuthWireError``; none of
/// them decides what a status *means*. See that type for why the policy line
/// sits there.
public struct AuthWireClient: Sendable {
    private let authBaseURL: URL
    private let session: any AuthRequestSession
    private let timeout: TimeInterval
    private let defaultHeaders: [String: String]
    private let onOutcome: (@Sendable (RequestOutcome) -> Void)?

    /// - Parameters:
    ///   - authBaseURL: The auth origin *including* its `/auth` prefix — e.g.
    ///     `https://api.wxyc.org/auth`. Endpoint paths are appended to it.
    ///   - session: Defaults to ``makeCookieFreeSession()``. An injected
    ///     session is why the per-request cookie guard below also exists.
    ///   - defaultHeaders: Sent on every request. wxyc-ios-64 puts its
    ///     `Origin` and `User-Agent` here; wxyc-dj-ios sends neither. Kept as
    ///     caller data rather than baked in, because adding an `Origin` header
    ///     to dj-ios's requests would change which better-auth middleware they
    ///     arm.
    ///   - onOutcome: Observation hook. See ``RequestOutcome``.
    public init(
        authBaseURL: URL,
        session: any AuthRequestSession = AuthWireClient.makeCookieFreeSession(),
        timeout: TimeInterval = 15,
        defaultHeaders: [String: String] = [:],
        onOutcome: (@Sendable (RequestOutcome) -> Void)? = nil
    ) {
        self.authBaseURL = authBaseURL
        self.session = session
        self.timeout = timeout
        self.defaultHeaders = defaultHeaders
        self.onOutcome = onOutcome
    }

    /// A `URLSession` that neither stores, accepts, nor sends cookies.
    ///
    /// This is a pure bearer-token client with no use for a cookie jar, and an
    /// unwanted jar is actively fatal on both apps' paths — which is why the
    /// guard is doubled (see ``perform(_:)``, which also clears the flag on
    /// every request).
    ///
    /// - wxyc-ios-64: `.ephemeral` alone is not enough. It only keeps cookies
    ///   off *disk*; the in-memory jar still collects the sign-in cookie and
    ///   resends it, and better-auth then refuses the next anonymous sign-in
    ///   ("Anonymous users cannot sign in again anonymously") because it sees a
    ///   live session — wedging auth until the process restarts.
    /// - wxyc-dj-ios: better-auth's `bearer()` after-hook adds `set-auth-token`
    ///   without stripping the `Set-Cookie` it rides alongside, and
    ///   `originCheckMiddleware` — registered globally on every non-GET —
    ///   enforces `Origin` *only when a cookie is present*. A native client
    ///   sends no `Origin`, so a cookie-bearing sign-in is refused with `403
    ///   MISSING_OR_NULL_ORIGIN` before any credential check.
    ///
    /// It also keeps the session off disk outside the Keychain, which a local
    /// sign-out cannot reach.
    public static func makeCookieFreeSession() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        return URLSession(configuration: configuration)
    }

    // MARK: - Credentialed sign-in

    /// `POST /auth/sign-in/email`.
    ///
    /// Both password routes are exposed because wxyc-dj-ios routes one login
    /// field to either of them: `/sign-in/username` validates the identifier's
    /// *shape* before looking up any user, and better-auth's default username
    /// pattern rejects an `@` outright with `422 INVALID_USERNAME`, so an email
    /// posted there fails at any password.
    public func signIn(email: String, password: String) async throws -> SignInResult {
        try await establishSession(
            path: "sign-in/email",
            jsonBody: ["email": email, "password": password]
        )
    }

    /// `POST /auth/sign-in/username`.
    public func signIn(username: String, password: String) async throws -> SignInResult {
        try await establishSession(
            path: "sign-in/username",
            jsonBody: ["username": username, "password": password]
        )
    }

    /// `POST /auth/sign-in/email-otp` — redeem a mailed one-time code.
    ///
    /// A peer of the two password routes, not a second state machine: it ends
    /// in the same `setSessionCookie`, and `bearer()` is a global plugin, so
    /// `set-auth-token` arrives identically.
    public func signIn(email: String, otp: String) async throws -> SignInResult {
        try await establishSession(
            path: "sign-in/email-otp",
            jsonBody: ["email": email, "otp": otp]
        )
    }

    /// `POST /auth/email-otp/send-verification-otp` — ask the server to mail a
    /// code.
    ///
    /// A 2xx says nothing about whether the account exists: with sign-up
    /// disabled the server answers success for an unknown address after quietly
    /// discarding the code. That is deliberate anti-enumeration upstream, and
    /// it is why this returns `Void` rather than a "was it sent" answer.
    public func sendVerificationOTP(email: String) async throws {
        _ = try await perform(makeRequest(
            path: "email-otp/send-verification-otp",
            method: "POST",
            jsonBody: ["email": email]
        ))
    }

    /// `POST /auth/wxyc/lookup-email` — resolve a username to the address a
    /// code will be mailed to.
    ///
    /// **This is the one WXYC-custom route here**, not a better-auth one, so it
    /// answers in Backend-Service's own `{error: …}` vocabulary rather than
    /// `{message, code}` and its failures are readable by status alone.
    /// `{"email": null}` on a 2xx is a *no-match rejection*, not a malformed
    /// response, so it surfaces as ``AuthWireError/missingLookupResult`` —
    /// distinct from a decode failure, because the caller has copy for it.
    public func lookUpEmail(identifier: String) async throws -> String {
        let (data, _) = try await perform(makeRequest(
            path: "wxyc/lookup-email",
            method: "POST",
            jsonBody: ["identifier": identifier]
        ))
        let response: LookupEmailResponse
        do {
            response = try JSONDecoder().decode(LookupEmailResponse.self, from: data)
        } catch {
            throw AuthWireError.decoding(error)
        }
        guard let email = response.email, !email.isEmpty else {
            throw AuthWireError.missingLookupResult
        }
        return email
    }

    // MARK: - Anonymous sign-in

    /// `POST /auth/sign-in/anonymous`.
    ///
    /// - Parameter deviceFingerprint: Sent as `X-Device-Fingerprint` so the
    ///   backend can associate the device with the freshly-minted `user.id` at
    ///   sign-in time. `nil` omits the header; the request still succeeds, the
    ///   audit-trail association is simply absent.
    public func signInAnonymously(deviceFingerprint: String?) async throws -> AnonymousSignInResult {
        var request = makeRequest(path: "sign-in/anonymous", method: "POST", jsonBody: [:])
        setDeviceFingerprint(deviceFingerprint, on: &request)
        let (data, response) = try await perform(request)
        let sessionToken = capturedSessionToken(header: response, body: data)
        do {
            let decoded = try JSONDecoder().decode(AnonymousSignInResponse.self, from: data)
            guard let sessionToken = sessionToken ?? nonEmpty(decoded.token) else {
                throw AuthWireError.missingSessionToken
            }
            return AnonymousSignInResult(sessionToken: sessionToken, userId: decoded.user.id)
        } catch let error as AuthWireError {
            throw error
        } catch {
            throw AuthWireError.decoding(error)
        }
    }

    // MARK: - JWT exchange and sign-out

    /// `GET /auth/token` — exchange a session token for a bearer JWT.
    ///
    /// A **401** here means the session is gone; a **404** means the route is
    /// not where we think it is. Both arrive as ``AuthWireError/status(_:body:)``
    /// with their real number precisely so the caller cannot conflate them —
    /// treating a 404 as a dead session would sign a DJ out over a deploy typo.
    public func mintJWT(sessionToken: String, deviceFingerprint: String?) async throws -> MintedJWT {
        var request = makeRequest(path: "token", method: "GET")
        request.setValue("Bearer \(sessionToken)", forHTTPHeaderField: "Authorization")
        setDeviceFingerprint(deviceFingerprint, on: &request)
        let (data, response) = try await perform(request)
        let token: String
        do {
            token = try JSONDecoder().decode(TokenResponse.self, from: data).token
        } catch {
            throw AuthWireError.decoding(error)
        }
        let claims: JWTClaims
        do {
            claims = try JWTDecoder.decode(token)
        } catch {
            throw AuthWireError.decoding(error)
        }
        // Case-insensitive by contract of `value(forHTTPHeaderField:)`, so the
        // header is captured however the server cases it.
        return MintedJWT(
            jwt: token,
            claims: claims,
            rotatedSessionToken: response.value(forHTTPHeaderField: "set-auth-token")
        )
    }

    /// `POST /auth/sign-out` — invalidate the session server-side.
    public func signOut(sessionToken: String) async throws {
        var request = makeRequest(path: "sign-out", method: "POST")
        request.setValue("Bearer \(sessionToken)", forHTTPHeaderField: "Authorization")
        _ = try await perform(request)
    }

    // MARK: - Wire

    /// POST a credential body to a sign-in route and return the session token
    /// it issues.
    ///
    /// Every credentialed route reaches the same response shape — `bearer()` is
    /// a global plugin — so the capture lives here once instead of once per
    /// credential, and a new route cannot get it subtly wrong.
    private func establishSession(path: String, jsonBody: [String: String]) async throws -> SignInResult {
        let (data, response) = try await perform(makeRequest(path: path, method: "POST", jsonBody: jsonBody))
        guard let token = capturedSessionToken(header: response, body: data) else {
            throw AuthWireError.missingSessionToken
        }
        return SignInResult(sessionToken: token)
    }

    /// The session token out of a 2xx: the `set-auth-token` header, else the
    /// body's `token` field. The body fallback is not redundant — a response
    /// that omits the header still carries the token, and both apps read it.
    private func capturedSessionToken(header response: HTTPURLResponse, body data: Data) -> String? {
        if let header = nonEmpty(response.value(forHTTPHeaderField: "set-auth-token")) {
            return header
        }
        return nonEmpty(try? JSONDecoder().decode(TokenResponse.self, from: data).token)
    }

    private func nonEmpty(_ value: String?) -> String? {
        guard let value, !value.isEmpty else { return nil }
        return value
    }

    private func setDeviceFingerprint(_ fingerprint: String?, on request: inout URLRequest) {
        guard let fingerprint else { return }
        request.setValue(fingerprint, forHTTPHeaderField: "X-Device-Fingerprint")
    }

    private func makeRequest(path: String, method: String, jsonBody: [String: String]? = nil) -> URLRequest {
        var request = URLRequest(url: authBaseURL.appending(path: path), timeoutInterval: timeout)
        request.httpMethod = method
        // The second half of the cookie-free guard, and the only half that
        // survives an injected session — which the `AuthRequestSession` seam
        // makes routine, since an adapter over a consumer's own session type
        // bypasses `makeCookieFreeSession()` entirely.
        request.httpShouldHandleCookies = false
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        for (field, value) in defaultHeaders {
            request.setValue(value, forHTTPHeaderField: field)
        }
        if let jsonBody {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try? JSONEncoder().encode(jsonBody)
        }
        return request
    }

    /// Issue the request, report the outcome, and reduce the response to either
    /// 2xx bytes or an ``AuthWireError``.
    private func perform(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            let outcome = RequestOutcome.classifying(error)
            onOutcome?(outcome)
            if case .cancelled = outcome { throw AuthWireError.cancelled }
            throw AuthWireError.transport(error)
        }
        guard let http = response as? HTTPURLResponse else {
            // Deliberately *not* reported as a transport failure: a response
            // that reached the HTTP layer without a status is a bug in this
            // client or its stub, not evidence about the network.
            throw AuthWireError.nonHTTPResponse
        }
        onOutcome?(.answered(status: http.statusCode))
        guard (200..<300).contains(http.statusCode) else {
            throw AuthWireError.status(http.statusCode, body: data)
        }
        return (data, http)
    }
}

// MARK: - Wire shapes

private struct TokenResponse: Decodable {
    let token: String
}

private struct AnonymousSignInResponse: Decodable {
    struct User: Decodable {
        let id: String
    }

    let token: String?
    let user: User
}

private struct LookupEmailResponse: Decodable {
    let email: String?
}

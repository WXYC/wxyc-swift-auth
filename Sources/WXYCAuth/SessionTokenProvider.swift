//
//  SessionTokenProvider.swift
//  WXYCAuth
//
//  The consumer seam between "something that needs a bearer token" and
//  "whatever owns the session", plus the retry-once transport helper both apps
//  had written twice.
//
//  Created by Jake on 08/28/26.
//  Copyright © 2026 WXYC. All rights reserved.
//

import Foundation

/// Supplies a session token, and recovers one after the server rejects it.
public protocol SessionTokenProvider: Sendable {
    /// A currently-valid token, signing in if that is what it takes.
    func token() async throws -> String

    /// A fresh token, discarding any cached one that still matches
    /// `previousToken`.
    ///
    /// `previousToken` is the exact value the server just rejected, and passing
    /// it is what makes this safe under concurrency: a burst of authed calls
    /// that all 401 on the same stale token must produce **one** re-sign-in,
    /// and every caller must receive that same fresh token. A conformer uses
    /// the parameter to tell "nobody has recovered from this yet" (do the work)
    /// apart from "another caller already refreshed past this" (hand back
    /// what's cached now).
    func reauthenticate(previousToken: String) async throws -> String
}

/// Sends a request with a bearer token attached, and on a 401 forces a fresh
/// token and retries **exactly once**.
///
/// Both apps arrived at this shape independently — wxyc-dj-ios inside
/// `APIClient.perform`, wxyc-ios-64 as `URLSession.authedData` — and both had
/// to relearn the same two constraints, which is why they are stated here:
///
/// - **The retry rebuilds from the original request**, so a body must be
///   `httpBody` and not a one-shot `httpBodyStream` the first attempt consumes.
/// - **A second 401 is not retried.** It is returned to the caller, which is
///   the signal the session is genuinely dead rather than merely stale.
///
/// Deliberately *not* status-validated: the response is returned whatever it
/// says, because the callers' status policies differ (dj-ios's catalog fetch
/// accepts a 304 that would fail any 2xx-only check).
public enum AuthenticatedRequest {
    public static func perform(
        _ request: URLRequest,
        using session: any AuthRequestSession,
        tokenProvider: (any SessionTokenProvider)?
    ) async throws -> (Data, HTTPURLResponse) {
        // No provider means "send it unauthenticated, and don't retry" — the
        // convention both apps use for their unauthenticated and test contexts.
        guard let tokenProvider else {
            return try await send(request, using: session)
        }

        let usedToken = try await tokenProvider.token()
        var authedRequest = request
        authedRequest.setValue("Bearer \(usedToken)", forHTTPHeaderField: "Authorization")

        let (data, response) = try await send(authedRequest, using: session)
        guard response.statusCode == 401 else { return (data, response) }

        let freshToken = try await tokenProvider.reauthenticate(previousToken: usedToken)

        // Reauthentication awaits a shared, deliberately non-cancellable
        // refresh; this caller may have been torn down while it was in flight.
        // Bail before paying for a retry nobody will read.
        try Task.checkCancellation()

        var retry = request
        retry.setValue("Bearer \(freshToken)", forHTTPHeaderField: "Authorization")
        return try await send(retry, using: session)
    }

    private static func send(
        _ request: URLRequest,
        using session: any AuthRequestSession
    ) async throws -> (Data, HTTPURLResponse) {
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw AuthWireError.nonHTTPResponse
        }
        return (data, http)
    }
}

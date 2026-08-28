//
//  AuthWireError.swift
//  WXYCAuth
//
//  The wire client's error surface: facts about what the transport and the
//  server did, never a verdict about what they mean.
//
//  Created by Jake on 08/28/26.
//  Copyright © 2026 WXYC. All rights reserved.
//

import Foundation

/// Why a wire call did not produce its result.
///
/// Two design constraints shaped this list, and both come from the consumers'
/// existing catch arms rather than from taste:
///
/// - **The underlying transport error survives.** wxyc-dj-ios's #53/#66 state
///   machine and wxyc-ios-64's failure coalescing both classify on the original
///   error (`URLError` codes decide transient-vs-terminal), so wrapping that
///   must never discard it.
/// - **Decode failure is distinguishable from transport failure.** ios-64's
///   `RequestLineAnalytics` reports a failure *phase* — `.parse` versus
///   `.network` — so an error surface that flattened the two would make its
///   "event shapes unchanged" adoption criterion unreachable.
///
/// Deliberately absent: any case that names a *policy*. There is no
/// `.invalidCredentials`, no `.rateLimited`. A served non-2xx arrives as
/// ``status(_:body:)`` with the number and the bytes, and the orchestrator
/// decides what a 401 or a 429 means for its own screen — the two apps disagree
/// on several of those mappings, and the wire client has no business
/// arbitrating.
public enum AuthWireError: Error, Sendable {
    /// The caller withdrew the request. Carries no connectivity meaning.
    case cancelled
    /// The request never reached an answer. Preserves the original error.
    case transport(any Error)
    /// A response arrived that carried no HTTP status. This is a bug, not
    /// evidence of being offline, and the consumers classify it that way.
    case nonHTTPResponse
    /// The server answered with a non-2xx status. `body` is the raw bytes, so
    /// the caller can read better-auth's `{message, code}` — via
    /// ``AuthWireErrorBody/init(decoding:)`` — or ignore it.
    case status(Int, body: Data)
    /// A 2xx whose body was not the declared shape. The `.parse` phase.
    case decoding(any Error)
    /// A 2xx `lookup-email` response that resolved to no address —
    /// `{"email": null}`. A *rejection* the caller has copy for, deliberately
    /// not folded into ``decoding(_:)``: the response was perfectly well
    /// formed, it just said no.
    case missingLookupResult
    /// A 2xx sign-in response that carried a session token in neither the
    /// `set-auth-token` header nor the body.
    case missingSessionToken
}

/// better-auth's error body, `{message, code}`.
///
/// Note the vocabulary boundary: better-auth's own routes answer in this shape,
/// while Backend-Service's custom routes and its Express rate limiter answer
/// `{error: …}`, which this cannot decode at all. Callers on those paths map by
/// status instead of reaching for this — `init?(decoding:)` returning `nil` is
/// the expected outcome there, not a defect.
public struct AuthWireErrorBody: Decodable, Sendable, Equatable {
    /// Required, and that is what makes ``init(decoding:)`` discriminating:
    /// a body in Backend-Service's `{error: …}` vocabulary has no `message` and
    /// therefore fails to decode, rather than arriving as an all-`nil` value
    /// that reads like a successfully-parsed better-auth error.
    public let message: String
    public let code: String?

    public init(message: String, code: String?) {
        self.message = message
        self.code = code
    }

    /// Decodes an error body, or `nil` if these bytes are not one.
    public init?(decoding data: Data) {
        guard let decoded = try? JSONDecoder().decode(AuthWireErrorBody.self, from: data) else {
            return nil
        }
        self = decoded
    }
}

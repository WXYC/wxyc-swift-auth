//
//  RequestOutcome.swift
//  WXYCAuth
//
//  What a request did, as an observation rather than a verdict.
//
//  Created by Jake on 08/28/26.
//  Copyright © 2026 WXYC. All rights reserved.
//

import Foundation

/// What happened to one request, reported to ``AuthWireClient``'s `onOutcome`
/// hook. It is the attachment point for whatever each app hangs off request
/// results — wxyc-dj-ios's `ConnectivityMonitor`, wxyc-ios-64's request-line
/// analytics — without either becoming a dependency of this package.
///
/// **`.cancelled` is its own case deliberately.** A cancelled request is
/// neither reachability evidence nor an auth failure: nobody answered because
/// the caller withdrew the question. Both apps discovered this independently
/// and the hard way — dj-ios's search debounce cancels the in-flight request on
/// every keystroke, so folding cancellation into failure latched its offline
/// state on every keystroke — and both then encoded the carve-out as a
/// condition inside a `catch`, where the next author has to notice it. Here it
/// is a case in the type, so a consumer's `switch` cannot silently omit it.
public enum RequestOutcome: Sendable {
    /// The server answered, whatever it said. `status` is the HTTP status.
    case answered(status: Int)
    /// The request never reached an answer: DNS, TLS, timeout, no route.
    case transportFailure(any Error)
    /// The caller withdrew the request. Says nothing about the network.
    case cancelled
}

extension RequestOutcome {
    /// Classifies a thrown transport error into `.cancelled` or
    /// `.transportFailure`, covering both forms a cancellation takes:
    /// `URLSession`'s `URLError.cancelled` and the `CancellationError` an
    /// injected ``AuthRequestSession`` may surface instead.
    public static func classifying(_ error: any Error) -> RequestOutcome {
        if (error as? URLError)?.code == .cancelled || error is CancellationError {
            return .cancelled
        }
        return .transportFailure(error)
    }
}

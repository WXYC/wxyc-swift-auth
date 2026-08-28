//
//  AuthenticatedRequestTests.swift
//  WXYCAuthTests
//
//  The retry-once transport helper: exactly one retry, the rejected token
//  handed back to the provider, and no status policy of its own.
//
//  Created by Jake on 08/28/26.
//  Copyright © 2026 WXYC. All rights reserved.
//

import Foundation
import Testing

@testable import WXYCAuth
import WXYCAuthTesting

private let endpoint = URL(string: "https://api.wxyc.test/library/search")!

/// Records what it was asked and hands back scripted tokens.
private final class SpyTokenProvider: SessionTokenProvider, @unchecked Sendable {
    private let lock = NSLock()
    private var tokens: [String]
    private var recordedPrevious: [String] = []
    private var tokenCalls = 0
    private var reauthenticateCalls = 0

    let reauthenticationError: (any Error)?

    init(tokens: [String], reauthenticationError: (any Error)? = nil) {
        self.tokens = tokens
        self.reauthenticationError = reauthenticationError
    }

    var previousTokensSeen: [String] { lock.withLock { recordedPrevious } }
    var tokenCallCount: Int { lock.withLock { tokenCalls } }
    var reauthenticateCallCount: Int { lock.withLock { reauthenticateCalls } }

    func token() async throws -> String {
        lock.withLock {
            tokenCalls += 1
            return tokens.first ?? "exhausted"
        }
    }

    func reauthenticate(previousToken: String) async throws -> String {
        if let reauthenticationError { throw reauthenticationError }
        return try lock.withLock {
            reauthenticateCalls += 1
            recordedPrevious.append(previousToken)
            guard tokens.count > 1 else { throw StubExhausted() }
            tokens.removeFirst()
            return tokens[0]
        }
    }
}

private func request(body: Data? = nil) -> URLRequest {
    var request = URLRequest(url: endpoint)
    request.httpMethod = body == nil ? "GET" : "POST"
    request.httpBody = body
    return request
}

@Suite("Retry-once helper")
struct AuthenticatedRequestTests {
    @Test("attaches the provider's token")
    func attachesBearer() async throws {
        let session = StubAuthRequestSession(.http(status: 200))
        let provider = SpyTokenProvider(tokens: ["token-1"])
        _ = try await AuthenticatedRequest.perform(request(), using: session, tokenProvider: provider)
        #expect(session.requests.first?.value(forHTTPHeaderField: "Authorization") == "Bearer token-1")
    }

    @Test("a 401 is retried exactly once, with the fresh token")
    func retriesOnceOn401() async throws {
        let session = StubAuthRequestSession([.http(status: 401), .http(status: 200)])
        let provider = SpyTokenProvider(tokens: ["stale", "fresh"])
        let (_, response) = try await AuthenticatedRequest.perform(
            request(), using: session, tokenProvider: provider
        )
        #expect(response.statusCode == 200)
        #expect(session.requests.count == 2)
        #expect(session.requests.last?.value(forHTTPHeaderField: "Authorization") == "Bearer fresh")
        #expect(provider.reauthenticateCallCount == 1)
    }

    /// The rejected value is passed through so a conformer can tell "nobody has
    /// recovered from this yet" apart from "another concurrent caller already
    /// did" — which is what keeps a burst of simultaneous 401s to one
    /// re-sign-in instead of one per caller.
    @Test("the provider is handed the exact token that was rejected")
    func passesRejectedToken() async throws {
        let session = StubAuthRequestSession([.http(status: 401), .http(status: 200)])
        let provider = SpyTokenProvider(tokens: ["stale", "fresh"])
        _ = try await AuthenticatedRequest.perform(request(), using: session, tokenProvider: provider)
        #expect(provider.previousTokensSeen == ["stale"])
    }

    /// A second consecutive 401 is the signal that the session is genuinely
    /// dead rather than merely stale, so it is returned rather than retried
    /// into a loop.
    @Test("a second 401 is returned, not retried again")
    func doesNotRetryTwice() async throws {
        let session = StubAuthRequestSession([.http(status: 401), .http(status: 401)])
        let provider = SpyTokenProvider(tokens: ["stale", "fresh"])
        let (_, response) = try await AuthenticatedRequest.perform(
            request(), using: session, tokenProvider: provider
        )
        #expect(response.statusCode == 401)
        #expect(session.requests.count == 2)
        #expect(provider.reauthenticateCallCount == 1)
    }

    @Test("a non-401 failure is returned untouched", arguments: [403, 404, 429, 500])
    func doesNotRetryOtherStatuses(status: Int) async throws {
        let session = StubAuthRequestSession(.http(status: status))
        let provider = SpyTokenProvider(tokens: ["token-1"])
        let (_, response) = try await AuthenticatedRequest.perform(
            request(), using: session, tokenProvider: provider
        )
        #expect(response.statusCode == status)
        #expect(session.requests.count == 1)
        #expect(provider.reauthenticateCallCount == 0)
    }

    /// Deliberately no 2xx-only validation: the consumers' status policies
    /// differ, and dj-ios's conditional catalog GET treats a 304 as success.
    @Test("a 304 is handed back rather than treated as a failure")
    func noStatusPolicy() async throws {
        let session = StubAuthRequestSession(.http(status: 304))
        let provider = SpyTokenProvider(tokens: ["token-1"])
        let (_, response) = try await AuthenticatedRequest.perform(
            request(), using: session, tokenProvider: provider
        )
        #expect(response.statusCode == 304)
    }

    @Test("no provider means no bearer and no retry")
    func unauthenticatedPath() async throws {
        let session = StubAuthRequestSession([.http(status: 401), .http(status: 200)])
        let (_, response) = try await AuthenticatedRequest.perform(
            request(), using: session, tokenProvider: nil
        )
        #expect(response.statusCode == 401)
        #expect(session.requests.count == 1)
        #expect(session.requests.first?.value(forHTTPHeaderField: "Authorization") == nil)
    }

    /// The retry rebuilds from the original request, so anything the first
    /// attempt would have consumed has to survive. A `Data` body does; a
    /// one-shot `httpBodyStream` would not, which is why the doc comment says
    /// so and this pins it.
    @Test("the retry re-sends the original body")
    func retryPreservesBody() async throws {
        let body = Data(#"{"query":"juana molina"}"#.utf8)
        let session = StubAuthRequestSession([.http(status: 401), .http(status: 200)])
        let provider = SpyTokenProvider(tokens: ["stale", "fresh"])
        _ = try await AuthenticatedRequest.perform(
            request(body: body), using: session, tokenProvider: provider
        )
        #expect(session.requests.count == 2)
        #expect(session.requests.last?.httpBody == body)
        #expect(session.requests.last?.httpMethod == "POST")
    }

    @Test("a failure to reauthenticate surfaces, and no retry is issued")
    func reauthenticationFailureSurfaces() async throws {
        let session = StubAuthRequestSession([.http(status: 401), .http(status: 200)])
        let provider = SpyTokenProvider(tokens: ["stale"], reauthenticationError: URLError(.notConnectedToInternet))
        await #expect(throws: URLError.self) {
            try await AuthenticatedRequest.perform(request(), using: session, tokenProvider: provider)
        }
        #expect(session.requests.count == 1)
    }

    @Test("a non-HTTP response throws rather than escaping unvalidated")
    func nonHTTPResponse() async throws {
        let session = StubAuthRequestSession(.nonHTTP)
        await #expect(throws: AuthWireError.self) {
            try await AuthenticatedRequest.perform(request(), using: session, tokenProvider: nil)
        }
    }
}

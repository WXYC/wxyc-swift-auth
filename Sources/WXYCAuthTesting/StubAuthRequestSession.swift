//
//  StubAuthRequestSession.swift
//  WXYCAuthTesting
//
//  Canned-response transport double, so a consumer can exercise its auth
//  orchestration without a network stack or a live better-auth.
//
//  Created by Jake on 08/28/26.
//  Copyright © 2026 WXYC. All rights reserved.
//

import Foundation
import WXYCAuth

/// One canned answer to one request.
public enum StubbedResponse: Sendable {
    /// An HTTP response with a status, body, and headers.
    case http(status: Int, body: Data = Data(), headers: [String: String] = [:])
    /// A transport failure — the request never gets an answer.
    case failure(any Error)
    /// A response that carries no HTTP status at all. Exists so a consumer can
    /// exercise the branch its own code has for this; it is a bug shape, not a
    /// network condition.
    case nonHTTP

    /// An HTTP response whose body is `json`, encoded UTF-8.
    public static func json(
        status: Int = 200,
        _ json: String,
        headers: [String: String] = [:]
    ) -> StubbedResponse {
        .http(status: status, body: Data(json.utf8), headers: headers)
    }
}

/// Answers requests from a queue, recording what it was asked.
///
/// Responses are consumed in order; once the queue is empty the **last**
/// response repeats, so a test that cares about one call needn't enumerate the
/// retries around it. Set ``exhaustionIsAnError`` to make an over-run loud
/// instead.
public final class StubAuthRequestSession: AuthRequestSession, @unchecked Sendable {
    private let lock = NSLock()
    private var queue: [StubbedResponse]
    private var lastResponse: StubbedResponse?
    private var recorded: [URLRequest] = []

    /// Whether running past the queued responses throws instead of repeating
    /// the last one.
    public var exhaustionIsAnError: Bool

    public init(_ responses: [StubbedResponse] = [], exhaustionIsAnError: Bool = false) {
        self.queue = responses
        self.exhaustionIsAnError = exhaustionIsAnError
    }

    public convenience init(_ response: StubbedResponse) {
        self.init([response])
    }

    /// Every request this stub was handed, in call order.
    public var requests: [URLRequest] {
        lock.withLock { recorded }
    }

    public func enqueue(_ response: StubbedResponse) {
        lock.withLock { queue.append(response) }
    }

    public func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        let response: StubbedResponse = try lock.withLock {
            recorded.append(request)
            if queue.isEmpty {
                guard !exhaustionIsAnError, let lastResponse else {
                    throw StubExhausted()
                }
                return lastResponse
            }
            let next = queue.removeFirst()
            lastResponse = next
            return next
        }

        switch response {
        case .failure(let error):
            throw error
        case .nonHTTP:
            return (Data(), URLResponse(
                url: request.url ?? URL(string: "https://example.invalid")!,
                mimeType: nil,
                expectedContentLength: 0,
                textEncodingName: nil
            ))
        case .http(let status, let body, let headers):
            let http = HTTPURLResponse(
                url: request.url ?? URL(string: "https://example.invalid")!,
                statusCode: status,
                httpVersion: "HTTP/1.1",
                headerFields: headers
            )!
            return (body, http)
        }
    }
}

/// A stub was asked for more responses than it was given.
public struct StubExhausted: Error, Sendable {
    public init() {}
}

//
//  AuthRequestSession.swift
//  WXYCAuth
//
//  The injection seam every request in this package passes through, plus the
//  cookie-free session that backs it in production.
//
//  Created by Jake on 08/28/26.
//  Copyright © 2026 WXYC. All rights reserved.
//

import Foundation

/// The one transport seam. Both consumers already own a protocol of exactly
/// this shape (`WXYCAPI.RequestSession`, `MusicShareKit.AuthNetworkClient`'s
/// injected `URLSession`), so an adapter is a one-line conformance.
public protocol AuthRequestSession: Sendable {
    func data(for request: URLRequest) async throws -> (Data, URLResponse)
}

extension URLSession: AuthRequestSession {}

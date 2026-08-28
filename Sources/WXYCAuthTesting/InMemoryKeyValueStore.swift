//
//  InMemoryKeyValueStore.swift
//  WXYCAuthTesting
//
//  Storage double for tests that need persistence semantics but not a real
//  Keychain — which a Simulator test bundle cannot have anyway.
//
//  Created by Jake on 08/28/26.
//  Copyright © 2026 WXYC. All rights reserved.
//

import Foundation

/// A lock-guarded account → data map with the same read/write/delete surface as
/// ``WXYCAuth/KeychainStore``, minus the Keychain.
///
/// Not a conformer to a shared protocol, because ``WXYCAuth/KeychainStore`` is
/// deliberately a concrete struct: its value is the query shapes, and a
/// protocol over it would invite a test to pass in something that proves
/// nothing about them. This is for the layers *above* storage.
public final class InMemoryKeyValueStore: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String: Data] = [:]

    /// Set to make the next operation of each kind fail, so a consumer's
    /// storage-failure arm is reachable.
    public var readError: (any Error)?
    public var writeError: (any Error)?

    public init() {}

    public func read(account: String) throws -> Data? {
        if let readError { throw readError }
        return lock.withLock { storage[account] }
    }

    public func write(_ data: Data, account: String) throws {
        if let writeError { throw writeError }
        lock.withLock { storage[account] = data }
    }

    public func delete(account: String) {
        lock.withLock { storage[account] = nil }
    }

    /// Everything currently stored, for assertions.
    public var contents: [String: Data] {
        lock.withLock { storage }
    }
}

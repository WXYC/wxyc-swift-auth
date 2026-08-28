//
//  KeychainStore.swift
//  WXYCAuth
//
//  Keychain plumbing beneath both apps' storage protocols: query building,
//  OSStatus mapping, and the iCloud-sync-with-local-fallback write. The
//  protocols themselves (dj-ios's slots, ios-64's single session blob) stay
//  app-side; only the mechanics are shared.
//
//  Created by Jake on 08/28/26.
//  Copyright © 2026 WXYC. All rights reserved.
//

import Foundation
import Security

/// When a stored item is readable. **A required initializer parameter, never a
/// default**, because the two apps deliberately differ: wxyc-dj-ios writes
/// `afterFirstUnlockThisDeviceOnly` (its session must not leave the device) and
/// wxyc-ios-64 writes `afterFirstUnlock` alongside iCloud sync. A hardcoded
/// class here would silently downgrade dj-ios's device-only posture on the next
/// write, and nothing would fail — the item would simply become more available
/// than it was ever meant to be.
public enum KeychainAccessibility: Sendable {
    case whenUnlocked
    case whenUnlockedThisDeviceOnly
    case afterFirstUnlock
    case afterFirstUnlockThisDeviceOnly

    var attributeValue: CFString {
        switch self {
        case .whenUnlocked: kSecAttrAccessibleWhenUnlocked
        case .whenUnlockedThisDeviceOnly: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .afterFirstUnlock: kSecAttrAccessibleAfterFirstUnlock
        case .afterFirstUnlockThisDeviceOnly: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        }
    }
}

/// Why a Keychain operation did not do what was asked.
public enum KeychainStoreError: Error, Sendable, Equatable {
    /// The item was found, but its payload was not readable as stored data.
    /// This is a **migration** signal — a format written by an older build, or
    /// by a different writer — and it is separated from `.operational` because
    /// the recoveries differ: a caller can discard and re-establish here, while
    /// an operational failure means the Keychain itself refused and retrying
    /// the same call is pointless. Both apps previously reported this case as a
    /// bare `errSecDecode`, indistinguishable from the OS returning that status
    /// itself.
    case decodeFailure
    /// The Keychain refused. Carries the `OSStatus` verbatim; note that
    /// `errSecDecode` can legitimately arrive *here* too, which is exactly the
    /// ambiguity the split above removes.
    case operational(OSStatus)
}

/// Generic-password Keychain access for one `service`, keyed by account.
///
/// **Testing note:** there is deliberately no `SecItem*` injection shim. These
/// operations are exercised against the real Keychain under `swift test` on the
/// host only — a Swift Package unit-test bundle running in a Simulator has no
/// Keychain entitlement and fails every call with `errSecMissingEntitlement`
/// (wxyc-ios-64's own Keychain tests document exactly this). A shim would let
/// the tests run everywhere while proving nothing about the queries that matter.
public struct KeychainStore: Sendable {
    private let service: String
    private let accessibility: KeychainAccessibility
    private let accessGroup: String?
    private let synchronizable: Bool

    /// - Parameters:
    ///   - service: `kSecAttrService`. Both apps scope their items by it.
    ///   - accessibility: See ``KeychainAccessibility`` for why this has no
    ///     default.
    ///   - accessGroup: `kSecAttrAccessGroup`, or `nil` for the process
    ///     default. The format is `<App ID prefix>.<group name>`, and the
    ///     prefix is not necessarily the Team ID.
    ///   - synchronizable: Whether to sync via iCloud Keychain. When `true`,
    ///     reads match sync and non-sync items alike and a write falls back to
    ///     local-only storage if iCloud Keychain is unavailable — local
    ///     persistence beats none.
    public init(
        service: String,
        accessibility: KeychainAccessibility,
        accessGroup: String? = nil,
        synchronizable: Bool = false
    ) {
        self.service = service
        self.accessibility = accessibility
        self.accessGroup = accessGroup
        self.synchronizable = synchronizable
    }

    /// The stored bytes for `account`, or `nil` if there is no such item.
    public func read(account: String) throws -> Data? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data else { throw KeychainStoreError.decodeFailure }
            return data
        case errSecItemNotFound:
            // A `synchronizable` store queries with `kSecAttrSynchronizableAny`,
            // which should already match both kinds — but a write that fell
            // back to local-only when iCloud Keychain was unavailable is
            // exactly the item a caller most needs to find, so look again
            // without the attribute rather than reporting a signed-out state.
            return synchronizable ? try readLocalOnly(account: account) : nil
        default:
            throw KeychainStoreError.operational(status)
        }
    }

    /// Upsert `data` for `account`.
    public func write(_ data: Data, account: String) throws {
        let query = baseQuery(account: account)
        let attributes: [String: Any] = [kSecValueData as String: data]

        // Canonical upsert: update first, add on not-found. The two steps have
        // a theoretical TOCTOU window; both consumers serialize their writes.
        let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        switch updateStatus {
        case errSecSuccess:
            return
        case errSecItemNotFound:
            break
        default:
            throw KeychainStoreError.operational(updateStatus)
        }

        var addQuery = query
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] = accessibility.attributeValue
        if synchronizable {
            addQuery[kSecAttrSynchronizable as String] = true
        }
        var addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if synchronizable && addStatus != errSecSuccess {
            addQuery[kSecAttrSynchronizable as String] = false
            addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        }
        guard addStatus == errSecSuccess else {
            throw KeychainStoreError.operational(addStatus)
        }
    }

    /// Remove the item for `account`. Absence is success — the postcondition
    /// callers actually want is "there is no such item now".
    public func delete(account: String) throws {
        let status = SecItemDelete(baseQuery(account: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainStoreError.operational(status)
        }
    }

    /// The query shape every operation shares.
    ///
    /// Not private: an access group requires an entitled, signed host, so a
    /// package test bundle cannot round-trip one and must introspect the query
    /// instead.
    func baseQuery(account: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        if synchronizable {
            query[kSecAttrSynchronizable as String] = kSecAttrSynchronizableAny
        }
        return query
    }

    private func readLocalOnly(account: String) throws -> Data? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        if let accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data else { throw KeychainStoreError.decodeFailure }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw KeychainStoreError.operational(status)
        }
    }
}

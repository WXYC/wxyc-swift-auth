//
//  KeychainStoreTests.swift
//  WXYCAuthTests
//
//  Real-Keychain round-trips plus query-shape introspection. See the suite's
//  doc comment for why there is no `SecItem*` shim and why these run on the
//  host only.
//
//  Created by Jake on 08/28/26.
//  Copyright © 2026 WXYC. All rights reserved.
//

import Foundation
import Security
import Testing

@testable import WXYCAuth

/// Round-trips against the **real** Keychain.
///
/// There is deliberately no `SecItem*` injection shim: the value of
/// ``KeychainStore`` is the query shapes it builds, and a shim would let these
/// tests pass everywhere while proving nothing about them. The cost is that
/// they are host-`swift test`-only — a Swift Package unit-test bundle running
/// in a Simulator has no Keychain entitlement and fails every call with
/// `errSecMissingEntitlement` (-34018), which wxyc-ios-64's own Keychain tests
/// already document. The suite is therefore gated on a one-shot write probe
/// (``keychainIsWritable``) and **skipped**, not failed, where the Keychain is
/// unavailable: a missing entitlement is an environment fact, and reporting it
/// as a red test would train the next reader to ignore this suite. The
/// query-shape suite below has no such gate — it touches no Keychain — so the
/// interesting half still runs everywhere.
///
/// If this suite skips in CI, that is a signal to investigate the runner, not
/// something to paper over by adding a shim.
let keychainIsWritable: Bool = {
    let probeService = "org.wxyc.auth.tests.probe.\(UUID().uuidString)"
    let store = KeychainStore(service: probeService, accessibility: .afterFirstUnlockThisDeviceOnly)
    do {
        try store.write(Data("probe".utf8), account: "probe")
        try store.delete(account: "probe")
        return true
    } catch {
        return false
    }
}()

@Suite("KeychainStore round-trip", .serialized, .enabled(if: keychainIsWritable))
struct KeychainStoreRoundTripTests {
    /// A service name unique to this run, so a crashed earlier run can't leave
    /// an item that makes a later one pass or fail spuriously.
    private let service = "org.wxyc.auth.tests.\(UUID().uuidString)"

    private var store: KeychainStore {
        KeychainStore(service: service, accessibility: .afterFirstUnlockThisDeviceOnly)
    }

    @Test("writes, reads back, and deletes")
    func roundTrip() throws {
        let payload = Data(#"{"token":"session-abc"}"#.utf8)
        try store.write(payload, account: "session")
        #expect(try store.read(account: "session") == payload)
        try store.delete(account: "session")
        #expect(try store.read(account: "session") == nil)
    }

    @Test("a second write updates in place rather than duplicating")
    func upsert() throws {
        try store.write(Data("first".utf8), account: "session")
        try store.write(Data("second".utf8), account: "session")
        #expect(try store.read(account: "session") == Data("second".utf8))
        try store.delete(account: "session")
    }

    @Test("reading an absent account is nil, not an error")
    func absentIsNil() throws {
        #expect(try store.read(account: "never-written") == nil)
    }

    /// The postcondition callers want is "there is no such item now", so a
    /// delete of nothing is success. Both consumers rely on this in their
    /// leave-no-trace teardown, which runs over every slot unconditionally.
    @Test("deleting an absent account succeeds")
    func deleteAbsentSucceeds() throws {
        #expect(throws: Never.self) { try store.delete(account: "never-written") }
    }

    @Test("accounts are isolated from each other")
    func accountsAreIsolated() throws {
        try store.write(Data("session-value".utf8), account: "session")
        try store.write(Data("jwt-value".utf8), account: "jwt")
        #expect(try store.read(account: "session") == Data("session-value".utf8))
        try store.delete(account: "session")
        #expect(try store.read(account: "jwt") == Data("jwt-value".utf8))
        try store.delete(account: "jwt")
    }

    /// The at-rest parity guard: an item written under wxyc-dj-ios's existing
    /// query shape — its `kSecAttrService`, its account name, its accessibility
    /// class — must still resolve through ``KeychainStore``'s queries, or Phase
    /// C signs every installed build out on upgrade. Written here with raw
    /// `SecItemAdd` precisely so the assertion doesn't depend on the code under
    /// test to also do the writing.
    @Test("an item written under dj-ios's existing query shape still resolves")
    func legacyItemResolves() throws {
        let account = "wxyc.dj-tool.session-token"
        let payload = Data("legacy-session".utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: payload,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        SecItemDelete(query as CFDictionary)
        try #require(SecItemAdd(query as CFDictionary, nil) == errSecSuccess)
        defer { SecItemDelete(query as CFDictionary) }

        #expect(try store.read(account: account) == payload)
    }
}

@Suite("KeychainStore query shape")
struct KeychainStoreQueryTests {
    /// An access group needs an entitled, signed host, so a package test bundle
    /// cannot round-trip one — the query is introspected instead. wxyc-ios-64
    /// hit exactly this and solved it the same way.
    @Test("an access group is included when configured, omitted when not")
    func accessGroup() {
        let scoped = KeychainStore(
            service: "org.wxyc.app.auth",
            accessibility: .afterFirstUnlock,
            accessGroup: "ABCDE12345.org.wxyc.shared"
        )
        #expect(scoped.baseQuery(account: "session")[kSecAttrAccessGroup as String] as? String
            == "ABCDE12345.org.wxyc.shared")

        let unscoped = KeychainStore(service: "org.wxyc.app.auth", accessibility: .afterFirstUnlock)
        #expect(unscoped.baseQuery(account: "session")[kSecAttrAccessGroup as String] == nil)
    }

    /// A synchronizable store must match sync and non-sync items alike on read,
    /// or a write that fell back to local-only when iCloud Keychain was
    /// unavailable becomes unreadable — which is a signed-out DJ, not a missing
    /// nicety.
    @Test("a synchronizable store queries with kSecAttrSynchronizableAny")
    func synchronizableQuery() {
        let syncing = KeychainStore(
            service: "org.wxyc.app.auth", accessibility: .afterFirstUnlock, synchronizable: true
        )
        #expect(syncing.baseQuery(account: "session")[kSecAttrSynchronizable as String] as? String
            == kSecAttrSynchronizableAny as String)

        let local = KeychainStore(service: "org.wxyc.app.auth", accessibility: .afterFirstUnlock)
        #expect(local.baseQuery(account: "session")[kSecAttrSynchronizable as String] == nil)
    }

    @Test("the query is a generic password scoped by service and account")
    func genericPasswordScoping() {
        let query = KeychainStore(service: "org.wxyc.dj", accessibility: .afterFirstUnlockThisDeviceOnly)
            .baseQuery(account: "wxyc.dj-tool.jwt")
        #expect(query[kSecClass as String] as? String == kSecClassGenericPassword as String)
        #expect(query[kSecAttrService as String] as? String == "org.wxyc.dj")
        #expect(query[kSecAttrAccount as String] as? String == "wxyc.dj-tool.jwt")
    }

    /// The two apps write deliberately different classes, and a default here
    /// would silently downgrade dj-ios's device-only posture on the next write
    /// with nothing failing. Pinned so a "helpful" default can't be added
    /// without this test changing too.
    @Test("each accessibility case maps to its own attribute value")
    func accessibilityMapping() {
        #expect(KeychainAccessibility.whenUnlocked.attributeValue == kSecAttrAccessibleWhenUnlocked)
        #expect(KeychainAccessibility.whenUnlockedThisDeviceOnly.attributeValue
            == kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
        #expect(KeychainAccessibility.afterFirstUnlock.attributeValue == kSecAttrAccessibleAfterFirstUnlock)
        #expect(KeychainAccessibility.afterFirstUnlockThisDeviceOnly.attributeValue
            == kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
    }
}

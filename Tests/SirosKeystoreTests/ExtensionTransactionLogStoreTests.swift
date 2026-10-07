// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore
import SirosCredentials

private final class FakeExtensionStore: ExtensionStore, @unchecked Sendable {
    private let lock = NSLock()
    private var data: [String: [String: String]] = [:]
    var locked = false

    func extensionEntries(namespace: String) async -> [String: String] {
        lock.lock(); defer { lock.unlock() }
        return data[namespace] ?? [:]
    }
    func setExtensionEntry(namespace: String, key: String, value: String) async throws {
        if locked { throw KeystoreError.locked }
        lock.lock(); data[namespace, default: [:]][key] = value; lock.unlock()
    }
    func removeExtensionEntry(namespace: String, key: String) async throws {
        if locked { throw KeystoreError.locked }
        lock.lock(); data[namespace]?[key] = nil; lock.unlock()
    }
}

final class ExtensionTransactionLogStoreTests: XCTestCase {
    private func entry(_ i: Int) -> TransactionLogEntry {
        TransactionLogEntry(id: "e\(i)", timestamp: Int64(i),
                            subject: TransactionLogSubject(transactionId: "tx\(i)", typeName: "Payment Confirmation", entities: ["payee": "Shop"]),
                            verifier: "v", credential: "c", outcome: .consented)
    }

    func testRecordsPersistInTheNamespaceAndSurviveANewInstance() async throws {
        let ext = FakeExtensionStore()
        let first = ExtensionTransactionLogStore(store: ext)
        await first.append([entry(1), entry(2)])
        let keys = Set(await ext.extensionEntries(namespace: ExtensionTransactionLogStore.namespace).keys)
        XCTAssertEqual(keys, ["e1", "e2"])
        let second = ExtensionTransactionLogStore(store: ext)
        let ids = await second.entries().map(\.id)
        XCTAssertEqual(ids, ["e2", "e1"], "newest first, read back from the container")
        let restored = await second.entries()
        XCTAssertEqual(restored.last, entry(1))
    }

    func testPersistCallbackRunsOnlyWhenSomethingWasWritten() async {
        let ext = FakeExtensionStore()
        let calls = Counter()
        let store = ExtensionTransactionLogStore(store: ext, persisted: { calls.bump() })
        await store.append([entry(1)])
        XCTAssertEqual(calls.value, 1)
        ext.locked = true
        await store.append([entry(2)])
        XCTAssertEqual(calls.value, 1, "a failed write is not reported as persisted")
    }

    func testLockedContainerLosesNothingForTheRunningSession() async {
        let ext = FakeExtensionStore()
        ext.locked = true
        let store = ExtensionTransactionLogStore(store: ext)
        await store.append([entry(1)])
        let ids = await store.entries().map(\.id)
        XCTAssertEqual(ids, ["e1"])
    }

    func testOldestRecordsBeyondCapacityAreRemoved() async {
        let ext = FakeExtensionStore()
        let store = ExtensionTransactionLogStore(store: ext, capacity: 2)
        for i in 1...4 { await store.append([entry(i)]) }
        let keys = Set(await ext.extensionEntries(namespace: ExtensionTransactionLogStore.namespace).keys)
        XCTAssertEqual(keys, ["e3", "e4"])
        let ids = await store.entries().map(\.id)
        XCTAssertEqual(ids, ["e4", "e3"])
    }

    func testUndecodableEntriesAreIgnored() async throws {
        let ext = FakeExtensionStore()
        try await ext.setExtensionEntry(namespace: ExtensionTransactionLogStore.namespace, key: "junk", value: "not json")
        let store = ExtensionTransactionLogStore(store: ext)
        await store.append([entry(1)])
        let ids = await store.entries().map(\.id)
        XCTAssertEqual(ids, ["e1"])
    }
}

private final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0
    var value: Int { lock.lock(); defer { lock.unlock() }; return n }
    func bump() { lock.lock(); n += 1; lock.unlock() }
}

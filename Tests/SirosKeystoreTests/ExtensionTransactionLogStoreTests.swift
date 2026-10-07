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
    private func entry(_ i: Int, outcome: TransactionLogEntry.Outcome = .consented) -> TransactionLogEntry {
        TransactionLogEntry(id: "e\(i)", timestamp: Int64(i),
                            subject: TransactionLogSubject(transactionId: "tx\(i)", typeName: "Payment Confirmation", entities: ["payee": "Shop"]),
                            verifier: "v", credential: "c", outcome: outcome, reason: outcome == .refused ? "invalidEntry" : nil)
    }

    func testRecordsPersistInTheNamespaceAndSurviveANewInstance() async throws {
        let ext = FakeExtensionStore()
        let first = ExtensionTransactionLogStore(store: ext)
        try await first.append([entry(1), entry(2)])
        let keys = Set(await ext.extensionEntries(namespace: ExtensionTransactionLogStore.namespace).keys)
        XCTAssertEqual(keys, ["e1", "e2"])
        let second = ExtensionTransactionLogStore(store: ext)
        let ids = await second.entries().map(\.id)
        XCTAssertEqual(ids, ["e2", "e1"], "newest first, read back from the container")
        let restored = await second.entries()
        XCTAssertEqual(restored.last, entry(1))
    }

    func testPersistCallbackRunsOnlyWhenSomethingWasWritten() async throws {
        let ext = FakeExtensionStore()
        let calls = Counter()
        let store = ExtensionTransactionLogStore(store: ext, persisted: { calls.bump() })
        try await store.append([entry(1)])
        XCTAssertEqual(calls.value, 1)
        ext.locked = true
        do { try await store.append([entry(2)]) } catch {}
        XCTAssertEqual(calls.value, 1, "a failed write is not reported as persisted")
    }

    /// A write that does not reach the container is SURFACED, while the record is still kept for the session.
    func testAFailedWriteThrowsButTheSessionKeepsTheRecord() async {
        let ext = FakeExtensionStore()
        ext.locked = true
        let store = ExtensionTransactionLogStore(store: ext)
        do { try await store.append([entry(1)]); XCTFail("must surface the failure") }
        catch let error as TransactionLogError { XCTAssertTrue(error.detail.contains("1 of 1")) }
        catch { XCTFail("\(error)") }
        let ids = await store.entries().map(\.id)
        XCTAssertEqual(ids, ["e1"])
    }

    func testOldestRecordsBeyondCapacityAreRemoved() async throws {
        let ext = FakeExtensionStore()
        let store = ExtensionTransactionLogStore(store: ext, capacity: 2)
        for i in 1...4 { try await store.append([entry(i)]) }
        let keys = Set(await ext.extensionEntries(namespace: ExtensionTransactionLogStore.namespace).keys)
        XCTAssertEqual(keys, ["e3", "e4"])
        let ids = await store.entries().map(\.id)
        XCTAssertEqual(ids, ["e4", "e3"])
    }

    /// Refusals can be provoked by anyone who can send a request: they must not push the user's own history out.
    func testRefusalsDoNotEvictConsentedOrDeclinedRecords() async throws {
        let ext = FakeExtensionStore()
        let store = ExtensionTransactionLogStore(store: ext, capacity: 3, refusedCapacity: 2)
        try await store.append([entry(1), entry(2, outcome: .declined)])
        for i in 10..<30 { try await store.append([entry(i, outcome: .refused)]) }
        let all = await store.entries()
        XCTAssertEqual(all.filter { $0.outcome != .refused }.map(\.id).sorted(), ["e1", "e2"], "the user's own records survive a flood of refusals")
        XCTAssertEqual(all.filter { $0.outcome == .refused }.count, 2, "refusals are bounded on their own")
        let keys = Set(await ext.extensionEntries(namespace: ExtensionTransactionLogStore.namespace).keys)
        XCTAssertEqual(keys.count, 4)
    }

    func testUndecodableEntriesAreIgnoredAndNeverDeleted() async throws {
        let ext = FakeExtensionStore()
        try await ext.setExtensionEntry(namespace: ExtensionTransactionLogStore.namespace, key: "junk", value: "not json")
        let store = ExtensionTransactionLogStore(store: ext, capacity: 1)
        try await store.append([entry(1), entry(2)])
        let ids = await store.entries().map(\.id)
        XCTAssertEqual(ids, ["e2"])
        let keys = Set(await ext.extensionEntries(namespace: ExtensionTransactionLogStore.namespace).keys)
        XCTAssertTrue(keys.contains("junk"), "pruning only removes records it decoded")
    }
}

private final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0
    var value: Int { lock.lock(); defer { lock.unlock() }; return n }
    func bump() { lock.lock(); n += 1; lock.unlock() }
}

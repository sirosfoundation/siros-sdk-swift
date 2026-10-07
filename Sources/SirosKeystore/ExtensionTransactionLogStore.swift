// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials

/// A ``TransactionLogStore`` that persists in the wallet's synchronised
/// container as one extension entry per log record (privatedata-spec §6.1,
/// namespace `org.siros.transaction_log`), the SDK's existing storage.
///
/// Records are also kept in memory, so a locked container or a failed write
/// loses nothing for the running session. The oldest records beyond
/// `capacity` are removed.
public final class ExtensionTransactionLogStore: TransactionLogStore, @unchecked Sendable {
    public static let namespace = "org.siros.transaction_log"

    private let store: any ExtensionStore
    private let capacity: Int
    private let refusedCapacity: Int
    private let persisted: (@Sendable () async -> Void)?
    private let memory: InMemoryTransactionLogStore

    /// - Parameter persisted: called after a successful write so the owner
    ///   can export and sync the container (the wallet's `persistAndSyncKeystore`).
    public init(store: any ExtensionStore, capacity: Int = 500, refusedCapacity: Int = 100, persisted: (@Sendable () async -> Void)? = nil) {
        self.store = store
        self.capacity = max(1, capacity)
        self.refusedCapacity = max(1, refusedCapacity)
        self.persisted = persisted
        self.memory = InMemoryTransactionLogStore(capacity: self.capacity, refusedCapacity: self.refusedCapacity)
    }

    /// Records are kept in memory for the session regardless; a write that did
    /// not reach the container throws `TransactionLogError`.
    public func append(_ entries: [TransactionLogEntry]) async throws {
        try await memory.append(entries)
        let encoder = JSONEncoder()
        var failed = 0
        for entry in entries {
            guard let data = try? encoder.encode(entry), let json = String(data: data, encoding: .utf8),
                  (try? await store.setExtensionEntry(namespace: Self.namespace, key: entry.id, value: json)) != nil else {
                failed += 1
                continue
            }
        }
        if failed < entries.count {
            await prune()
            await persisted?()
        }
        if failed > 0 { throw TransactionLogError("\(failed) of \(entries.count) records were not stored") }
    }

    public func entries() async -> [TransactionLogEntry] {
        let decoder = JSONDecoder()
        var byId: [String: TransactionLogEntry] = [:]
        for raw in (await store.extensionEntries(namespace: Self.namespace)).values {
            if let entry = try? decoder.decode(TransactionLogEntry.self, from: Data(raw.utf8)) { byId[entry.id] = entry }
        }
        for entry in await memory.entries() { byId[entry.id] = entry }
        return byId.values.sorted { $0.timestamp > $1.timestamp }
    }

    /// Removes the oldest records beyond each class's capacity. Only ever
    /// deletes entries it has read and decoded: a failed or partial read
    /// removes nothing.
    private func prune() async {
        let all = await entries()
        let keep = Set(InMemoryTransactionLogStore.bounded(all, capacity: capacity, refusedCapacity: refusedCapacity).map(\.id))
        for old in all where !keep.contains(old.id) {
            try? await store.removeExtensionEntry(namespace: Self.namespace, key: old.id)
        }
    }
}

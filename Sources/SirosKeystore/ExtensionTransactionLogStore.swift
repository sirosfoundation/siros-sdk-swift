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
    private let persisted: (@Sendable () async -> Void)?
    private let memory: InMemoryTransactionLogStore

    /// - Parameter persisted: called after a successful write so the owner
    ///   can export and sync the container (the wallet's `persistAndSyncKeystore`).
    public init(store: any ExtensionStore, capacity: Int = 500, persisted: (@Sendable () async -> Void)? = nil) {
        self.store = store
        self.capacity = max(1, capacity)
        self.persisted = persisted
        self.memory = InMemoryTransactionLogStore(capacity: max(1, capacity))
    }

    public func append(_ entries: [TransactionLogEntry]) async {
        await memory.append(entries)
        let encoder = JSONEncoder()
        var wrote = false
        for entry in entries {
            guard let data = try? encoder.encode(entry), let json = String(data: data, encoding: .utf8) else { continue }
            if (try? await store.setExtensionEntry(namespace: Self.namespace, key: entry.id, value: json)) != nil {
                wrote = true
            }
        }
        if wrote {
            await prune()
            await persisted?()
        }
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

    private func prune() async {
        let all = await entries()
        guard all.count > capacity else { return }
        for old in all.dropFirst(capacity) {
            try? await store.removeExtensionEntry(namespace: Self.namespace, key: old.id)
        }
    }
}

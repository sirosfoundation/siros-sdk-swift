// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosWallet

/// Joined-group persistence: provider URL, session and latest resumption
/// token. Restores resume those sessions rather than re-consuming invitations.
final class JsonFileWmpJoinStore: @unchecked Sendable {
    private struct Document: Codable {
        var joins: [WmpJoinRecord] = []
    }

    private let fileURL: URL
    private let lock = NSLock()

    init() {
        let directory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        self.fileURL = directory.appendingPathComponent("wmp-joins.json")
    }

    init(directory: URL) {
        self.fileURL = directory.appendingPathComponent("wmp-joins.json")
    }

    func load() -> [WmpJoinRecord] {
        lock.lock()
        defer { lock.unlock() }
        return read().joins
    }

    func save(_ record: WmpJoinRecord) {
        lock.lock()
        defer { lock.unlock() }
        var document = read()
        document.joins.removeAll { $0.providerUrl == record.providerUrl }
        document.joins.append(record)
        write(document)
    }

    func remove(providerUrl: String) {
        lock.lock()
        defer { lock.unlock() }
        var document = read()
        document.joins.removeAll { $0.providerUrl == providerUrl }
        write(document)
    }

    func clear() {
        lock.lock()
        defer { lock.unlock() }
        try? FileManager.default.removeItem(at: fileURL)
    }

    /// A missing or corrupt file is simply an empty store.
    private func read() -> Document {
        guard let data = try? Data(contentsOf: fileURL),
              let document = try? JSONDecoder().decode(Document.self, from: data) else {
            return Document()
        }
        return document
    }

    private func write(_ document: Document) {
        guard let data = try? JSONEncoder().encode(document) else { return }
        try? data.write(to: fileURL, options: .atomic)
    }
}

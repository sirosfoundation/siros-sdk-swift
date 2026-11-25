// Copyright 2026 SIROS Foundation. BSD-2-Clause License.

import Foundation

/// The wallet's group message store (issue #77): the inbox (the messages
/// the wallet's sessions received) and the outbox (its own sends) —
/// CLIENT-SIDE ONLY (never the backend: the relay is the Delivery
/// Service, wmp-mls.md §5; its own queueing may back onto Valkey or
/// similar, that's the gateway's business).
///
/// The seam: the SDK owns the plumbing (`SirosWallet` appends every
/// arrival, the apps render snapshots) and the STORE is app-supplied —
/// the app constructs its own persistence (its files, its database)
/// against this protocol, exactly like the engine's `Host` port. The
/// privatedata Rust library lands here later: it implements this
/// protocol, the app constructs it instead, nothing else moves.
///
/// Kotlin parity: `org.siros.sdk.wallet.WmpMessageStore`.
public protocol WmpMessageStore: Sendable {
    /// Append one message (idempotent by `messageId` when present).
    func append(_ message: WmpGroupMessage)

    /// The messages a session holds, newest first, up to `limit`.
    func load(backend: String, sessionId: String, limit: Int) -> [WmpGroupMessage]

    /// The poll cursor (the last `wmp_message_id` answered), nil when none.
    func cursor(backend: String, sessionId: String) -> String?

    /// Set the poll cursor.
    func setCursor(backend: String, sessionId: String, since: String)

    /// Keep at most `keep` messages per session (the retention).
    func prune(keep: Int)

    /// Drop everything (the logout/relogin path).
    func clear()
}

/// The message id's dedup key (absent ids fall back to the text).
extension WmpGroupMessage {
    var storeKey: String {
        "\(backend):\(sessionId):\(outbound ? "outbound" : "inbound"):\(messageId ?? text)"
    }
}

/// The in-memory store (the SDK's default when the app supplies none):
/// the whole inbox lives in a dictionary, gone with the process. The app
/// that wants persistence constructs its own `WmpMessageStore` (its
/// files, its database) and passes it in the config.
///
/// Kotlin parity: `InMemoryWmpMessageStore`.
public final class InMemoryWmpMessageStore: WmpMessageStore, @unchecked Sendable {
    /// The default instance (the config's nil fallback — one shared store
    /// per wallet process, matching the Kotlin default's lifetime).
    static let sharedDefault = InMemoryWmpMessageStore()

    private let lock = NSLock()
    private var boxes: [String: [WmpGroupMessage]] = [:]
    private var cursors: [String: String] = [:]

    public init() {}

    public func append(_ message: WmpGroupMessage) {
        lock.lock(); defer { lock.unlock() }
        let key = "\(message.backend):\(message.sessionId)"
        var box = boxes[key] ?? []
        if !box.contains(where: { $0.storeKey == message.storeKey }) {
            box.insert(message, at: 0)
            boxes[key] = box
        }
    }

    public func load(backend: String, sessionId: String, limit: Int) -> [WmpGroupMessage] {
        lock.lock(); defer { lock.unlock() }
        return boxes["\(backend):\(sessionId)"] ?? []
    }

    public func cursor(backend: String, sessionId: String) -> String? {
        lock.lock(); defer { lock.unlock() }
        return cursors["\(backend):\(sessionId)"]
    }

    public func setCursor(backend: String, sessionId: String, since: String) {
        lock.lock(); defer { lock.unlock() }
        cursors["\(backend):\(sessionId)"] = since
    }

    public func prune(keep: Int) {
        lock.lock(); defer { lock.unlock() }
        boxes = boxes.mapValues { Array($0.prefix(keep)) }
    }

    public func clear() {
        lock.lock(); defer { lock.unlock() }
        boxes.removeAll()
        cursors.removeAll()
    }
}
// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// In-memory cache for trust evaluation results.
///
/// Provides resilience when the backend is temporarily unreachable by serving
/// cached positive trust results for previously-evaluated verifiers.
///
/// Security invariants:
/// - Only positive (trusted=true) results are cached (never cache denials)
/// - TTL-based expiry prevents stale trust data
/// - Cache is keyed by full client_id (scheme + identifier)
public final class TrustCache: @unchecked Sendable {
    private struct Entry {
        let result: TrustResult
        let cachedAt: Date
    }

    private let ttl: TimeInterval
    private let maxSize: Int
    private var entries: [String: Entry] = [:]
    private var accessOrder: [String] = []
    private let lock = NSLock()

    /// - Parameters:
    ///   - ttl: Time-to-live for cache entries (default 1 hour).
    ///   - maxSize: Maximum number of entries (LRU eviction).
    public init(ttl: TimeInterval = 3600, maxSize: Int = 100) {
        self.ttl = ttl
        self.maxSize = maxSize
    }

    /// Store a trust result in the cache.
    /// Only trusted=true results are cached (security: never cache denials).
    func put(identifier: String, result: TrustResult) {
        guard result.trusted, !identifier.isEmpty else { return }

        lock.lock()
        defer { lock.unlock() }

        entries[identifier] = Entry(result: result, cachedAt: Date())
        accessOrder.removeAll { $0 == identifier }
        accessOrder.append(identifier)

        // LRU eviction
        while entries.count > maxSize, let eldest = accessOrder.first {
            entries.removeValue(forKey: eldest)
            accessOrder.removeFirst()
        }
    }

    /// Retrieve a cached trust result for the given identifier.
    /// Returns nil if no entry exists or the entry has expired.
    func get(identifier: String) -> TrustResult? {
        guard !identifier.isEmpty else { return nil }

        lock.lock()
        defer { lock.unlock() }

        guard let entry = entries[identifier] else { return nil }
        if Date().timeIntervalSince(entry.cachedAt) > ttl {
            entries.removeValue(forKey: identifier)
            accessOrder.removeAll { $0 == identifier }
            return nil // Expired
        }

        // Update access order for LRU
        accessOrder.removeAll { $0 == identifier }
        accessOrder.append(identifier)
        return entry.result
    }

    /// Clear all cached entries.
    func clear() {
        lock.lock()
        defer { lock.unlock() }
        entries.removeAll()
        accessOrder.removeAll()
    }

    /// Number of cached entries.
    var size: Int {
        lock.lock()
        defer { lock.unlock() }
        return entries.count
    }
}

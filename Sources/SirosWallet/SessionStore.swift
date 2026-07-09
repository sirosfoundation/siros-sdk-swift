// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Protocol for persisting session tokens and key material across app launches.
///
/// All reads/writes are scoped to the ``activeAccountId``. When set,
/// keys are prefixed with `{accountId}/` so multiple accounts coexist.
/// When nil, reads return nil and writes are no-ops.
public protocol SessionStoreProtocol: AnyObject, Sendable {
    /// The currently active account ID (`tenantId:userId`).
    var activeAccountId: String? { get set }

    var appToken: String? { get set }
    var refreshToken: String? { get set }
    var userId: String? { get set }
    var displayName: String? { get set }
    var tenantId: String? { get set }
    var mainKey: String? { get set }
    var hkdfSalt: String? { get set }
    var hkdfInfo: String? { get set }
    var prfSalt: String? { get set }
    var credentialId: String? { get set }
    var privateDataJwe: String? { get set }
    var privateDataEtag: String? { get set }
    var hasSession: Bool { get }

    /// Clear the active account's session data only.
    func clearAccount()
    /// Clear all accounts' session data (factory reset).
    func clearAll()
    /// Legacy alias for ``clearAccount()``.
    func clear()
}

/// Account-keyed in-memory session store for testing and Linux.
public final class InMemorySessionStore: SessionStoreProtocol, @unchecked Sendable {
    private let lock = NSLock()
    private var store: [String: String] = [:]

    public var activeAccountId: String?

    public init() {}

    private func scopedKey(_ key: String) -> String? {
        guard let id = activeAccountId else { return nil }
        return "\(id)/\(key)"
    }
    private func get(_ key: String) -> String? {
        guard let k = scopedKey(key) else { return nil }
        lock.lock(); defer { lock.unlock() }
        return store[k]
    }
    private func set(_ key: String, _ value: String?) {
        guard let k = scopedKey(key) else { return }
        lock.lock(); defer { lock.unlock() }
        if let value { store[k] = value } else { store.removeValue(forKey: k) }
    }

    public var appToken: String? { get { get("appToken") } set { set("appToken", newValue) } }
    public var refreshToken: String? { get { get("refreshToken") } set { set("refreshToken", newValue) } }
    public var userId: String? { get { get("userId") } set { set("userId", newValue) } }
    public var displayName: String? { get { get("displayName") } set { set("displayName", newValue) } }
    public var tenantId: String? { get { get("tenantId") } set { set("tenantId", newValue) } }
    public var mainKey: String? { get { get("mainKey") } set { set("mainKey", newValue) } }
    public var hkdfSalt: String? { get { get("hkdfSalt") } set { set("hkdfSalt", newValue) } }
    public var hkdfInfo: String? { get { get("hkdfInfo") } set { set("hkdfInfo", newValue) } }
    public var prfSalt: String? { get { get("prfSalt") } set { set("prfSalt", newValue) } }
    public var credentialId: String? { get { get("credentialId") } set { set("credentialId", newValue) } }
    public var privateDataJwe: String? { get { get("privateDataJwe") } set { set("privateDataJwe", newValue) } }
    public var privateDataEtag: String? { get { get("privateDataEtag") } set { set("privateDataEtag", newValue) } }

    public var hasSession: Bool { userId != nil }

    public func clearAccount() {
        guard let id = activeAccountId else { return }
        let prefix = "\(id)/"
        lock.lock(); defer { lock.unlock() }
        store = store.filter { !$0.key.hasPrefix(prefix) }
    }

    public func clearAll() {
        lock.lock(); defer { lock.unlock() }
        store.removeAll()
        activeAccountId = nil
    }

    public func clear() { clearAccount() }
}

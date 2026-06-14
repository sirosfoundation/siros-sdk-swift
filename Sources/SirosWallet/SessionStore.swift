// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Protocol for persisting session tokens and key material across app launches.
///
/// On iOS/macOS, implement using the Keychain. On other platforms, use any
/// secure storage appropriate for the environment.
public protocol SessionStoreProtocol: AnyObject, Sendable {
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
    func clear()
}

/// Simple in-memory session store for testing and Linux.
public final class InMemorySessionStore: SessionStoreProtocol, @unchecked Sendable {
    private let lock = NSLock()
    private var store: [String: String] = [:]

    public init() {}

    private func get(_ key: String) -> String? {
        lock.lock(); defer { lock.unlock() }
        return store[key]
    }
    private func set(_ key: String, _ value: String?) {
        lock.lock(); defer { lock.unlock() }
        if let value { store[key] = value } else { store.removeValue(forKey: key) }
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

    public var hasSession: Bool { appToken != nil && userId != nil }

    public func clear() {
        lock.lock(); defer { lock.unlock() }
        store.removeAll()
    }
}

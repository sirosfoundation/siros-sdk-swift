// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

#if canImport(Security)
import Foundation
import Security

/// Keychain-backed session store for iOS/macOS.
///
/// Stores session tokens and key material securely in the system Keychain
/// using `kSecClassGenericPassword` items scoped by a configurable service name.
///
/// Usage:
/// ```swift
/// let store = KeychainSessionStore(service: "org.siros.wallet")
/// let wallet = SirosWallet(config: config, authProvider: auth, sessionStore: store)
/// ```
public final class KeychainSessionStore: SessionStoreProtocol, @unchecked Sendable {
    private let lock = NSLock()
    private let service: String
    private let accessGroup: String?

    public var activeAccountId: String?

    /// Create a Keychain session store.
    ///
    /// - Parameters:
    ///   - service: Keychain service identifier (e.g. your bundle ID).
    ///   - accessGroup: Optional Keychain access group for sharing across apps.
    public init(service: String = "org.siros.wallet", accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }

    // MARK: - SessionStoreProtocol

    public var appToken: String? {
        get { read("appToken") }
        set { write("appToken", newValue) }
    }
    public var refreshToken: String? {
        get { read("refreshToken") }
        set { write("refreshToken", newValue) }
    }
    public var userId: String? {
        get { read("userId") }
        set { write("userId", newValue) }
    }
    public var displayName: String? {
        get { read("displayName") }
        set { write("displayName", newValue) }
    }
    public var tenantId: String? {
        get { read("tenantId") }
        set { write("tenantId", newValue) }
    }
    public var mainKey: String? {
        get { read("mainKey") }
        set { write("mainKey", newValue) }
    }
    public var hkdfSalt: String? {
        get { read("hkdfSalt") }
        set { write("hkdfSalt", newValue) }
    }
    public var hkdfInfo: String? {
        get { read("hkdfInfo") }
        set { write("hkdfInfo", newValue) }
    }
    public var prfSalt: String? {
        get { read("prfSalt") }
        set { write("prfSalt", newValue) }
    }
    public var credentialId: String? {
        get { read("credentialId") }
        set { write("credentialId", newValue) }
    }
    public var privateDataJwe: String? {
        get { read("privateDataJwe") }
        set { write("privateDataJwe", newValue) }
    }
    public var privateDataEtag: String? {
        get { read("privateDataEtag") }
        set { write("privateDataEtag", newValue) }
    }

    public var hasSession: Bool { userId != nil }

    public func clearAccount() {
        guard let id = activeAccountId else { return }
        // Delete all keys with the account prefix
        // Since Keychain doesn't support prefix queries easily,
        // we delete each known key individually
        let keys = ["appToken", "refreshToken", "userId", "displayName",
                    "tenantId", "mainKey", "hkdfSalt", "hkdfInfo",
                    "prfSalt", "credentialId", "privateDataJwe", "privateDataEtag"]
        lock.lock(); defer { lock.unlock() }
        for key in keys {
            let scopedKey = "\(id)/\(key)"
            var query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: scopedKey,
            ]
            if let group = accessGroup { query[kSecAttrAccessGroup as String] = group }
            SecItemDelete(query as CFDictionary)
        }
    }

    public func clearAll() {
        lock.lock(); defer { lock.unlock() }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        SecItemDelete(query as CFDictionary)
        activeAccountId = nil
    }

    public func clear() { clearAccount() }

    // MARK: - Keychain helpers

    private func scopedKey(_ key: String) -> String? {
        guard let id = activeAccountId else { return nil }
        return "\(id)/\(key)"
    }

    private func read(_ key: String) -> String? {
        guard let k = scopedKey(key) else { return nil }
        lock.lock()
        defer { lock.unlock() }

        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: k,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        if let group = accessGroup {
            query[kSecAttrAccessGroup as String] = group
        }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func write(_ key: String, _ value: String?) {
        guard let k = scopedKey(key) else { return }
        lock.lock()
        defer { lock.unlock() }

        var deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: k,
        ]
        if let group = accessGroup {
            deleteQuery[kSecAttrAccessGroup as String] = group
        }
        SecItemDelete(deleteQuery as CFDictionary)

        guard let value, let data = value.data(using: .utf8) else { return }

        var addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: k,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        if let group = accessGroup {
            addQuery[kSecAttrAccessGroup as String] = group
        }
        SecItemAdd(addQuery as CFDictionary, nil)
    }
}
#endif

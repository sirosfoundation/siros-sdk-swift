// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(Security)
import Security
#endif

/// Persistent registry of known accounts that survives logout.
///
/// Mirrors the frontend's `localStorage.cachedUsers` — stores an array
/// of ``CachedAccount`` entries so the login screen can show "Welcome back"
/// with a list of known accounts and their passkeys.
///
/// On Apple platforms, backed by the Keychain for encrypted storage.
/// On Linux, falls back to UserDefaults.
public final class AccountRegistry: @unchecked Sendable {

    private let lock = NSLock()
    private let decoder = JSONDecoder()
    private let encoder = JSONEncoder()
    private let service: String

    public init(service: String = "org.siros.wallet.accounts") {
        self.service = service
    }

    // MARK: - Account CRUD

    /// All known accounts across all tenants and backends.
    public func listAccounts() -> [CachedAccount] {
        lock.lock(); defer { lock.unlock() }
        guard let data = defaults.data(forKey: Keys.accounts) else { return [] }
        return (try? decoder.decode([CachedAccount].self, from: data)) ?? []
    }

    /// Accounts for a specific tenant.
    public func listAccounts(tenantId: String) -> [CachedAccount] {
        listAccounts().filter { $0.tenantId == tenantId }
    }

    /// Accounts that have at least one passkey with PRF support.
    public func listLoginableAccounts() -> [CachedAccount] {
        listAccounts().filter { $0.hasPrfKeys }
    }

    /// Accounts for a specific tenant that can log in.
    public func listLoginableAccounts(tenantId: String) -> [CachedAccount] {
        listAccounts(tenantId: tenantId).filter { $0.hasPrfKeys }
    }

    /// Find an account by its unique ID (`tenantId:userId`).
    public func findAccount(accountId: String) -> CachedAccount? {
        listAccounts().first { $0.accountId == accountId }
    }

    /// Add or update an account in the registry.
    public func upsertAccount(_ account: CachedAccount) {
        lock.lock(); defer { lock.unlock() }
        var accounts = loadAccountsLocked()
        if let index = accounts.firstIndex(where: { $0.accountId == account.accountId }) {
            accounts[index] = account
        } else {
            accounts.append(account)
        }
        saveAccountsLocked(accounts)
    }

    /// Remove an account from the registry.
    public func removeAccount(accountId: String) {
        lock.lock(); defer { lock.unlock() }
        var accounts = loadAccountsLocked()
        accounts.removeAll { $0.accountId == accountId }
        saveAccountsLocked(accounts)
        if readString(Keys.active) == accountId {
            deleteKey(Keys.active)
        }
    }

    /// Remove all cached accounts (factory reset).
    public func clear() {
        lock.lock(); defer { lock.unlock() }
        deleteAll()
    }

    // MARK: - Active Account

    /// The ID of the currently active account, or nil.
    public var activeAccountId: String? {
        get { readString(Keys.active) }
        set {
            if let id = newValue {
                writeString(Keys.active, id)
            } else {
                deleteKey(Keys.active)
            }
        }
    }

    // MARK: - Tenants

    /// Distinct tenants across all registered accounts.
    public func knownTenants() -> [TenantInfo] {
        let accounts = listAccounts()
        let grouped = Dictionary(grouping: accounts, by: { $0.tenantId })
        return grouped.map { (tenantId, accts) in
            TenantInfo(
                id: tenantId,
                accountCount: accts.count,
                backendUrl: accts.first?.backendUrl ?? ""
            )
        }
    }

    // MARK: - Storage Backend

    private func loadAccountsLocked() -> [CachedAccount] {
        guard let data = readData(Keys.accounts) else { return [] }
        return (try? decoder.decode([CachedAccount].self, from: data)) ?? []
    }

    private func saveAccountsLocked(_ accounts: [CachedAccount]) {
        guard let data = try? encoder.encode(accounts) else { return }
        writeData(Keys.accounts, data)
    }

    #if canImport(Security)
    // Keychain-backed storage (Apple platforms)

    private func readData(_ key: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { return nil }
        return result as? Data
    }

    private func writeData(_ key: String, _ data: Data) {
        deleteKey(key)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        SecItemAdd(query as CFDictionary, nil)
    }

    private func readString(_ key: String) -> String? {
        guard let data = readData(key) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func writeString(_ key: String, _ value: String) {
        guard let data = value.data(using: .utf8) else { return }
        writeData(key, data)
    }

    private func deleteKey(_ key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        SecItemDelete(query as CFDictionary)
    }

    private func deleteAll() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        SecItemDelete(query as CFDictionary)
    }

    #else
    // UserDefaults fallback (Linux)
    private let defaults = UserDefaults.standard

    private func readData(_ key: String) -> Data? { defaults.data(forKey: key) }
    private func writeData(_ key: String, _ data: Data) { defaults.set(data, forKey: key) }
    private func readString(_ key: String) -> String? { defaults.string(forKey: key) }
    private func writeString(_ key: String, _ value: String) { defaults.set(value, forKey: key) }
    private func deleteKey(_ key: String) { defaults.removeObject(forKey: key) }
    private func deleteAll() {
        deleteKey(Keys.accounts)
        deleteKey(Keys.active)
    }
    #endif

    private enum Keys {
        static let accounts = "siros_cached_accounts"
        static let active = "siros_active_account_id"
    }
}

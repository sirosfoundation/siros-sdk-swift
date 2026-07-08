// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Persistent registry of known accounts that survives logout.
///
/// Mirrors the frontend's `localStorage.cachedUsers` — stores an array
/// of ``CachedAccount`` entries so the login screen can show "Welcome back"
/// with a list of known accounts and their passkeys.
///
/// On iOS, backed by `UserDefaults` (the Keychain stores session secrets
/// separately via ``KeychainSessionStore``). On macOS/Linux, uses
/// `UserDefaults` as well.
public final class AccountRegistry: @unchecked Sendable {

    private let defaults: UserDefaults
    private let lock = NSLock()
    private let decoder = JSONDecoder()
    private let encoder = JSONEncoder()

    public init(suiteName: String? = nil) {
        if let suite = suiteName {
            self.defaults = UserDefaults(suiteName: suite) ?? .standard
        } else {
            self.defaults = .standard
        }
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
        // Clear active if it was the removed account
        if defaults.string(forKey: Keys.active) == accountId {
            defaults.removeObject(forKey: Keys.active)
        }
    }

    /// Remove all cached accounts (factory reset).
    public func clear() {
        lock.lock(); defer { lock.unlock() }
        defaults.removeObject(forKey: Keys.accounts)
        defaults.removeObject(forKey: Keys.active)
    }

    // MARK: - Active Account

    /// The ID of the currently active account, or nil.
    public var activeAccountId: String? {
        get { defaults.string(forKey: Keys.active) }
        set {
            if let id = newValue {
                defaults.set(id, forKey: Keys.active)
            } else {
                defaults.removeObject(forKey: Keys.active)
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

    // MARK: - Private

    private func loadAccountsLocked() -> [CachedAccount] {
        guard let data = defaults.data(forKey: Keys.accounts) else { return [] }
        return (try? decoder.decode([CachedAccount].self, from: data)) ?? []
    }

    private func saveAccountsLocked(_ accounts: [CachedAccount]) {
        guard let data = try? encoder.encode(accounts) else { return }
        defaults.set(data, forKey: Keys.accounts)
    }

    private enum Keys {
        static let accounts = "siros_cached_accounts"
        static let active = "siros_active_account_id"
    }
}

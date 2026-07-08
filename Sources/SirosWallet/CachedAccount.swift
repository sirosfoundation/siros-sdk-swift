// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// A passkey registered to an account — stores the credential ID and PRF salt
/// needed to re-derive the encryption key on login.
///
/// Mirrors the frontend's `WebauthnPrfSaltInfo`.
public struct CachedPasskey: Codable, Sendable, Equatable {
    /// Base64url-encoded WebAuthn credential ID.
    public var credentialId: String
    /// Base64-encoded PRF salt used during registration.
    public var prfSalt: String
    /// Optional user-assigned nickname (e.g. "My YubiKey").
    public var nickname: String

    public init(credentialId: String, prfSalt: String, nickname: String = "") {
        self.credentialId = credentialId
        self.prfSalt = prfSalt
        self.nickname = nickname
    }

    enum CodingKeys: String, CodingKey {
        case credentialId = "credential_id"
        case prfSalt = "prf_salt"
        case nickname
    }
}

/// A cached account entry that persists across logouts.
///
/// Mirrors the frontend's `CachedUser`. The account registry stores an
/// array of these — they survive logout and allow the login screen to
/// show "Welcome back" with a list of known accounts.
public struct CachedAccount: Codable, Sendable, Equatable, Identifiable {
    /// User ID from the AS (UUID).
    public var userId: String
    /// Tenant ID this account belongs to.
    public var tenantId: String
    /// User's display name (set at registration).
    public var displayName: String
    /// Backend URL this account was registered on.
    public var backendUrl: String
    /// Registered passkeys for this account.
    public var passkeys: [CachedPasskey]
    /// HKDF salt used for key derivation (base64).
    public var hkdfSalt: String
    /// HKDF info string (base64).
    public var hkdfInfo: String

    /// Unique account identifier: `tenantId:userId`.
    public var id: String { "\(tenantId):\(userId)" }

    /// Convenience alias matching Kotlin SDK.
    public var accountId: String { id }

    /// True if this account has at least one passkey with a PRF salt.
    public var hasPrfKeys: Bool { passkeys.contains { !$0.prfSalt.isEmpty } }

    public init(
        userId: String,
        tenantId: String,
        displayName: String,
        backendUrl: String,
        passkeys: [CachedPasskey] = [],
        hkdfSalt: String = "",
        hkdfInfo: String = ""
    ) {
        self.userId = userId
        self.tenantId = tenantId
        self.displayName = displayName
        self.backendUrl = backendUrl
        self.passkeys = passkeys
        self.hkdfSalt = hkdfSalt
        self.hkdfInfo = hkdfInfo
    }

    enum CodingKeys: String, CodingKey {
        case userId = "user_id"
        case tenantId = "tenant_id"
        case displayName = "display_name"
        case backendUrl = "backend_url"
        case passkeys
        case hkdfSalt = "hkdf_salt"
        case hkdfInfo = "hkdf_info"
    }
}

/// Summary info about a known tenant.
public struct TenantInfo: Sendable, Equatable {
    public let id: String
    public let accountCount: Int
    public let backendUrl: String
}

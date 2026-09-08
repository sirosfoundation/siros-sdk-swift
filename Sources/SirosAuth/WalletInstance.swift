// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// One wallet installation as the backend sees it (go-wallet-backend
/// `domain.WalletInstance`): registered when the installation first obtains a
/// Wallet Instance Attestation and identified by the JWK thumbprint of its
/// instance key. Lifecycle (SID-AUTH-06): `active` → `suspended` is reversible
/// and only blocks; `revoked` is terminal; revoking the last non-revoked
/// instance deactivates the wallet and erases its data server-side.
public struct WalletInstance: Sendable, Equatable {
    public enum Status: String, Sendable {
        case active
        case suspended
        case revoked
    }

    public let id: String
    public var tenantId: String = ""
    public var userId: String?
    public let status: Status
    public var wscdType: String = ""
    /// base64url WebAuthn credential id of the passkey this instance logs in
    /// with, when the client reported it at WIA generation. Lets an app match
    /// an instance to a passkey; nil for instances attested by older SDKs.
    public var credentialId: String?
    public var attestationSource: String = ""
    public var lastAttestedAt: String?
    public var statusReason: String?

    /// The two members every instance has; the rest are filled in from the
    /// backend's JSON by `init?(json:)` or set by the caller.
    public init(id: String, status: Status) {
        self.id = id
        self.status = status
    }

    /// Decodes the backend's JSON object; nil when `id` or a known `status` is missing.
    public init?(json: [String: Any]) {
        guard let id = json["id"] as? String,
              let status = (json["status"] as? String).flatMap(Status.init(rawValue:)) else { return nil }
        self.init(id: id, status: status)
        tenantId = json["tenant_id"] as? String ?? ""
        userId = json["user_id"] as? String
        wscdType = json["wscd_type"] as? String ?? ""
        credentialId = json["credential_id"] as? String
        attestationSource = json["attestation_source"] as? String ?? ""
        lastAttestedAt = json["last_attested_at"] as? String
        statusReason = json["status_reason"] as? String
    }
}

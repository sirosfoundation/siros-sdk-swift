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
    public let tenantId: String
    public let userId: String?
    public let status: Status
    public let wscdType: String
    /// base64url WebAuthn credential id of the passkey this instance logs in
    /// with, when the client reported it at WIA generation. Lets an app match
    /// an instance to a passkey; nil for instances attested by older SDKs.
    public let credentialId: String?
    public let attestationSource: String
    public let lastAttestedAt: String?
    public let statusReason: String?

    public init(
        id: String,
        tenantId: String = "",
        userId: String? = nil,
        status: Status,
        wscdType: String = "",
        credentialId: String? = nil,
        attestationSource: String = "",
        lastAttestedAt: String? = nil,
        statusReason: String? = nil
    ) {
        self.id = id
        self.tenantId = tenantId
        self.userId = userId
        self.status = status
        self.wscdType = wscdType
        self.credentialId = credentialId
        self.attestationSource = attestationSource
        self.lastAttestedAt = lastAttestedAt
        self.statusReason = statusReason
    }

    /// Decodes the backend's JSON object; nil when `id` or a known `status` is missing.
    public init?(json: [String: Any]) {
        guard let id = json["id"] as? String,
              let status = (json["status"] as? String).flatMap(Status.init(rawValue:)) else { return nil }
        self.init(
            id: id,
            tenantId: json["tenant_id"] as? String ?? "",
            userId: json["user_id"] as? String,
            status: status,
            wscdType: json["wscd_type"] as? String ?? "",
            credentialId: json["credential_id"] as? String,
            attestationSource: json["attestation_source"] as? String ?? "",
            lastAttestedAt: json["last_attested_at"] as? String,
            statusReason: json["status_reason"] as? String
        )
    }
}

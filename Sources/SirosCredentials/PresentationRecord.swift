// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// The privatedata-spec's own `S.presentations[]` shape only normatively
/// defines `id`/`credentialIds`/`timestamp`; the remaining fields
/// (flowId/verifierName/credentialNames/requestedClaims/success/zkProof) are
/// client-local enrichment layered on top, mirroring `StoredCredential`'s own
/// metadata/issuedAt/expiresAt precedent. They ARE persisted (see
/// `CodingKeys` below) into this client's own encrypted container - other
/// clients reading the same container simply don't populate or rely on them.
public struct PresentationRecord: Codable, Sendable, Equatable, Identifiable {
    public let id: Int64
    public let flowId: String
    public let verifierName: String?
    public let credentialIds: [Int64]
    public let credentialNames: [String]
    public let requestedClaims: [String]
    public let timestamp: Int64
    public let success: Bool
    /// True if presenting ANY of `credentialIds` this time was a
    /// zero-knowledge proof (`"mso_mdoc_zk"`) rather than a raw claim
    /// disclosure - lets history/UX distinguish the two, and lets
    /// ``CredentialConsumptionPolicy/consumeNonZkp`` be understood after the
    /// fact. Defaults to false so an older reloaded record (or a format that
    /// never involves ZK) doesn't need updating.
    public let zkProof: Bool

    public init(
        id: Int64,
        flowId: String,
        verifierName: String? = nil,
        credentialIds: [Int64],
        credentialNames: [String] = [],
        requestedClaims: [String] = [],
        timestamp: Int64,
        success: Bool = true,
        zkProof: Bool = false
    ) {
        self.id = id
        self.flowId = flowId
        self.verifierName = verifierName
        self.credentialIds = credentialIds
        self.credentialNames = credentialNames
        self.requestedClaims = requestedClaims
        self.timestamp = timestamp
        self.success = success
        self.zkProof = zkProof
    }

    enum CodingKeys: String, CodingKey {
        case id, timestamp, success
        case flowId = "flow_id"
        case verifierName = "verifier_name"
        case credentialIds = "credential_ids"
        case credentialNames = "credential_names"
        case requestedClaims = "requested_claims"
        case zkProof = "zk_proof"
    }

    /// Hand-written rather than synthesized: the synthesized decoder demands
    /// every non-optional key, but a record reloaded from the encrypted
    /// container (see `JweKeystore.loadPresentations`) carries only the
    /// privatedata-spec-normative `id`/`flow_id`/`credential_ids`/`timestamp`
    /// (plus `verifier_name` when an audience was recorded), and a record
    /// written before `zk_proof` existed lacks that key too. Every
    /// enrichment field therefore falls back to the same default the
    /// memberwise `init` uses.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(Int64.self, forKey: .id)
        flowId = try container.decodeIfPresent(String.self, forKey: .flowId) ?? ""
        verifierName = try container.decodeIfPresent(String.self, forKey: .verifierName)
        credentialIds = try container.decode([Int64].self, forKey: .credentialIds)
        credentialNames = try container.decodeIfPresent([String].self, forKey: .credentialNames) ?? []
        requestedClaims = try container.decodeIfPresent([String].self, forKey: .requestedClaims) ?? []
        timestamp = try container.decode(Int64.self, forKey: .timestamp)
        success = try container.decodeIfPresent(Bool.self, forKey: .success) ?? true
        zkProof = try container.decodeIfPresent(Bool.self, forKey: .zkProof) ?? false
    }
}

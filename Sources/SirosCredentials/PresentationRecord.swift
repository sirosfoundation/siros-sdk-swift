// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Android-only enrichment fields (flowId/verifierName/credentialNames/
/// requestedClaims/success) are NOT persisted into the encrypted container -
/// they mirror StoredCredential's own metadata/issuedAt/expiresAt precedent
/// of client-local, non-normative data layered on top of the privatedata-spec
/// shape (id/credentialIds/timestamp, matching S.presentations[]).
public struct PresentationRecord: Codable, Sendable, Equatable, Identifiable {
    public let id: Int64
    public let flowId: String
    public let verifierName: String?
    public let credentialIds: [Int64]
    public let credentialNames: [String]
    public let requestedClaims: [String]
    public let timestamp: Int64
    public let success: Bool

    public init(
        id: Int64,
        flowId: String,
        verifierName: String? = nil,
        credentialIds: [Int64],
        credentialNames: [String] = [],
        requestedClaims: [String] = [],
        timestamp: Int64,
        success: Bool = true
    ) {
        self.id = id
        self.flowId = flowId
        self.verifierName = verifierName
        self.credentialIds = credentialIds
        self.credentialNames = credentialNames
        self.requestedClaims = requestedClaims
        self.timestamp = timestamp
        self.success = success
    }

    enum CodingKeys: String, CodingKey {
        case id, timestamp, success
        case flowId = "flow_id"
        case verifierName = "verifier_name"
        case credentialIds = "credential_ids"
        case credentialNames = "credential_names"
        case requestedClaims = "requested_claims"
    }
}

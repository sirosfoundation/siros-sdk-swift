// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

public struct PresentationRecord: Codable, Sendable, Equatable, Identifiable {
    public let id: String
    public let flowId: String
    public let verifierName: String?
    public let credentialIds: [String]
    public let credentialNames: [String]
    public let requestedClaims: [String]
    public let timestamp: Int64
    public let success: Bool

    public init(
        id: String,
        flowId: String,
        verifierName: String? = nil,
        credentialIds: [String],
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

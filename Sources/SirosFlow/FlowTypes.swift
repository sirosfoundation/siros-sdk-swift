// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Events emitted during a credential flow. SDK consumer handles UI.
public enum FlowEvent: Sendable {
    /// Flow has started and is in progress.
    case progress(flowId: String, step: String, payload: [String: Any]?)

    /// Backend requests the client to sign (proof generation or VP).
    case signRequest(flowId: String, messageId: String, action: SignAction, params: SignParams)

    /// Backend requests credential matching (DCQL query).
    case matchRequest(flowId: String, messageId: String, dcqlQuery: [String: Any])

    /// Flow completed successfully.
    case complete(flowId: String, result: [String: Any]?)

    /// Flow failed with an error.
    case error(flowId: String, code: String?, message: String?)
}

/// Sign action requested by the backend.
public enum SignAction: String, Sendable {
    case generateProof = "generate_proof"
    case signPresentation = "sign_presentation"
}

/// Parameters for a sign request.
public struct SignParams: Sendable {
    public var audience: String?
    public var nonce: String?
    public var issuer: String?
    public var responseUri: String?
    public var verifierJwkThumbprint: String?
    public var count: Int?
    public var proofTypesSupported: [String: Any]?
    public var credentialsToInclude: [[String: Any]]?

    public init(
        audience: String? = nil,
        nonce: String? = nil,
        issuer: String? = nil,
        responseUri: String? = nil,
        verifierJwkThumbprint: String? = nil,
        count: Int? = nil,
        proofTypesSupported: [String: Any]? = nil,
        credentialsToInclude: [[String: Any]]? = nil
    ) {
        self.audience = audience
        self.nonce = nonce
        self.issuer = issuer
        self.responseUri = responseUri
        self.verifierJwkThumbprint = verifierJwkThumbprint
        self.count = count
        self.proofTypesSupported = proofTypesSupported
        self.credentialsToInclude = credentialsToInclude
    }
}

/// Response to a sign request.
public struct SignResponse: Sendable {
    public var proofJwt: String?
    public var proofs: [String]?
    public var vpToken: String?
    public var attestation: String?
    public var proofType: String?

    public init(proofJwt: String? = nil, proofs: [String]? = nil, vpToken: String? = nil, attestation: String? = nil, proofType: String? = nil) {
        self.proofJwt = proofJwt
        self.proofs = proofs
        self.vpToken = vpToken
        self.attestation = attestation
        self.proofType = proofType
    }
}

/// Response to a match request.
public struct MatchResponse: Sendable {
    public var credentialIds: [String]

    public init(credentialIds: [String]) {
        self.credentialIds = credentialIds
    }
}

/// Parameters for starting an OID4VCI flow.
public struct OID4VCIFlowParams: Sendable {
    public var credentialOfferUri: String?
    public var credentialOffer: [String: Any]?
    public var issuerUrl: String?

    public init(credentialOfferUri: String? = nil, credentialOffer: [String: Any]? = nil, issuerUrl: String? = nil) {
        self.credentialOfferUri = credentialOfferUri
        self.credentialOffer = credentialOffer
        self.issuerUrl = issuerUrl
    }
}

/// Parameters for starting an OID4VP flow.
public struct OID4VPFlowParams: Sendable {
    public var requestUri: String?
    public var request: [String: Any]?

    public init(requestUri: String? = nil, request: [String: Any]? = nil) {
        self.requestUri = requestUri
        self.request = request
    }
}

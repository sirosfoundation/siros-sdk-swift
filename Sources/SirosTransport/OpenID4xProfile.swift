// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

// MARK: - Flow Type Constants

public enum OID4FlowTypes {
    public static let oid4vci = "oid4vci"
    public static let oid4vp = "oid4vp"
}

// MARK: - OID4VCI Step Constants

public enum VCIStep {
    public static let parsingOffer = "parsing_offer"
    public static let resolvingMetadata = "resolving_metadata"
    public static let metadataFetched = "metadata_fetched"
    public static let evaluatingTrust = "evaluating_trust"
    public static let trustEvaluated = "trust_evaluated"
    public static let awaitingOfferAcceptance = "awaiting_offer_acceptance"
    public static let awaitingTxCode = "awaiting_tx_code"
    public static let authorizationPending = "authorization_pending"
    public static let generatingProof = "generating_proof"
    public static let requestingCredential = "requesting_credential"
    public static let credentialReceived = "credential_received"
}

// MARK: - OID4VP Step Constants

public enum VPStep {
    public static let parsingRequest = "parsing_request"
    public static let requestParsed = "request_parsed"
    public static let matchingCredentials = "matching_credentials"
    public static let awaitingConsent = "awaiting_consent"
    public static let generatingPresentation = "generating_presentation"
}

// MARK: - Action Constants

public enum OID4Action {
    public static let acceptOffer = "accept_offer"
    public static let provideTxCode = "provide_tx_code"
    public static let authorize = "authorize"
    public static let selectCredentials = "select_credentials"
    public static let cancel = "cancel"
}

// MARK: - Credential Format Constants

public enum CredentialFormat {
    public static let vcSdJwt = "vc+sd-jwt"
    public static let dcSdJwt = "dc+sd-jwt"
    public static let msoMdoc = "mso_mdoc"
    public static let jwtVcJson = "jwt_vc_json"
}

// MARK: - Grant Type Constants

public enum GrantType {
    public static let authorizationCode = "authorization_code"
    public static let preAuthorizedCode = "pre-authorized_code"
}

// MARK: - Proof Type Constants

public enum ProofType {
    public static let jwt = "jwt"
    public static let attestation = "attestation"
    public static let cwt = "cwt"
}

// MARK: - OID4VCI §10 Credential Lifecycle Events

public enum CredentialEvent {
    public static let accepted = "credential_accepted"
    public static let failure = "credential_failure"
}

// MARK: - Typed Data Structures

public struct CredentialConfigurationSupported: Codable, Sendable {
    public var format: String
    public var scope: String?
    public var vct: String?
    public var doctype: String?
    public var proofTypesSupported: AnyCodable?
    public var display: [CredentialDisplay]?

    enum CodingKeys: String, CodingKey {
        case format, scope, vct, doctype, display
        case proofTypesSupported = "proof_types_supported"
    }
}

public struct CredentialDisplay: Codable, Sendable {
    public var name: String
    public var locale: String?
    public var description: String?
    public var logoUri: String?
    public var logoAltText: String?
    public var backgroundColor: String?
    public var textColor: String?

    enum CodingKeys: String, CodingKey {
        case name, locale, description
        case logoUri = "logo_uri"
        case logoAltText = "logo_alt_text"
        case backgroundColor = "background_color"
        case textColor = "text_color"
    }
}

// CredentialResult is defined in EngineTypes.swift

public struct VPTokenResult: Codable, Sendable {
    public var vpToken: String?
    public var presentationSubmission: AnyCodable?
    public var responseCode: String?

    enum CodingKeys: String, CodingKey {
        case vpToken = "vp_token"
        case presentationSubmission = "presentation_submission"
        case responseCode = "response_code"
    }
}

public struct TransactionData: Codable, Sendable {
    public var type: String
    public var params: AnyCodable?
    public var credentialIds: [String]?
    public var hashAlgorithm: String?

    enum CodingKeys: String, CodingKey {
        case type, params
        case credentialIds = "credential_ids"
        case hashAlgorithm = "hash_alg"
    }
}

public struct SignSubFlowParams: Codable, Sendable {
    public var action: String
    public var nonce: String
    public var audience: String
    public var proofType: String?
    public var parentFlowId: String?
    public var count: Int?
    public var transactionData: [TransactionData]?

    enum CodingKeys: String, CodingKey {
        case action, nonce, audience, count
        case proofType = "proof_type"
        case parentFlowId = "parent_flow_id"
        case transactionData = "transaction_data"
    }
}

// MARK: - Client Attestation (WIA)

/// Provider for OAuth client attestation (WIA + PoP).
public protocol ClientAttestationProvider: AnyObject {
    /// Obtain a client attestation for the given audience.
    func getAttestation(audience: String) async throws -> ClientAttestation
}

public struct ClientAttestation: Codable, Sendable {
    /// Wallet Instance Attestation JWT.
    public var clientAssertion: String
    /// Proof of Possession JWT.
    public var clientAssertionPop: String

    enum CodingKeys: String, CodingKey {
        case clientAssertion = "client_assertion"
        case clientAssertionPop = "client_assertion_pop"
    }

    public init(clientAssertion: String, clientAssertionPop: String) {
        self.clientAssertion = clientAssertion
        self.clientAssertionPop = clientAssertionPop
    }
}

// MARK: - Sub-flow Result Types

// ProofObject and CredentialMatch are defined in EngineTypes.swift

public struct SignSubFlowResult: Sendable {
    public var proofs: [ProofObject]?
    public var vpToken: String?

    public init(proofs: [ProofObject]? = nil, vpToken: String? = nil) {
        self.proofs = proofs
        self.vpToken = vpToken
    }
}

// CredentialMatch is defined in EngineTypes.swift

public struct MatchResult: Sendable {
    public var matches: [CredentialMatch]

    public init(matches: [CredentialMatch]) {
        self.matches = matches
    }
}

public struct TrustResult: Sendable {
    public var trusted: Bool
    public var framework: String?
    public var reason: String?

    public init(trusted: Bool, framework: String? = nil, reason: String? = nil) {
        self.trusted = trusted
        self.framework = framework
        self.reason = reason
    }
}

// MARK: - OpenID4x Profile Configuration

// @unchecked because the stored async closures are not automatically @Sendable,
// but the struct is immutable after construction and only called from async contexts.
public struct OpenID4xConfig: @unchecked Sendable {
    public var onProgress: ((String, String, AnyCodable?) async -> Void)?
    public var onSignRequest: ((String, SignSubFlowParams) async throws -> SignSubFlowResult)?
    public var onMatchRequest: ((String, AnyCodable?) async throws -> MatchResult)?
    public var onTrustEvaluation: ((String, AnyCodable?) async throws -> TrustResult)?
    public var onComplete: ((String, AnyCodable?) async -> Void)?
    public var onError: ((String, String?, String?) async -> Void)?
    public var attestationProvider: ClientAttestationProvider?

    public init(
        onProgress: ((String, String, AnyCodable?) async -> Void)? = nil,
        onSignRequest: ((String, SignSubFlowParams) async throws -> SignSubFlowResult)? = nil,
        onMatchRequest: ((String, AnyCodable?) async throws -> MatchResult)? = nil,
        onTrustEvaluation: ((String, AnyCodable?) async throws -> TrustResult)? = nil,
        onComplete: ((String, AnyCodable?) async -> Void)? = nil,
        onError: ((String, String?, String?) async -> Void)? = nil,
        attestationProvider: ClientAttestationProvider? = nil
    ) {
        self.onProgress = onProgress
        self.onSignRequest = onSignRequest
        self.onMatchRequest = onMatchRequest
        self.onTrustEvaluation = onTrustEvaluation
        self.onComplete = onComplete
        self.onError = onError
        self.attestationProvider = attestationProvider
    }
}

// MARK: - OpenID4x Profile Implementation

private let stepSignRequest = "sign_request"
private let stepMatchRequest = "match_request"
private let stepTrustEvaluation = "trust_evaluation_required"

/// OpenID4x WMP profile for OID4VCI and OID4VP flows.
///
/// Handles server-initiated flows: the backend engine starts flows and
/// the SDK responds to progress events, sign requests, match requests,
/// and trust evaluations.
public final class OpenID4xProfile: WmpProfile, WmpFlowHandler, @unchecked Sendable {
    public let name: String = "openid4x"
    public let capabilities: [String] = ["oid4vci", "oid4vp"]
    public let flowTypes: [String] = [OID4FlowTypes.oid4vci, OID4FlowTypes.oid4vp]

    private let config: OpenID4xConfig
    private weak var peer: WmpPeerContext?

    public init(config: OpenID4xConfig = OpenID4xConfig()) {
        self.config = config
    }

    // MARK: - WmpProfile

    public func initialize(ctx: WmpPeerContext) {
        peer = ctx
    }

    // MARK: - WmpFlowHandler

    public func startFlow(params: FlowStartParams) async throws -> FlowStartResult {
        return FlowStartResult(flowId: params.flowId, flowType: params.flowType)
    }

    public func handleProgress(params: FlowProgressParams) async {
        let flowId = params.flowId
        let step = params.step
        let payload = params.payload

        switch step {
        case stepSignRequest, VCIStep.generatingProof:
            await handleSignRequest(flowId: flowId, payload: payload)
        case stepMatchRequest, VPStep.matchingCredentials:
            await handleMatchRequest(flowId: flowId, payload: payload)
        case stepTrustEvaluation, VCIStep.evaluatingTrust:
            await handleTrustEvaluation(flowId: flowId, payload: payload)
        default:
            await config.onProgress?(flowId, step, payload)
        }
    }

    public func handleAction(params: FlowActionParams) async throws -> FlowActionResult {
        return FlowActionResult(flowId: params.flowId, accepted: true)
    }

    public func handleComplete(params: FlowCompleteParams) async {
        await config.onComplete?(params.flowId, params.result)
    }

    public func handleError(params: FlowErrorParams) async {
        await config.onError?(params.flowId, params.code, params.message)
    }

    public func handleCancel(params: FlowCancelParams) async {
        // No-op for now
    }

    // MARK: - Sub-flow Handlers

    private func handleSignRequest(flowId: String, payload: AnyCodable?) async {
        guard let handler = config.onSignRequest else { return }

        guard let payload else {
            await sendFlowError(flowId: flowId, code: "INVALID_PARAMS", message: "sign_request missing payload")
            return
        }
        let signParams: SignSubFlowParams
        do {
            let data = try JSONEncoder().encode(payload)
            signParams = try JSONDecoder().decode(SignSubFlowParams.self, from: data)
        } catch {
            await sendFlowError(flowId: flowId, code: "INVALID_PARAMS", message: "sign_request payload decode failed: \(error.localizedDescription)")
            return
        }

        do {
            let result = try await handler(flowId, signParams)
            await sendSignResponse(flowId: flowId, result: result)
        } catch {
            await sendFlowError(flowId: flowId, code: "SIGN_ERROR", message: error.localizedDescription)
        }
    }

    private func handleMatchRequest(flowId: String, payload: AnyCodable?) async {
        guard let handler = config.onMatchRequest else { return }

        do {
            let result = try await handler(flowId, payload)
            await sendMatchResponse(flowId: flowId, result: result)
        } catch {
            await sendFlowError(flowId: flowId, code: "MATCH_ERROR", message: error.localizedDescription)
        }
    }

    private func handleTrustEvaluation(flowId: String, payload: AnyCodable?) async {
        guard let handler = config.onTrustEvaluation else { return }

        do {
            let result = try await handler(flowId, payload)
            await sendTrustResult(flowId: flowId, result: result)
        } catch {
            await sendTrustResult(flowId: flowId, result: TrustResult(trusted: false, reason: error.localizedDescription))
        }
    }

    // MARK: - Response Helpers

    private func sendSignResponse(flowId: String, result: SignSubFlowResult) async {
        guard let peer else { return }
        var params: [String: AnyCodable] = [
            "flow_id": .string(flowId),
            "action": .string("sign_response"),
        ]
        if let proofs = result.proofs {
            let encoded = proofs.map { proof -> [String: AnyCodable] in
                var dict: [String: AnyCodable] = ["proof_type": .string(proof.proofType)]
                if let jwt = proof.jwt { dict["jwt"] = .string(jwt) }
                return dict
            }
            params["proofs"] = .array(encoded.map { .object_($0) })
        }
        if let vpToken = result.vpToken {
            params["vp_token"] = .string(vpToken)
        }
        try? await peer.notify(method: WmpMethods.flowAction, params: params)
    }

    private func sendMatchResponse(flowId: String, result: MatchResult) async {
        guard let peer else { return }
        let matchArray = result.matches.map { match -> [String: AnyCodable] in
            var dict: [String: AnyCodable] = [
                "credential_id": .string(match.credentialId),
                "format": .string(match.format),
            ]
            if let qid = match.credentialQueryId { dict["credential_query_id"] = .string(qid) }
            if let vct = match.vct { dict["vct"] = .string(vct) }
            if let claims = match.availableClaims { dict["available_claims"] = .array(claims.map { .string($0) }) }
            return dict
        }
        let params: [String: AnyCodable] = [
            "flow_id": .string(flowId),
            "action": .string("match_response"),
            "matches": .array(matchArray.map { AnyCodable.object_($0) }),
        ]
        try? await peer.notify(method: WmpMethods.flowAction, params: params)
    }

    private func sendTrustResult(flowId: String, result: TrustResult) async {
        guard let peer else { return }
        var params: [String: AnyCodable] = [
            "flow_id": .string(flowId),
            "action": .string("trust_result"),
            "trusted": .bool(result.trusted),
        ]
        if let framework = result.framework { params["framework"] = .string(framework) }
        if let reason = result.reason { params["reason"] = .string(reason) }
        try? await peer.notify(method: WmpMethods.flowAction, params: params)
    }

    private func sendFlowError(flowId: String, code: String, message: String?) async {
        guard let peer else { return }
        var params: [String: AnyCodable] = [
            "flow_id": .string(flowId),
            "code": .string(code),
        ]
        if let message { params["message"] = .string(message) }
        try? await peer.notify(method: WmpMethods.flowError, params: params)
    }
}

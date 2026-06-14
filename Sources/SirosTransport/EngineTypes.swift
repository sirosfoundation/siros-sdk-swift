// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Message types used in the wallet backend engine WebSocket protocol.
public enum MessageTypes {
    // Client → Server
    public static let handshake = "handshake"
    public static let flowStart = "flow_start"
    public static let flowAction = "flow_action"
    public static let signResponse = "sign_response"
    public static let matchResponse = "match_response"

    // Server → Client
    public static let handshakeComplete = "handshake_complete"
    public static let flowProgress = "flow_progress"
    public static let flowComplete = "flow_complete"
    public static let flowError = "flow_error"
    public static let signRequest = "sign_request"
    public static let matchRequest = "match_request"
    public static let push = "push"
    public static let error = "error"
}

/// Base envelope — every engine message carries at least a type.
public struct EngineMessage: Codable, Sendable, Equatable {
    public var type: String
    public var flowId: String?
    public var messageId: String?
    public var timestamp: String?

    enum CodingKeys: String, CodingKey {
        case type, timestamp
        case flowId = "flow_id"
        case messageId = "message_id"
    }
}

// MARK: - Client → Server

public struct HandshakeMessage: Codable, Sendable {
    public var type: String
    public var appToken: String

    public init(type: String = MessageTypes.handshake, appToken: String) {
        self.type = type
        self.appToken = appToken
    }

    enum CodingKeys: String, CodingKey {
        case type
        case appToken = "app_token"
    }
}

public struct FlowStartMessage: Codable, Sendable {
    public var type: String
    public var `protocol`: String
    public var offer: String?
    public var credentialOfferUri: String?
    public var requestUri: String?
    public var requestUriRef: String?
    public var vct: String?
    public var redirectUri: String?
    public var authCode: String?
    public var codeVerifier: String?
    public var timestamp: String?

    public init(
        type: String = MessageTypes.flowStart,
        protocol: String,
        offer: String? = nil,
        credentialOfferUri: String? = nil,
        requestUri: String? = nil,
        requestUriRef: String? = nil,
        vct: String? = nil,
        redirectUri: String? = nil,
        authCode: String? = nil,
        codeVerifier: String? = nil,
        timestamp: String? = nil
    ) {
        self.type = type
        self.protocol = `protocol`
        self.offer = offer
        self.credentialOfferUri = credentialOfferUri
        self.requestUri = requestUri
        self.requestUriRef = requestUriRef
        self.vct = vct
        self.redirectUri = redirectUri
        self.authCode = authCode
        self.codeVerifier = codeVerifier
        self.timestamp = timestamp
    }

    enum CodingKeys: String, CodingKey {
        case type, `protocol`, offer, vct, timestamp
        case credentialOfferUri = "credential_offer_uri"
        case requestUri = "request_uri"
        case requestUriRef = "request_uri_ref"
        case redirectUri = "redirect_uri"
        case authCode = "auth_code"
        case codeVerifier = "code_verifier"
    }
}

public struct FlowActionMessage: Codable, Sendable {
    public var type: String
    public var flowId: String
    public var action: String
    public var payload: [String: AnyCodable]?
    public var timestamp: String?

    public init(
        type: String = MessageTypes.flowAction,
        flowId: String,
        action: String,
        payload: [String: AnyCodable]? = nil,
        timestamp: String? = nil
    ) {
        self.type = type
        self.flowId = flowId
        self.action = action
        self.payload = payload
        self.timestamp = timestamp
    }

    enum CodingKeys: String, CodingKey {
        case type, action, payload, timestamp
        case flowId = "flow_id"
    }
}

public struct SignResponseMessage: Codable, Sendable {
    public var type: String
    public var flowId: String
    public var messageId: String?
    public var proofJwt: String?
    public var vpToken: String?
    public var proofs: [ProofObject]?
    public var timestamp: String?

    public init(
        type: String = MessageTypes.signResponse,
        flowId: String,
        messageId: String? = nil,
        proofJwt: String? = nil,
        vpToken: String? = nil,
        proofs: [ProofObject]? = nil,
        timestamp: String? = nil
    ) {
        self.type = type
        self.flowId = flowId
        self.messageId = messageId
        self.proofJwt = proofJwt
        self.vpToken = vpToken
        self.proofs = proofs
        self.timestamp = timestamp
    }

    enum CodingKeys: String, CodingKey {
        case type, proofs, timestamp
        case flowId = "flow_id"
        case messageId = "message_id"
        case proofJwt = "proof_jwt"
        case vpToken = "vp_token"
    }
}

public struct ProofObject: Codable, Sendable {
    public var proofType: String
    public var jwt: String?
    public var attestation: String?

    public init(proofType: String, jwt: String? = nil, attestation: String? = nil) {
        self.proofType = proofType
        self.jwt = jwt
        self.attestation = attestation
    }

    enum CodingKeys: String, CodingKey {
        case jwt, attestation
        case proofType = "proof_type"
    }
}

public struct MatchResponseMessage: Codable, Sendable {
    public var type: String
    public var flowId: String
    public var matches: [CredentialMatch]
    public var noMatchReason: String?
    public var error: String?
    public var timestamp: String?

    public init(
        type: String = MessageTypes.matchResponse,
        flowId: String,
        matches: [CredentialMatch],
        noMatchReason: String? = nil,
        error: String? = nil,
        timestamp: String? = nil
    ) {
        self.type = type
        self.flowId = flowId
        self.matches = matches
        self.noMatchReason = noMatchReason
        self.error = error
        self.timestamp = timestamp
    }

    enum CodingKeys: String, CodingKey {
        case type, matches, error, timestamp
        case flowId = "flow_id"
        case noMatchReason = "no_match_reason"
    }
}

public struct CredentialMatch: Codable, Sendable {
    public var credentialQueryId: String?
    public var credentialId: String
    public var format: String
    public var vct: String?
    public var availableClaims: [String]?

    public init(
        credentialQueryId: String? = nil,
        credentialId: String,
        format: String,
        vct: String? = nil,
        availableClaims: [String]? = nil
    ) {
        self.credentialQueryId = credentialQueryId
        self.credentialId = credentialId
        self.format = format
        self.vct = vct
        self.availableClaims = availableClaims
    }

    enum CodingKeys: String, CodingKey {
        case format, vct
        case credentialQueryId = "credential_query_id"
        case credentialId = "credential_id"
        case availableClaims = "available_claims"
    }
}

// MARK: - Server → Client

public struct HandshakeCompleteMessage: Codable, Sendable {
    public var type: String
    public var sessionId: String
    public var capabilities: [String]?
    public var timestamp: String?

    enum CodingKeys: String, CodingKey {
        case type, capabilities, timestamp
        case sessionId = "session_id"
    }
}

public struct FlowProgressMessage: Codable, Sendable {
    public var type: String
    public var flowId: String
    public var step: String
    public var payload: AnyCodable?
    public var timestamp: String?

    enum CodingKeys: String, CodingKey {
        case type, step, payload, timestamp
        case flowId = "flow_id"
    }
}

public struct FlowCompleteMessage: Codable, Sendable {
    public var type: String
    public var flowId: String
    public var credentials: [CredentialResult]?
    public var redirectUri: String?
    public var typeMetadata: AnyCodable?
    public var credentialIssuer: String?
    public var selectedCredentialConfigurationId: String?
    public var timestamp: String?

    enum CodingKeys: String, CodingKey {
        case type, credentials, timestamp
        case flowId = "flow_id"
        case redirectUri = "redirect_uri"
        case typeMetadata = "type_metadata"
        case credentialIssuer = "credential_issuer"
        case selectedCredentialConfigurationId = "selected_credential_configuration_id"
    }
}

public struct CredentialResult: Codable, Sendable {
    public var format: String
    public var credential: String
    public var vct: String?
    public var typeMetadata: AnyCodable?

    enum CodingKeys: String, CodingKey {
        case format, credential, vct
        case typeMetadata = "type_metadata"
    }
}

public struct FlowErrorMessage: Codable, Sendable {
    public var type: String
    public var flowId: String?
    public var step: String?
    public var error: FlowError
    public var timestamp: String?

    enum CodingKeys: String, CodingKey {
        case type, step, error, timestamp
        case flowId = "flow_id"
    }
}

public struct FlowError: Codable, Sendable {
    public var code: String
    public var message: String
    public var details: [String: AnyCodable]?
}

public struct SignRequestMessage: Codable, Sendable {
    public var type: String
    public var flowId: String
    public var messageId: String?
    public var action: String
    public var params: SignRequestParams
    public var timestamp: String?

    enum CodingKeys: String, CodingKey {
        case type, action, params, timestamp
        case flowId = "flow_id"
        case messageId = "message_id"
    }
}

public struct SignRequestParams: Codable, Sendable {
    public var audience: String?
    public var nonce: String?
    public var issuer: String?
    public var proofType: String?
    public var proofTypesSupported: [String: AnyCodable]?
    public var count: Int?
    public var credentialsToInclude: [CredentialRef]?
    public var responseUri: String?
    public var verifierJwkThumbprint: String?

    enum CodingKeys: String, CodingKey {
        case audience, nonce, issuer, count
        case proofType = "proof_type"
        case proofTypesSupported = "proof_types_supported"
        case credentialsToInclude = "credentials_to_include"
        case responseUri = "response_uri"
        case verifierJwkThumbprint = "verifier_jwk_thumbprint"
    }
}

public struct CredentialRef: Codable, Sendable {
    public var credentialQueryId: String?
    public var credentialId: String
    public var disclosedClaims: [String]?

    enum CodingKeys: String, CodingKey {
        case credentialId = "credential_id"
        case credentialQueryId = "credential_query_id"
        case disclosedClaims = "disclosed_claims"
    }
}

public struct MatchRequestMessage: Codable, Sendable {
    public var type: String
    public var flowId: String
    public var dcqlQuery: AnyCodable?
    public var timestamp: String?

    enum CodingKeys: String, CodingKey {
        case type, timestamp
        case flowId = "flow_id"
        case dcqlQuery = "dcql_query"
    }
}

public struct PushMessage: Codable, Sendable {
    public var type: String
    public var pushType: String
    public var credentials: [CredentialResult]?
    public var timestamp: String?

    enum CodingKeys: String, CodingKey {
        case type, credentials, timestamp
        case pushType = "push_type"
    }
}

public struct ErrorMessage: Codable, Sendable {
    public var type: String
    public var code: String
    public var details: String
    public var timestamp: String?

    enum CodingKeys: String, CodingKey {
        case type, code, timestamp
        case details = "message"
    }
}

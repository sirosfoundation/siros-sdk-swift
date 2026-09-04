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
    /// OID4VCI §10 credential lifecycle notification reported to the backend
    /// for forwarding to the issuer.
    public static let credentialNotification = "credential_notification"

    // Server → Client
    public static let handshakeComplete = "handshake_complete"
    public static let flowProgress = "flow_progress"
    public static let flowComplete = "flow_complete"
    public static let flowError = "flow_error"
    public static let signRequest = "sign_request"
    public static let matchRequest = "match_request"
    public static let push = "push"
    public static let error = "error"
    /// Acknowledgement of a credential_notification from the backend.
    public static let notificationAck = "notification_ack"
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
    /// OAuth Client Attestation (draft-ietf-oauth-attestation-based-client-auth-04
    /// §3.1): a Wallet Instance Attestation JWT (`typ: oauth-client-attestation+jwt`)
    /// obtained from this wallet's own backend (`/wallet-provider/wia/generate`).
    /// Forwarded by go-wallet-backend as the `OAuth-Client-Attestation` HTTP
    /// header on PAR/token requests to the credential issuer.
    public var clientAttestation: String?
    /// The matching PoP JWT (`typ: oauth-client-attestation-pop+jwt`), freshly
    /// signed per flow with `aud` = the credential issuer's own authorization
    /// server, proving possession of the instance key the WIA above is bound
    /// to (`cnf.jwk`/`cnf.jkt`). Forwarded as `OAuth-Client-Attestation-PoP`.
    public var clientAttestationPoP: String?
    /// Renewal fields (credential re-issuance/renewal plan, Phase 1 Slice 2
    /// - see go-wallet-backend's `internal/engine/oid4vci.go` `Execute`).
    /// When `refreshToken` is set, this is a renewal request rather than a
    /// fresh issuance: `offer`/`credentialOfferUri` are unused, and
    /// `credentialIssuer`/`selectedCredentialConfigurationId` are required
    /// instead (the client already knows both from the credential being
    /// renewed).
    public var refreshToken: String?
    public var credentialIssuer: String?
    public var selectedCredentialConfigurationId: String?
    /// When set, asks the server to request a `generate_proof` signature
    /// using this existing kid instead of a fresh one - same-wallet-unit
    /// continuity evidence for a renewal. Optional even on a renewal
    /// request.
    public var reissuanceKid: String?
    /// On a renewal request, the private DPoP JWK previously captured from
    /// `FlowCompleteMessage.dpopJwk` for this same refresh_token. The
    /// issuer's refresh_token grant binds the token to the exact DPoP key
    /// used at initial issuance (RFC 9449/ARF ISSU_65 §6.6.6.2.2), so the
    /// backend must reuse this key rather than generate a fresh one. Never
    /// persisted by the SDK itself beyond whatever the caller does with it
    /// (privatedata, Phase 2).
    public var dpopJwk: String?
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
        clientAttestation: String? = nil,
        clientAttestationPoP: String? = nil,
        refreshToken: String? = nil,
        credentialIssuer: String? = nil,
        selectedCredentialConfigurationId: String? = nil,
        reissuanceKid: String? = nil,
        dpopJwk: String? = nil,
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
        self.clientAttestation = clientAttestation
        self.clientAttestationPoP = clientAttestationPoP
        self.refreshToken = refreshToken
        self.credentialIssuer = credentialIssuer
        self.selectedCredentialConfigurationId = selectedCredentialConfigurationId
        self.reissuanceKid = reissuanceKid
        self.dpopJwk = dpopJwk
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
        case clientAttestation = "client_attestation"
        case clientAttestationPoP = "client_attestation_pop"
        case refreshToken = "refresh_token"
        case credentialIssuer = "credential_issuer"
        case selectedCredentialConfigurationId = "selected_credential_configuration_id"
        case reissuanceKid = "reissuance_kid"
        case dpopJwk = "dpop_jwk"
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
    /// Response to a `request_attestation` sign request (go-wallet-backend's
    /// `SignActionRequestAttestation`): the Wallet Instance Attestation JWT
    /// (`typ: oauth-client-attestation+jwt`) and the per-flow PoP JWT
    /// (`typ: oauth-client-attestation-pop+jwt`) the client signed with its
    /// instance key, with `aud`/`iss` taken from the request's
    /// `SignRequestParams.audience`/`.issuer`. Both nil means the client has
    /// no attestation to offer - the engine then proceeds without wallet
    /// attestation rather than waiting for one.
    public var clientAttestation: String?
    public var clientAttestationPoP: String?
    public var timestamp: String?

    public init(
        type: String = MessageTypes.signResponse,
        flowId: String,
        messageId: String? = nil,
        proofJwt: String? = nil,
        vpToken: String? = nil,
        proofs: [ProofObject]? = nil,
        clientAttestation: String? = nil,
        clientAttestationPoP: String? = nil,
        timestamp: String? = nil
    ) {
        self.type = type
        self.flowId = flowId
        self.messageId = messageId
        self.proofJwt = proofJwt
        self.vpToken = vpToken
        self.proofs = proofs
        self.clientAttestation = clientAttestation
        self.clientAttestationPoP = clientAttestationPoP
        self.timestamp = timestamp
    }

    enum CodingKeys: String, CodingKey {
        case type, proofs, timestamp
        case flowId = "flow_id"
        case messageId = "message_id"
        case proofJwt = "proof_jwt"
        case vpToken = "vp_token"
        case clientAttestation = "client_attestation"
        case clientAttestationPoP = "client_attestation_pop"
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
    /// OAuth refresh_token the issuer's token endpoint returned alongside
    /// this batch, if any (OID4VCI issuance only). Captured durably into
    /// `privatedata` (`S.credentialRefreshTokens`) by
    /// `SirosWallet+Notifications.swift`'s `handleFlowComplete` so
    /// `SirosWallet.renewCredential(batchId:)` can use it later.
    public var refreshToken: String?
    /// The private JWK of the ephemeral DPoP key this flow used for its
    /// token exchange, present only alongside `refreshToken`. Must be
    /// presented back as `FlowStartMessage.dpopJwk` on a renewal request.
    public var dpopJwk: String?
    public var timestamp: String?

    enum CodingKeys: String, CodingKey {
        case type, credentials, timestamp
        case flowId = "flow_id"
        case redirectUri = "redirect_uri"
        case typeMetadata = "type_metadata"
        case credentialIssuer = "credential_issuer"
        case selectedCredentialConfigurationId = "selected_credential_configuration_id"
        case refreshToken = "refresh_token"
        case dpopJwk = "dpop_jwk"
    }
}

public struct CredentialResult: Codable, Sendable {
    public var format: String
    public var credential: String
    public var vct: String?
    public var typeMetadata: AnyCodable?
    /// OID4VCI §10 notification identifier for this credential, if the issuer
    /// returned one. Persisted client-side and echoed back when a lifecycle
    /// event occurs.
    public var notificationId: String?

    enum CodingKeys: String, CodingKey {
        case format, credential, vct
        case typeMetadata = "type_metadata"
        case notificationId = "notification_id"
    }
}

/// Outgoing OID4VCI §10 credential lifecycle notification. The client supplies
/// the notification_id obtained at issuance; the backend supplies the issuer
/// endpoint and access token from ephemeral flow state.
public struct CredentialNotificationMessage: Codable, Sendable {
    public var type: String
    public var flowId: String
    public var notificationId: String
    public var event: String
    public var eventDescription: String?
    public var timestamp: String?

    public init(
        type: String = MessageTypes.credentialNotification,
        flowId: String,
        notificationId: String,
        event: String,
        eventDescription: String? = nil,
        timestamp: String? = nil
    ) {
        self.type = type
        self.flowId = flowId
        self.notificationId = notificationId
        self.event = event
        self.eventDescription = eventDescription
        self.timestamp = timestamp
    }

    enum CodingKeys: String, CodingKey {
        case type, event, timestamp
        case flowId = "flow_id"
        case notificationId = "notification_id"
        case eventDescription = "event_description"
    }
}

/// Incoming acknowledgement for a credential_notification.
public struct NotificationAckMessage: Codable, Sendable {
    public var type: String
    public var flowId: String?
    public var notificationId: String?
    public var status: String
    public var error: String?
    public var timestamp: String?

    enum CodingKeys: String, CodingKey {
        case type, status, error, timestamp
        case flowId = "flow_id"
        case notificationId = "notification_id"
    }
}

/// OID4VCI §10 credential lifecycle event identifiers reportable to the backend.
public enum CredentialNotificationEvent {
    public static let accepted = "credential_accepted"
    public static let failure = "credential_failure"
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
    /// When set (a renewal's continuity proof), the client should sign the
    /// `generate_proof` response with this existing kid instead of a fresh
    /// key - see `FlowStartMessage.reissuanceKid`'s doc comment.
    public var reissuanceKid: String?
    /// The verifier-assigned session id for this specific presentation -
    /// go-wallet-backend parses this from the `request_uri`'s `?sessionId=`
    /// query parameter (the only hop that ever sees the raw request_uri) and
    /// forwards it here so a ZK/PPID proof's `verifier_context` can bind to
    /// the actual presentation SESSION, not just the verifier's static
    /// identity - see `VerifierIdentity.sessionId`'s doc comment.
    public var verifierSessionId: String?

    enum CodingKeys: String, CodingKey {
        case audience, nonce, issuer, count
        case proofType = "proof_type"
        case proofTypesSupported = "proof_types_supported"
        case credentialsToInclude = "credentials_to_include"
        case responseUri = "response_uri"
        case verifierJwkThumbprint = "verifier_jwk_thumbprint"
        case reissuanceKid = "reissuance_kid"
        case verifierSessionId = "verifier_session_id"
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

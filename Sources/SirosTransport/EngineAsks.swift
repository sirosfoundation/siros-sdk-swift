// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

//
// siros-wallet-core's typed asks — the child flows the Rust engine starts on the
// wallet (engine-ports' `Host` vocabulary, bridged by the server's `RemoteHost` as
// `<parent>::<type>::<seq>` child flows). Field-for-field mirrors of the serde
// structs in siros-wallet-core's crates/engine-ports/src/lib.rs: the same member
// names, the same null vs absent shapes, so a profile answers them without a
// translation layer.
//
// A SECOND ask dialect beside go-wmp's (the `sign` sub-flow with its `action`
// member, and `match`): LEGACY_WS speaks go-wmp's against the Go engine, and the
// httpSSE/local modes speak these against siros-wallet-core. The profile tells
// them apart by shape, never by configuration.
//

/// The bare `sign` ask (engine-ports `SignParams`): one raw signature over the
/// bytes the engine built (an OID4VCI proof's `header.payload` ASCII, an RFC 7523
/// assertion, an engine-held DPoP proof) — the key never left the wallet.
///
/// `toSign` is `Vec<u8>` on the wire: a JSON array of byte values.
public struct EngineSignParams: Codable, Sendable {
    /// The PARENT flow's id (the ask rides a `<parent>::sign::<n>` child).
    public var flowId: String?
    /// The raw to-be-signed bytes.
    public var toSign: [UInt8] = []
    /// The wallet key to sign with; nil = the default proof key.
    public var keyId: String?
    /// The JWS algorithm the engine wants ("ES256" today).
    public var algorithm: String?

    public init(flowId: String? = nil, toSign: [UInt8] = [], keyId: String? = nil, algorithm: String? = nil) {
        self.flowId = flowId
        self.toSign = toSign
        self.keyId = keyId
        self.algorithm = algorithm
    }

    /// [toSign] as bytes.
    public var toSignBytes: Data { Data(toSign) }

    enum CodingKeys: String, CodingKey {
        case flowId = "flow_id"
        case toSign = "to_sign"
        case keyId = "key_id"
        case algorithm
    }
}

/// The `signing_key` ask (engine-ports `SigningKeyParams`): the public JWK of a
/// named wallet key, so the engine can build a proof header that names it. An
/// empty answer is a legal "no such key" (the engine keeps the header bare).
public struct EngineSigningKeyParams: Codable, Sendable {
    public var flowId: String?
    public var keyId: String?

    public init(flowId: String? = nil, keyId: String? = nil) {
        self.flowId = flowId
        self.keyId = keyId
    }

    enum CodingKeys: String, CodingKey {
        case flowId = "flow_id"
        case keyId = "key_id"
    }
}

/// The answer to an [EngineSigningKeyParams]: the public JWK (as its JSON
/// object), or nil for "no such key".
public struct EngineSigningKeyResult: Sendable {
    public var jwk: [String: AnyCodable]?

    public init(jwk: [String: AnyCodable]? = nil) {
        self.jwk = jwk
    }
}

/// The `consent` ask (engine-ports `ConsentParams`): the engine asks the wallet's
/// USER whether this presentation may proceed. `consented: false` is the decline
/// path (the verifier is told `access_denied`), never a flow error.
public struct EngineConsentParams: Codable, Sendable {
    public var flowId: String?
    /// The scope the verifier asked for.
    public var purpose: String?
    /// The claims the query would disclose.
    public var requestedClaims: [String] = []
    /// The raw base64url transaction_data entries the presentation would bind.
    public var transactionData: [String] = []

    public init(flowId: String? = nil, purpose: String? = nil, requestedClaims: [String] = [], transactionData: [String] = []) {
        self.flowId = flowId
        self.purpose = purpose
        self.requestedClaims = requestedClaims
        self.transactionData = transactionData
    }

    enum CodingKeys: String, CodingKey {
        case flowId = "flow_id"
        case purpose
        case requestedClaims = "requested_claims"
        case transactionData = "transaction_data"
    }
}

/// The `authorization` ask (ports' `open_authorization`): the engine built an
/// OAuth authorization URL; the wallet hands the user to it. The ask's result is
/// ignored — the authorization's own answer arrives later as an `authorize`
/// action on the parent flow, after the redirect.
public struct EngineAuthorizationParams: Codable, Sendable {
    public var flowId: String?
    public var url: String?

    public init(flowId: String? = nil, url: String? = nil) {
        self.flowId = flowId
        self.url = url
    }
}

/// One credential the wallet selected to present (engine-ports `VpSelection`).
public struct EngineVpSelection: Codable, Sendable {
    public var credentialQueryId: String?
    public var credentialId: String
    public var disclosedClaims: [String]?

    public init(credentialQueryId: String?, credentialId: String, disclosedClaims: [String]? = nil) {
        self.credentialQueryId = credentialQueryId
        self.credentialId = credentialId
        self.disclosedClaims = disclosedClaims
    }

    enum CodingKeys: String, CodingKey {
        case credentialQueryId = "credential_query_id"
        case credentialId = "credential_id"
        case disclosedClaims = "disclosed_claims"
    }
}

/// The `presentation` ask (engine-ports `VpParams`): build and sign the VP token
/// for the selections the wallet itself reported in its `match` answer.
public struct EngineVpParams: Codable, Sendable {
    public var flowId: String?
    public var audience: String?
    public var nonce: String?
    public var selections: [EngineVpSelection] = []
    public var responseUri: String?
    public var verifierJwkThumbprint: String?
    public var verifierSessionId: String?
    public var transactionData: [String] = []
    public var selectionHandle: String?

    public init(
        flowId: String? = nil, audience: String? = nil, nonce: String? = nil,
        selections: [EngineVpSelection] = [], responseUri: String? = nil,
        verifierJwkThumbprint: String? = nil, verifierSessionId: String? = nil,
        transactionData: [String] = [], selectionHandle: String? = nil
    ) {
        self.flowId = flowId
        self.audience = audience
        self.nonce = nonce
        self.selections = selections
        self.responseUri = responseUri
        self.verifierJwkThumbprint = verifierJwkThumbprint
        self.verifierSessionId = verifierSessionId
        self.transactionData = transactionData
        self.selectionHandle = selectionHandle
    }

    enum CodingKeys: String, CodingKey {
        case flowId = "flow_id"
        case audience, nonce, selections
        case responseUri = "response_uri"
        case verifierJwkThumbprint = "verifier_jwk_thumbprint"
        case verifierSessionId = "verifier_session_id"
        case transactionData = "transaction_data"
        case selectionHandle = "selection_handle"
    }
}

/// The answer to an [EngineVpParams]: the signed `vp_token`, or a structured
/// refusal naming its code — exactly one of the two. Never a flow error: the
/// engine reads any `wmp.flow.error` on an ask as a generic refusal, and the
/// verifier must learn WHICH it was.
public struct EngineVpResult: Sendable {
    public var vpToken: String?
    /// `SIGN_REFUSED` (the user declined at the sign stage → `access_denied`) or
    /// `UNSUPPORTED_TRANSACTION_DATA` (→ `invalid_transaction_data`).
    public var refusalCode: String?

    public init(vpToken: String? = nil, refusalCode: String? = nil) {
        precondition((vpToken == nil) != (refusalCode == nil),
                     "A presentation answer carries exactly one of vp_token or a refusal")
        self.vpToken = vpToken
        self.refusalCode = refusalCode
    }

    /// The user declined at the sign stage: the verifier is answered `access_denied`.
    public static let signRefused = "SIGN_REFUSED"
    /// The transaction_data entries are not supported: the verifier is answered `invalid_transaction_data`.
    public static let unsupportedTransactionData = "UNSUPPORTED_TRANSACTION_DATA"
}

/// The `dpop_proof` ask (engine-ports `DpopProofParams`): a DPoP proof for a
/// request the engine is about to send, signed by the CLIENT-held key. An empty
/// answer is a legal "unavailable" (the engine falls back to its own ephemeral
/// key).
public struct EngineDpopProofParams: Codable, Sendable {
    public var flowId: String?
    public var keyId: String?
    public var htm: String?
    public var htu: String?
    public var accessToken: String?
    public var nonce: String?

    public init(
        flowId: String? = nil, keyId: String? = nil, htm: String? = nil,
        htu: String? = nil, accessToken: String? = nil, nonce: String? = nil
    ) {
        self.flowId = flowId
        self.keyId = keyId
        self.htm = htm
        self.htu = htu
        self.accessToken = accessToken
        self.nonce = nonce
    }

    enum CodingKeys: String, CodingKey {
        case flowId = "flow_id"
        case keyId = "key_id"
        case htm, htu
        case accessToken = "access_token"
        case nonce
    }
}

/// The answer to an [EngineDpopProofParams]: the `dpop+jwt` proof, or nil for
/// "unavailable" (the engine falls back to its own key).
public struct EngineDpopProofResult: Sendable {
    public var proof: String?

    public init(proof: String? = nil) {
        self.proof = proof
    }
}

/// The `attestation` ask (engine-ports `AttestationParams`): the OAuth client
/// attestation (a WIA and its PoP) for the authorization server [audience]. An
/// empty answer is a legal "no attestation" (the flow proceeds without one).
public struct EngineAttestationParams: Codable, Sendable {
    public var flowId: String?
    public var audience: String?
    public var clientId: String?
    public var challenge: String?

    public init(flowId: String? = nil, audience: String? = nil, clientId: String? = nil, challenge: String? = nil) {
        self.flowId = flowId
        self.audience = audience
        self.clientId = clientId
        self.challenge = challenge
    }

    enum CodingKeys: String, CodingKey {
        case flowId = "flow_id"
        case audience
        case clientId = "client_id"
        case challenge
    }
}

/// The answer to an [EngineAttestationParams]: the WIA and PoP JWTs; nils =
/// "no attestation".
public struct EngineAttestationResult: Sendable {
    public var wia: String?
    public var pop: String?

    public init(wia: String? = nil, pop: String? = nil) {
        self.wia = wia
        self.pop = pop
    }
}

/// One credential a multi-configuration offer offers (engine-ports'
/// `AvailableCredential`): the shape a credential-selection ask carries.
public struct EngineAvailableCredential: Codable, Sendable {
    public var id: String
    public var display: String?
    public var format: String
    public var vct: String

    public init(id: String, display: String? = nil, format: String = "", vct: String = "") {
        self.id = id
        self.display = display
        self.format = format
        self.vct = vct
    }
}
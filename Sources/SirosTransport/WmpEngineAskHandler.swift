// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// The SDK-level port for the LOCAL engine's asks - the one seam the wallet's
/// handlers plug into for the in-process engine (docs/engine-switching.md: "the
/// SDK's `Host` is the native UI").
///
/// The ask VOCABULARY is the engine's own (engine-ports' `Host`), the same one
/// the REMOTE engine bridges onto the wire as typed child flows - so a wallet
/// implements its asks ONCE:
///
/// - remote (httpSSE): the asks arrive as `wmp.flow.start` children and are
///   answered through the ``OpenID4xProfile`` callbacks;
/// - local (local): the asks arrive through this port - the app hands the
///   engine a `Host` built from it (``UniFfiEngineAskHost``) when it constructs
///   ``WmpUniFFITransport``.
///
/// The carrier differs; the handlers behind it are the same wallet code.
///
/// A nil/absent answer is the same "unavailable" the engine defines per ask (no
/// key, no DPoP proof, no attestation); `requestCredentialSelection`'s nil is
/// the engine-ports default REFUSAL. A thrown error is a generic refusal (the
/// flow fails closed) - exactly what a `wmp.flow.error` on a remote ask means.
public protocol WmpEngineAskHandler: AnyObject, Sendable {
    /// The bare `sign` ask: sign the raw bytes with the named key (nil = the wallet's default proof key).
    func requestSign(flowId: String, toSign: Data, keyId: String?, algorithm: String) async throws -> Data

    /// The `signing_key` ask: the named key's public JWK, or nil for "no such key".
    func requestSigningKey(flowId: String, keyId: String?) async throws -> EngineSigningKeyResult

    /// The `match` ask: the wallet's DCQL match. The payload is the profile-shaped
    /// object (the `dcql_query` member among others) so one matcher serves both carriers.
    func requestMatch(flowId: String, params: [String: AnyCodable]?) async throws -> MatchResult

    /// The `consent` ask: the user's YES/NO. `false` is the decline path, never an error.
    func requestConsent(flowId: String, params: EngineConsentParams) async throws -> Bool

    /// The `tx_code` ask: the transaction code the user entered.
    func requestTxCode(flowId: String) async throws -> String

    /// The `authorization` ask: hand the user to the URL (open the browser).
    func openAuthorization(flowId: String, url: String) async throws

    /// The `presentation` ask: build and sign the VP token, or answer the structured refusal.
    func requestVp(flowId: String, params: EngineVpParams) async throws -> EngineVpResult

    /// The `dpop_proof` ask: the client-held DPoP proof, or nil for "unavailable" (the engine falls back).
    func requestDpopProof(flowId: String, params: EngineDpopProofParams) async throws -> EngineDpopProofResult

    /// The `attestation` ask: the WIA + PoP pair, or nils for "no attestation".
    func requestAttestation(flowId: String, params: EngineAttestationParams) async throws -> EngineAttestationResult

    /// The credential-selection ask: the configuration id the user chose, or nil to
    /// refuse (the engine-ports default: the flow fails closed rather than guessing).
    func requestCredentialSelection(flowId: String, available: [EngineAvailableCredential]) async throws -> String?

    /// The engine's progress relay (the local carrier has no SSE stream for the wallet's
    /// own UI - the Host port is the only channel). Non-throwing: the engine calls it
    /// synchronously and expects nothing back.
    func onProgress(flowId: String, step: String, detail: String?)
}

/// `EngineAdapterSdk.Host` over a ``WmpEngineAskHandler``: the class the app hands
/// `WmpUniFFITransport` in local mode, so the wallet's ask handlers answer the in-process
/// engine exactly as they answer the remote one.
///
/// Gate: `#if canImport(EngineAdapterSdk)` - the XCFramework links where the
/// local mode activates; the package builds everywhere else.
#if canImport(EngineAdapterSdk)
import EngineAdapterSdk

public final class UniFfiEngineAskHost: EngineAdapterSdk.Host, @unchecked Sendable {
    private let handler: WmpEngineAskHandler

    public init(handler: WmpEngineAskHandler) {
        self.handler = handler
    }

    public func requestSign(params: EngineAdapterSdk.SignParams) async throws -> EngineAdapterSdk.SignResult {
        EngineAdapterSdk.SignResult(
            signature: try await handler.requestSign(
                flowId: params.flowId, toSign: params.toSign, keyId: params.keyId, algorithm: params.algorithm
            )
        )
    }

    public func requestMatch(params: EngineAdapterSdk.MatchParams) async throws -> EngineAdapterSdk.MatchResult {
        // The profile-shaped payload: the wallet's one matcher reads `dcql_query`
        // (and the verifier members, informational) whatever the carrier.
        var payload: [String: AnyCodable] = [
            "scope": .string(params.scope),
            "transaction_data": .array(params.transactionData.map { .string($0) }),
            "verifier": .object_([
                "name": .string(params.verifier.name),
                "client_id": .string(params.verifier.clientId),
                "trusted": .bool(params.verifier.trusted),
            ]),
        ]
        if let framework = params.verifier.framework, !framework.isEmpty {
            payload["verifier"]?.objectValue?["framework"] = .string(framework)
        }
        if let reason = params.verifier.reason, !reason.isEmpty {
            payload["verifier"]?.objectValue?["reason"] = .string(reason)
        }
        if let raw = params.dcqlQuery {
            // A query the wallet cannot read is one it cannot match: an explicit null
            // (the "offer every credential" branch), never a crash on the engine's
            // callback thread.
            payload["dcql_query"] = (try? JSONSerialization.jsonObject(with: Data(raw.utf8)))
                .flatMap { AnyCodable($0) } ?? AnyCodable.null_
        }
        let result = try await handler.requestMatch(flowId: params.flowId, params: payload)
        return EngineAdapterSdk.MatchResult(
            selections: result.matches.map { match in
                EngineAdapterSdk.VpSelection(
                    credentialQueryId: match.credentialQueryId ?? "",
                    credentialId: match.credentialId,
                    disclosedClaims: match.availableClaims ?? []
                )
            },
            handle: nil
        )
    }

    public func requestVp(params: EngineAdapterSdk.VpParams) async throws -> EngineAdapterSdk.VpResult {
        let result = try await handler.requestVp(
            params.flowId,
            EngineVpParams(
                flowId: params.flowId,
                audience: params.audience,
                nonce: params.nonce,
                selections: params.selections.map {
                    EngineVpSelection(
                        credentialQueryId: $0.credentialQueryId,
                        credentialId: $0.credentialId,
                        disclosedClaims: $0.disclosedClaims
                    )
                },
                responseUri: params.responseUri,
                verifierJwkThumbprint: params.verifierJwkThumbprint,
                verifierSessionId: params.verifierSessionId,
                transactionData: params.transactionData,
                selectionHandle: params.selectionHandle
            )
        )
        return EngineAdapterSdk.VpResult(
            vpToken: result.vpToken ?? "",
            refusal: result.refusalCode.map { EngineAdapterSdk.SignRefusal(code: $0) }
        )
    }

    public func requestDpopProof(params: EngineAdapterSdk.DpopProofParams) async throws -> EngineAdapterSdk.DpopProofResult {
        EngineAdapterSdk.DpopProofResult(
            proof: try await handler.requestDpopProof(
                params.flowId,
                EngineDpopProofParams(
                    flowId: params.flowId, keyId: params.keyId, htm: params.htm,
                    htu: params.htu, accessToken: params.accessToken, nonce: params.nonce
                )
            ).proof ?? ""
        )
    }

    public func requestConsent(params: EngineAdapterSdk.ConsentParams) async throws -> EngineAdapterSdk.ConsentResult {
        EngineAdapterSdk.ConsentResult(
            consented: try await handler.requestConsent(
                params.flowId,
                EngineConsentParams(
                    flowId: params.flowId, purpose: params.purpose,
                    requestedClaims: params.requestedClaims, transactionData: params.transactionData
                )
            )
        )
    }

    public func requestTxCode(flowId: String) async throws -> String {
        try await handler.requestTxCode(flowId: flowId)
    }

    public func openAuthorization(flowId: String, url: String) async throws {
        try await handler.openAuthorization(flowId: flowId, url: url)
    }

    public func requestSigningKey(params: EngineAdapterSdk.SigningKeyParams) async throws -> EngineAdapterSdk.SigningKeyResult {
        let result = try await handler.requestSigningKey(flowId: params.flowId, keyId: params.keyId)
        // The JWK travels as a JSON string over UniFFI; "no key" is the empty string.
        if let jwk = result.jwk,
           let codable = AnyCodable.object_(jwk).any,
           JSONSerialization.isValidJSONObject(codable),
           let data = try? JSONSerialization.data(withJSONObject: codable),
           let json = String(data: data, encoding: .utf8) {
            return EngineAdapterSdk.SigningKeyResult(jwk: json)
        }
        return EngineAdapterSdk.SigningKeyResult(jwk: "")
    }

    public func requestAttestation(params: EngineAdapterSdk.AttestationParams) async throws -> EngineAdapterSdk.AttestationResult {
        let result = try await handler.requestAttestation(
            params.flowId,
            EngineAttestationParams(
                flowId: params.flowId, audience: params.audience,
                clientId: params.clientId, challenge: params.challenge
            )
        )
        return EngineAdapterSdk.AttestationResult(wia: result.wia ?? "", pop: result.pop ?? "")
    }

    public func requestCredentialSelection(params: EngineAdapterSdk.CredentialSelectionParams) async throws -> EngineAdapterSdk.CredentialSelectionResult {
        let chosen = try await handler.requestCredentialSelection(
            params.flowId,
            params.available.map {
                EngineAvailableCredential(id: $0.id, display: $0.display, format: $0.format, vct: $0.vct)
            }
        )
        guard let chosen else {
            throw EngineAdapterSdk.SdkException.Cannot("credential selection is not supported by this wallet")
        }
        return EngineAdapterSdk.CredentialSelectionResult(credentialConfigurationId: chosen)
    }

    public func progress(flowId: String, step: String, detail: String?) {
        handler.onProgress(flowId: flowId, step: step, detail: detail)
    }
}
#endif
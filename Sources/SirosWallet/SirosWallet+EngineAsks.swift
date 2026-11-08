// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

// The engine's asks, by surface: siros-wallet-core's typed asks over the
// remote transports (httpSSE - the child flows the profile answers) and
// the same asks over the LOCAL engine's Host port (the UniFFI callbacks).
// Split out of SirosWallet+Engine.swift for swiftlint's file length: the
// connect/mint plumbing and the flow handling stay there; the ask
// handlers - one per ask type, both surfaces - live here.

import Foundation
import Crypto
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosCredentials
import SirosTransport
import SirosAuth
import SirosKeystore
import SirosFlow
@preconcurrency import SwiftCBOR

// The engine's asks, by surface: siros-wallet-core's typed asks over the
// remote transports (httpSSE - the child flows the profile answers) and
// the same asks over the LOCAL engine's Host port (the UniFFI callbacks).
// Split out of SirosWallet+Engine.swift for swiftlint's file length: the
// connect/mint plumbing and the flow handling stay there; the ask
// handlers - one per ask type, both surfaces - live here.

extension SirosWallet {
    // MARK: - siros-wallet-core's typed asks and progress (httpSSE/local)

    /// A flow progress on the WMP path: carries the `authorization_required` step (the
    /// OAuth browser hand-over) — the context is saved BEFORE the listener is told,
    /// the legacy path's identical sequence. The tx_code variant rides a child flow
    /// in that engine's dialect (handled below), never this step.
    func handleWmpProgress(flowId: String, step: String, payload: AnyCodable?) async {
        guard step == "authorization_required" else {
            #if canImport(os)
            os.Logger(subsystem: "org.siros.sdk", category: "SirosWallet").debug("WMP progress flow=\(flowId) step=\(step)")
            #endif
            return
        }
        let members = payload?.objectValue ?? [:]
        guard let authUrl = members["authorization_url"]?.stringValue, !authUrl.isEmpty else { return }
        let redirectUri = members["expected_redirect_uri"]?.stringValue
        let state = members["state"]?.stringValue ?? ""
        let rewritten = config.urlRewriter?(authUrl) ?? authUrl
        if let redirectUri {
            pendingAuthorizations[flowId] = PendingAuthorization(
                offer: nil,
                credentialOfferUri: nil,
                redirectUri: redirectUri,
                codeVerifier: members["code_verifier"]?.stringValue,
                state: state,
                startEpoch: nil
            )
        }
        await eventListener?.onAuthorizationRequired(
            flowId: flowId, authorizationUrl: rewritten, redirectUri: redirectUri ?? "", state: state
        )
    }

    /// The bare `sign` ask: one raw signature over the engine-built proof input, with
    /// the named key - or the wallet's default proof key when unnamed, which MUST be
    /// the key whose JWK `handleWmpSigningKey` published (the engine puts that JWK in
    /// the proof header).
    func handleWmpProofSign(parentId: String, params: SirosTransport.EngineSignParams) async throws -> Data {
        var resolved = params.keyId
        if resolved == nil, let named = try? await keystore.publicKeyJwk(keyId: nil) {
            resolved = named.keyId
        }
        guard let keyId = resolved else {
            throw SirosError.wallet(message: "This keystore cannot name its default proof key for an unnamed sign ask")
        }
        guard let signature = try await keystore.signJwsSignature(
            keyId: keyId, signingInput: params.toSignBytes, algorithm: params.algorithm ?? "ES256"
        ) else {
            throw SirosError.wallet(message: "This keystore cannot sign an engine proof's signing input")
        }
        return signature
    }

    /// The `signing_key` ask: the named key's public JWK, or the default proof key's.
    func handleWmpSigningKey(parentId: String, keyId: String?) async throws -> SirosTransport.EngineSigningKeyResult {
        guard let key = try await keystore.publicKeyJwk(keyId: keyId) else {
            return SirosTransport.EngineSigningKeyResult(jwk: nil)
        }
        return SirosTransport.EngineSigningKeyResult(
            jwk: SirosTransport.AnyCodable.object_(key.jwk.mapValues { SirosTransport.AnyCodable.string($0) }).objectValue
        )
    }

    /// The `consent` ask: the user's YES/NO. The listener's default declines (fail closed).
    func handleWmpConsent(parentId: String, params: SirosTransport.EngineConsentParams) async -> Bool {
        await eventListener?.onConsentRequested(flowId: parentId, purpose: params.purpose, requestedClaims: params.requestedClaims) ?? false
    }

    /// The `tx_code` ask: the transaction code from the user. The listener's nil (its
    /// default) cancels: a refused ask rather than an invented code.
    func handleWmpTxCode(parentId: String) async throws -> String {
        guard let code = eventListener?.onTxCodeRequired(flowId: parentId, description: nil) else {
            throw SirosError.wallet(message: "No tx_code provided for flow \(parentId)")
        }
        return code
    }

    /// The `authorization` ask: the context was saved and the listener told by the
    /// `authorization_required` progress that precedes it, so this only completes the
    /// ask. The fallback (a progress that never arrived) still hands the URL over.
    func handleWmpAuthorizationAsk(parentId: String, url: String) async throws {
        guard pendingAuthorizations[parentId] == nil else { return }
        let rewritten = config.urlRewriter?(url) ?? url
        let comps = URLComponents(string: rewritten)
        let state = comps?.queryItems?.first(where: { $0.name == "state" })?.value ?? ""
        await eventListener?.onAuthorizationRequired(
            flowId: parentId, authorizationUrl: rewritten, redirectUri: "", state: state
        )
    }

    /// The `presentation` ask: build and sign the VP token for the wallet's own
    /// selections — through the SAME `handleWmpSignRequest` path the go-wmp dialect
    /// drives (a synthesized `sign_presentation`), so the two dialects share one
    /// implementation. A `SignRefusedException`-shaped decline propagates as a
    /// structured refusal the verifier learns, never a generic flow error.
    func handleWmpVpRequest(parentId: String, params: SirosTransport.EngineVpParams) async throws -> SirosTransport.EngineVpResult {
        var members: [String: AnyCodable] = [
            "action": .string("sign_presentation"),
            "nonce": .string(params.nonce ?? ""),
            "audience": .string(params.audience ?? ""),
            "parent_flow_id": .string(parentId),
        ]
        members["credentials_to_include"] = .array(params.selections.map { selection in
            var dict: [String: AnyCodable] = [
                "credential_id": .string(selection.credentialId),
            ]
            if let q = selection.credentialQueryId { dict["credential_query_id"] = .string(q) }
            if let claims = selection.disclosedClaims {
                dict["disclosed_claims"] = .array(claims.map { AnyCodable.string($0) })
            }
            return AnyCodable.object_(dict)
        })
        if let thumbprint = params.verifierJwkThumbprint { members["verifier_jwk_thumbprint"] = .string(thumbprint) }
        if let sessionId = params.verifierSessionId { members["verifier_session_id"] = .string(sessionId) }
        if !params.transactionData.isEmpty {
            // The raw base64url entry is the only trustworthy member - the TS12 pipeline
            // decodes it itself.
            members["transaction_data"] = .array(params.transactionData.map { raw in
                AnyCodable.object_(["type": AnyCodable.string(""), "raw": AnyCodable.string(raw)])
            })
        }
        let signParams: SignSubFlowParams
        do {
            signParams = try JSONDecoder().decode(SignSubFlowParams.self, from: try JSONEncoder().encode(AnyCodable.object_(members)))
        } catch {
            throw SirosError.wallet(message: "The presentation ask could not be decoded")
        }
        let signed = try await handleWmpSignRequest(flowId: parentId, params: signParams)
        guard let vpToken = signed.vpToken else {
            throw SirosError.wallet(message: "The presentation ask produced no vp_token")
        }
        return SirosTransport.EngineVpResult(vpToken: vpToken)
    }

    /// The `dpop_proof` ask: a proof with the CLIENT-held key the flow named (a null
    /// key asks for "unavailable" - the engine falls back to its own key). The ask's
    /// `accessToken` is the raw token; RFC 9449's `ath` is its SHA-256, hashed here.
    func handleWmpDpopProof(parentId: String, params: SirosTransport.EngineDpopProofParams) async throws -> SirosTransport.EngineDpopProofResult {
        guard let keyId = params.keyId,
              let htm = params.htm, !htm.isEmpty,
              let htu = params.htu, !htu.isEmpty else {
            return SirosTransport.EngineDpopProofResult(proof: nil)
        }
        let ath = params.accessToken.flatMap { token -> String? in
            var hasher = SHA256()
            hasher.update(data: Data(token.utf8))
            let digest = hasher.finalize()
            var b64 = Data(digest).base64EncodedString()
            b64 = b64.replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
            while b64.hasSuffix("=") { b64.removeLast() }
            return b64
        }
        do {
            let proof = try await keystore.generateDPoPProof(
                keyId: keyId, htm: htm, htu: htu,
                nonce: params.nonce.flatMap { $0.isEmpty ? nil : $0 },
                accessTokenHash: ath
            )
            return SirosTransport.EngineDpopProofResult(proof: proof)
        } catch {
            #if canImport(os)
            os.Logger(subsystem: "org.siros.sdk", category: "SirosWallet")
                .warning("The client-held DPoP proof for flow \(parentId) failed; answering unavailable")
            #endif
            return SirosTransport.EngineDpopProofResult(proof: nil)
        }
    }

    /// The `attestation` ask: the OAuth client attestation (WIA + PoP) — the same
    /// `buildClientAuth` the legacy `request_attestation` drives.
    func handleWmpAttestation(parentId: String, params: SirosTransport.EngineAttestationParams) async throws -> SirosTransport.EngineAttestationResult {
        let material = await buildClientAuth(
            flowId: parentId, keyIdHint: nil, audience: params.audience, issuer: params.clientId,
            htm: nil, htu: nil, dpopNonce: nil, ath: nil
        )
        return SirosTransport.EngineAttestationResult(wia: material.wia, pop: material.pop)
    }

    // MARK: - The LOCAL engine's asks (the Host port carrier)

    /// The wallet's answers to the LOCAL engine's asks - the same handlers the
    /// remote engine reaches through the profile's typed-ask callbacks, carried
    /// over the SDK's ask port (engine-switching.md: "the SDK's Host is the native
    /// UI"). Built per `connectViaWmp` with THIS connection's own ask generation: an
    /// ask that arrives from an engine the wallet has since replaced is refused before
    /// it allocates anything (the same liveness rule every remote WMP callback follows).
    final class WalletEngineAskHandler: WmpEngineAskHandler, @unchecked Sendable {
        private weak var wallet: SirosWallet?
        /// THIS connection's own ask generation, from connectViaWmp - never a
        /// fresh `wmpAskGeneration` read afterward.
        private let lifetime: Int

        init(wallet: SirosWallet, lifetime: Int) {
            self.wallet = wallet
            self.lifetime = lifetime
        }

        private func requireLive() throws {
            guard let wallet, !wallet.isDestroyed else {
                throw SirosError.wallet(message: "This wallet session has ended")
            }
            wallet.lock.lock(); let current = wallet.wmpAskGeneration; wallet.lock.unlock()
            guard current == lifetime else {
                throw SirosError.wallet(message: "This wallet session has ended")
            }
        }

        public func requestSign(flowId: String, toSign: Data, keyId: String?, algorithm: String) async throws -> Data {
            try requireLive()
            return try await wallet!.handleWmpProofSign(
                parentId: flowId,
                params: SirosTransport.EngineSignParams(
                    flowId: flowId,
                    toSign: [UInt8](toSign),
                    keyId: keyId,
                    algorithm: algorithm
                )
            )
        }

        public func requestSigningKey(flowId: String, keyId: String?) async throws -> EngineSigningKeyResult {
            try requireLive()
            return try await wallet!.handleWmpSigningKey(parentId: flowId, keyId: keyId)
        }

        public func requestMatch(flowId: String, params: [String: AnyCodable]?) async throws -> MatchResult {
            try requireLive()
            return await wallet!.handleWmpMatchRequest(flowId: flowId, payload: params.map { AnyCodable.object_($0) })
        }

        public func requestConsent(flowId: String, params: EngineConsentParams) async throws -> Bool {
            try requireLive()
            return await wallet!.handleWmpConsent(parentId: flowId, params: params)
        }

        public func requestTxCode(flowId: String) async throws -> String {
            try requireLive()
            return try await wallet!.handleWmpTxCode(parentId: flowId)
        }

        public func openAuthorization(flowId: String, url: String) async throws {
            try requireLive()
            try await wallet!.handleWmpAuthorizationAsk(parentId: flowId, url: url)
        }

        public func requestVp(flowId: String, params: EngineVpParams) async throws -> EngineVpResult {
            try requireLive()
            return try await wallet!.handleWmpVpRequest(parentId: flowId, params: params)
        }

        public func requestDpopProof(flowId: String, params: EngineDpopProofParams) async throws -> EngineDpopProofResult {
            try requireLive()
            return try await wallet!.handleWmpDpopProof(parentId: flowId, params: params)
        }

        public func requestAttestation(flowId: String, params: EngineAttestationParams) async throws -> EngineAttestationResult {
            try requireLive()
            return try await wallet!.handleWmpAttestation(parentId: flowId, params: params)
        }

        public func requestCredentialSelection(flowId: String, available: [EngineAvailableCredential]) async throws -> String? {
            // The engine-ports default refusal: a flow that needs a multi-configuration
            // selection fails closed rather than guessing. Wiring the wallet's selection
            // UI is the named follow-up (a single-configuration offer never asks).
            nil
        }

        public func onProgress(flowId: String, step: String, detail: String?) {
            guard let wallet, !wallet.isDestroyed else { return }
            wallet.lock.lock(); let current = wallet.wmpAskGeneration; wallet.lock.unlock()
            guard current == lifetime else { return }
            // The local carrier has no SSE stream for the wallet's own UI: the Host's
            // progress relay feeds the same progress handling.
            Task { [wallet] in
                await wallet.handleWmpProgress(
                    flowId: flowId,
                    step: step,
                    payload: detail.map { msg -> AnyCodable in AnyCodable.object_(["message": .string(msg)]) }
                )
            }
        }
    }

    // MARK: - Base64 helpers

    /// Convert AnyCodable dict to [String: Any] for internal use.
    func anyCodableDictToAny(_ dict: [String: AnyCodable]?) -> [String: Any] {
        guard let dict else { return [:] }
        var result: [String: Any] = [:]
        for (k, v) in dict { result[k] = anyCodableToAny(v) }
        return result
    }

    // Internal (not private): `SirosWallet+Engine.swift`'s trust-evaluation
    // path reaches it through `anyCodableDictToAny` from its own file - the
    // pair lived together before the asks split.
    func anyCodableToAny(_ value: AnyCodable) -> Any {
        switch value {
        case .string(let s): return s
        case .int(let i): return i
        case .double(let d): return d
        case .bool(let b): return b
        case .object_(let obj): return anyCodableDictToAny(obj)
        case .array(let arr): return arr.map { anyCodableToAny($0) }
        case .null_: return NSNull()
        }
    }

    static func randomBytes(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBuffer(&bytes, count)
        return Data(bytes)
    }

    static func b64Encode(_ data: Data) -> String {
        data.base64EncodedString()
    }

    static func b64Decode(_ string: String) -> Data? {
        Data(base64Encoded: string)
    }

    static func b64UrlEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func b64UrlDecode(_ string: String) -> Data? {
        var s = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        return Data(base64Encoded: s)
    }

    /// Cross-platform secure random bytes.
    // swiftlint:disable:next identifier_name
    private static func SecRandomCopyBuffer(_ buffer: inout [UInt8], _ count: Int) -> Int32 {
        #if canImport(Security)
        return SecRandomCopyBytes(kSecRandomDefault, count, &buffer)
        #else
        // Linux fallback
        guard let f = fopen("/dev/urandom", "r") else { return -1 }
        let read = fread(&buffer, 1, count, f)
        fclose(f)
        return read == count ? 0 : -1
        #endif
    }
}

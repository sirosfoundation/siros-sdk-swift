// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosCredentials
import SirosTransport
import SirosAuth
import SirosKeystore
import SirosFlow
@preconcurrency import SwiftCBOR

extension SirosWallet {
    /// The final payload to hand back to the OS/browser for a W3C Digital
    /// Credentials API presentation - the platform's own credential-provider
    /// bridge (Android's `PendingIntentHandler`, or the equivalent wherever
    /// iOS eventually wires up native DC API OS integration - a separate,
    /// larger, already-tracked gap, not addressed here) wraps `responseJson`
    /// as the `DigitalCredential`'s response data.
    ///
    /// For `response_mode=dc_api` (unencrypted): `{"vp_token": {...}}`.
    /// For `response_mode=dc_api.jwt`: `{"response": "<jwe-compact>"}` per
    /// OpenID4VP 1.0 Appendix A.3.2.
    public struct DCAPIPresentationResult: Sendable {
        public let responseJson: String
        public let credentialIds: [Int64]

        public init(responseJson: String, credentialIds: [Int64]) {
            self.responseJson = responseJson
            self.credentialIds = credentialIds
        }
    }

    /// Process an incoming W3C Digital Credentials API (DC API) OpenID4VP
    /// presentation request entirely client-side - mirrors the Kotlin SDK's
    /// `handleDCAPIRequest` architecture rather than the
    /// `startPresentation`/engine-relay pattern: there is no
    /// `WalletEngineSession` involvement and no DC-API-specific backend call.
    /// The only backend calls made are the SAME generic trust-evaluation
    /// (`evaluateTrustDirect`) and presentation-history persistence the
    /// redirect flow already uses.
    ///
    /// - Parameters:
    ///   - rawRequestJson: the raw request data string from the OS/browser -
    ///     either a raw OpenID4VP request JSON object (unsigned protocol
    ///     variant) or `{"request": "<JWT>"}` (signed/multisigned JAR variant).
    ///   - origin: the browser/page origin that made the
    ///     `navigator.credentials.get()` call, as verified by the platform -
    ///     NOT read from the request body, which is untrusted until the
    ///     platform attests it.
    /// - Throws: `DCAPIRequestException` if the request is malformed or (for
    ///   the signed variant) fails JWS verification; `SirosError.wallet` if
    ///   no credential in the wallet is eligible to satisfy it.
    public func handleDCAPIRequest(rawRequestJson: String, origin: String) async throws -> DCAPIPresentationResult {
        let request = try DCAPIRequestParser.parse(rawRequestJson)
        let trustResult = try await resolveDCAPITrust(request: request, origin: origin)

        let allCreds = await credentialStore.getAll()
        let (matchResults, selectedIds) = try dcapiSelectCandidates(request: request, allCreds: allCreds)

        // "origin:<value>" per OpenID4VP 1.0 Appendix A is only used for the
        // VP token audience claim at signing time - trust evaluation above
        // uses the bare origin.
        let audience = "origin:\(origin)"
        let (encryptionJwk, encryptionThumbprint) = try dcapiResolveEncryption(request: request)

        let (tokensByQueryId, queryIdOrder) = try await dcapiSignTokens(
            selectedIds: selectedIds,
            matchResults: matchResults,
            allCreds: allCreds,
            origin: origin,
            audience: audience,
            request: request,
            encryptionThumbprint: encryptionThumbprint
        )
        var vpTokenObj: [String: Any] = [:]
        for queryId in queryIdOrder {
            vpTokenObj[queryId] = tokensByQueryId[queryId] ?? []
        }

        let finalResponseJson = try dcapiBuildResponseEnvelope(
            request: request,
            vpTokenObj: vpTokenObj,
            encryptionJwk: encryptionJwk
        )

        var seenClaims = Set<String>()
        let requestedClaims = matchResults.flatMap { $0.requestedClaims.flatMap { $0 } }.filter { seenClaims.insert($0).inserted }

        await recordPresentation(PresentationRecord(
            id: randomUint32Id(),
            flowId: "dc-api-\(UUID().uuidString)",
            verifierName: trustResult.entityName,
            credentialIds: selectedIds,
            credentialNames: selectedIds.compactMap { id in allCreds.first(where: { $0.id == id })?.metadata?.name },
            requestedClaims: requestedClaims,
            timestamp: Int64(Date().timeIntervalSince1970 * 1000)
        ))

        return DCAPIPresentationResult(responseJson: finalResponseJson, credentialIds: selectedIds)
    }

    /// Evaluate (and enforce) trust for the DC API request's verifier -
    /// split out of `handleDCAPIRequest` to keep that function's complexity
    /// within `type_body_length`'s function-level limits.
    private func resolveDCAPITrust(request: DCAPIRequest, origin: String) async throws -> TrustResult {
        // request.clientId is only cryptographically bound to anything when
        // the request is signed (keyMaterial != nil, verified against the
        // JWS header's own key in DCAPIRequestParser) - for the unsigned
        // variant it's just a caller-supplied field in the untrusted request
        // body. Using it there let a malicious page set client_id to some
        // other, possibly-whitelisted verifier's identity and have trust
        // (and presentation history) evaluated against that spoofed identity
        // instead of the platform-attested origin.
        let subjectId = request.keyMaterial != nil ? (request.clientId ?? origin) : origin
        let trustResult: TrustResult
        do {
            trustResult = try await evaluateTrustDirect(
                subjectId: subjectId,
                subjectType: "credential_verifier",
                keyMaterialType: request.keyMaterial?.x5c != nil ? "x5c" : (request.keyMaterial?.jwk != nil ? "jwk" : nil),
                x5c: request.keyMaterial?.x5c,
                jwk: request.keyMaterial?.jwk,
                context: nil
            )
        } catch {
            trustResult = trustCache.get(identifier: subjectId)
                ?? TrustResult(trusted: false, reason: error.localizedDescription, identifier: subjectId)
        }

        // Unlike the QR/redirect flow, there is no engine round-trip here to
        // gate on (trust is evaluated and enforced entirely wallet-side) - a
        // request from an untrusted or trust-eval-failed verifier must be
        // rejected before any credential is matched or signed, not merely
        // have its trust result computed and ignored.
        guard trustResult.trusted else {
            throw SirosError.wallet(message: "Verifier '\(subjectId)' is not trusted: \(trustResult.reason ?? "no reason given")")
        }
        return trustResult
    }

    /// DCQL-match, dedupe, and apply the credential-consumption eligibility
    /// filter for a DC API request - split out of `handleDCAPIRequest`, see
    /// that function's doc comment for the overall flow.
    private func dcapiSelectCandidates(
        request: DCAPIRequest,
        allCreds: [StoredCredential]
    ) throws -> (matchResults: [CredentialMatcher.MatchResult], selectedIds: [Int64]) {
        let dcqlOutput: CredentialMatcher.DcqlMatchOutput
        if let dcqlQuery = request.dcqlQuery {
            dcqlOutput = CredentialMatcher.matchDcql(dcqlQuery: dcqlQuery, credentials: allCreds)
        } else {
            dcqlOutput = CredentialMatcher.DcqlMatchOutput(
                queryResults: [CredentialMatcher.MatchResult(
                    queryId: "_default", format: nil, candidates: allCreds, requestedClaims: []
                )],
                credentialSets: nil,
                satisfiableOptions: []
            )
        }
        let matchResults = dcqlOutput.queryResults
        var seenIds = Set<Int64>()
        let candidates = matchResults.flatMap { $0.candidates }.filter { cred in
            guard !seenIds.contains(cred.id) else { return false }
            seenIds.insert(cred.id)
            return true
        }

        // Unlike the QR/redirect flow, credential selection and consent
        // already happened natively - the OS's own credential picker showed
        // the matching registered entries and the user picked one before
        // this call was ever reached. Routing through eventListener's
        // interactive onCredentialSelectionRequired here would suspend
        // waiting for an in-app consent screen that this headless flow
        // never shows.
        let eligible = CredentialUtils.eligibleInstances(
            instances: candidates,
            policy: credentialConsumptionPolicy,
            presentationHistory: presentationHistory
        )
        let selectedIds = eligible.map(\.id)

        if selectedIds.isEmpty {
            throw SirosError.wallet(message: candidates.isEmpty
                ? "No credential in the wallet matches the request"
                : "No eligible copies of the requested credential remain - renew it to get more"
            )
        }
        return (matchResults, selectedIds)
    }

    /// Resolve the verifier's response-encryption key (for `dc_api.jwt`) and
    /// its JWK thumbprint - split out of `handleDCAPIRequest`.
    private func dcapiResolveEncryption(request: DCAPIRequest) throws -> (jwk: [String: Any]?, thumbprint: String?) {
        var encryptionJwk: [String: Any]?
        if request.responseMode == "dc_api.jwt" {
            guard let jwk = Self.findEncryptionJwk(request.clientMetadata) else {
                throw SirosError.wallet(message: "dc_api.jwt response_mode requires client_metadata.jwks with an encryption key")
            }
            encryptionJwk = jwk
        }
        // `DCAPIResponseEncryption` is entirely CryptoKit-gated (Apple
        // platforms only, matching this module's existing convention e.g.
        // `EncryptedContainer`) - `nil` here on an unsupported platform still
        // lets an unencrypted `dc_api` presentation proceed; `dc_api.jwt`
        // itself is rejected below with a clear error instead.
        var encryptionThumbprint: String?
        #if canImport(CryptoKit)
        encryptionThumbprint = encryptionJwk.flatMap { DCAPIResponseEncryption.jwkThumbprint($0) }
        #endif
        return (encryptionJwk, encryptionThumbprint)
    }

    /// Sign a VP token per selected credential (plain SD-JWT/mdoc, or the
    /// ZK-wrapped mdoc branch), grouped by DCQL query id - split out of
    /// `handleDCAPIRequest`, the largest single contributor to that
    /// function's original cyclomatic-complexity/length lint violations.
    private func dcapiSignTokens(
        selectedIds: [Int64],
        matchResults: [CredentialMatcher.MatchResult],
        allCreds: [StoredCredential],
        origin: String,
        audience: String,
        request: DCAPIRequest,
        encryptionThumbprint: String?
    ) async throws -> (tokensByQueryId: [String: [String]], queryIdOrder: [String]) {
        // Per OpenID4VP 1.0 (#response_parameters), vp_token's value for each
        // DCQL query id MUST be a JSON array of one or more Presentations -
        // even when `multiple` is omitted/false, the array MUST still
        // contain exactly one Presentation, never a bare string. A real bug,
        // confirmed via Multipaz's own server source
        // (multipaz-verifier-server's handleDcGetDataOpenID4VP does
        // `value.jsonArray.map{...}` for the openid4vp-v1-signed/-unsigned
        // protocol versions): putting a bare string here throws inside their
        // server and surfaces as an opaque HTTP 500.
        var tokensByQueryId: [String: [String]] = [:]
        var queryIdOrder: [String] = []
        for id in selectedIds {
            guard let cred = allCreds.first(where: { $0.id == id }) else { continue }
            let matchResult = matchResults.first(where: { result in result.candidates.contains(where: { $0.id == id }) })
            let queryId = matchResult?.queryId ?? "_default"
            let disclosedClaims = matchResult?.requestedClaims.compactMap(\.last)

            let token = try await dcapiSignSingleToken(
                cred: cred,
                matchResult: matchResult,
                disclosedClaims: disclosedClaims,
                origin: origin,
                audience: audience,
                request: request,
                encryptionThumbprint: encryptionThumbprint
            )

            if tokensByQueryId[queryId] == nil {
                tokensByQueryId[queryId] = []
                queryIdOrder.append(queryId)
            }
            tokensByQueryId[queryId]?.append(token)
        }
        return (tokensByQueryId, queryIdOrder)
    }

    /// Sign one credential's VP token for the DC API response - the
    /// mso_mdoc_zk/mso_mdoc/default three-way branch factored out of
    /// `dcapiSignTokens`'s loop body.
    private func dcapiSignSingleToken(
        cred: StoredCredential,
        matchResult: CredentialMatcher.MatchResult?,
        disclosedClaims: [String]?,
        origin: String,
        audience: String,
        request: DCAPIRequest,
        encryptionThumbprint: String?
    ) async throws -> String {
        if matchResult?.format?.caseInsensitiveCompare("mso_mdoc_zk") == .orderedSame {
            // ZK-wrapped mDoc presentation - see the shared
            // `buildZkPresentationToken` helper's doc comment.
            guard let credBytes = Self.b64UrlDecode(cred.raw) else {
                throw SirosError.wallet(message: "Credential \(cred.id) has malformed base64url raw data")
            }
            // cred.kid is commonly nil for a softkey-issued credential
            // with no explicit per-credential key binding (the plain,
            // non-ZK signing paths tolerate this via a similar
            // fallback) - keystore.sign() below needs an explicit key
            // id, so resolve the same default here rather than
            // treating a nil kid as "no key exists".
            guard let kid = cred.kid ?? keystore.listKeys().first?.keyId else {
                throw SirosError.wallet(message: "No signing key available for credential \(cred.id) - cannot generate a ZK proof for it")
            }
            let mdocDocument = try MdocCbor.parseStoredCredential([UInt8](credBytes))
            let docType = mdocDocument.docType
            // A circuit is compiled for a fixed attribute count, so the
            // verifier's zk_system_type list must be matched against how
            // many claims are actually being disclosed here.
            guard let (system, spec) = zkProofSystemRegistry.resolve(
                credentialType: CredentialTypeRef(format: .msoMdoc, typeId: docType),
                requestedSpecs: matchResult?.zkSystemTypes ?? [],
                numAttributes: disclosedClaims?.count ?? 0
            ) else {
                throw SirosError.wallet(message: "No registered ZK proof system satisfies the verifier's zk_system_type for \(docType)")
            }
            // Only bind a pseudonym when actually disclosed for this
            // query.
            let wantsPseudonym = disclosedClaims?.contains(zkPseudonymClaim) == true
            let verifierIdentity: VerifierIdentity? = wantsPseudonym
                ? VerifierIdentity(clientId: audience, ppidContext: matchResult?.ppidContext)
                : nil
            let sessionTranscript = MdocDeviceResponseBuilder.buildDCAPISessionTranscript(
                origin: origin,
                nonce: request.nonce,
                encryptionPublicJwkThumbprint: encryptionThumbprint
            )
            let result = try await system.generateProof(
                spec: spec,
                document: .mdoc([UInt8](credBytes)),
                sessionTranscript: sessionTranscript,
                requestedClaims: disclosedClaims ?? [],
                verifierIdentity: verifierIdentity,
                signer: { algorithm, data in
                    // The signer carries an algorithm so a system needing a
                    // key this keystore cannot produce fails here rather
                    // than getting a signature over the wrong curve.
                    guard algorithm == coseAlgES256 else {
                        throw SirosError.wallet(message: "This keystore signs ES256 only, proof system asked for COSE alg \(algorithm)")
                    }
                    return [UInt8](try await self.keystore.sign(keyId: kid, payload: Data(data), algorithm: "ES256"))
                },
                priorState: nil
            )
            let zkDeviceResponse = try buildZkPresentationToken(
                credBytes: [UInt8](credBytes),
                docType: docType,
                spec: spec,
                disclosedClaimNames: disclosedClaims ?? [],
                result: result
            )
            return Self.b64UrlEncode(zkDeviceResponse)
        } else if cred.format == "mso_mdoc" {
            guard let credBytes = Self.b64UrlDecode(cred.raw) else {
                throw SirosError.wallet(message: "Credential \(cred.id) has malformed base64url raw data")
            }
            let deviceResponse = try await keystore.signMdocPresentationForDCAPI(
                credentialBytes: credBytes,
                disclosedClaims: disclosedClaims,
                nonce: request.nonce,
                origin: origin,
                encryptionPublicJwkThumbprint: encryptionThumbprint,
                kid: cred.kid
            )
            return Self.b64UrlEncode(deviceResponse)
        } else {
            return try await keystore.signVpToken(
                credential: cred.raw,
                disclosedClaims: disclosedClaims,
                nonce: request.nonce,
                audience: audience,
                kid: cred.kid
            )
        }
    }

    /// Build the final `{"protocol", "data"}` envelope JSON to hand back to
    /// the OS/browser, optionally JWE-encrypting the response for
    /// `dc_api.jwt` - split out of `handleDCAPIRequest`.
    private func dcapiBuildResponseEnvelope(
        request: DCAPIRequest,
        vpTokenObj: [String: Any],
        encryptionJwk: [String: Any]?
    ) throws -> String {
        var responseBody: [String: Any] = ["vp_token": vpTokenObj]
        // The verifier's only means of correlating this response back to the
        // right authorization session - the response arrives via the DC API
        // callback, a wholly separate channel from the original request,
        // with no other correlator available. Omitting this (a real bug:
        // request.state was parsed but never echoed back) left the verifier
        // decrypting a JWE it had no way to attribute to any session.
        if let state = request.state {
            responseBody["state"] = state
        }
        guard let responseBodyData = try? JSONSerialization.data(withJSONObject: responseBody),
              let responseBodyJson = String(data: responseBodyData, encoding: .utf8) else {
            throw SirosError.wallet(message: "Failed to serialize DC API response body")
        }

        let responseData: [String: Any]
        if request.responseMode == "dc_api.jwt", let encryptionJwk {
            #if canImport(CryptoKit)
            let jwe = try DCAPIResponseEncryption.encryptResponse(responseJson: responseBodyJson, verifierJwk: encryptionJwk)
            responseData = ["response": jwe]
            #else
            throw SirosError.wallet(message: "dc_api.jwt response encryption requires CryptoKit (unsupported on this platform)")
            #endif
        } else {
            responseData = responseBody
        }

        // The platform's own reference wallet
        // (https://github.com/digitalcredentialsdev/CMWallet) wraps its
        // response in this exact {"protocol": ..., "data": {...}} envelope
        // before handing it back - the mirror image of the {"requests":
        // [{"protocol", "data"}]} envelope the request itself arrives in
        // (see `DCAPIRequestParser`). Returning the bare `data` object on its
        // own leaves the platform with no declared protocol to associate the
        // response with.
        let finalResponse: [String: Any] = ["protocol": request.protocolIdentifier, "data": responseData]
        guard let finalResponseData = try? JSONSerialization.data(withJSONObject: finalResponse),
              let finalResponseJson = String(data: finalResponseData, encoding: .utf8) else {
            throw SirosError.wallet(message: "Failed to serialize DC API response envelope")
        }
        return finalResponseJson
    }

    /// Wraps a raw ZK proof result into the full `{version, status,
    /// zkDocuments: [...]}` DeviceResponse-shaped CBOR structure multipaz's
    /// own `DeviceResponseParser` requires (see
    /// `MdocDeviceResponseBuilder.buildZkDeviceResponse`'s doc comment). Bare
    /// proof bytes alone are not a valid `vp_token` entry - a verifier that
    /// understands this format silently shows nothing for one, since its
    /// parser never finds a `documents` or `zkDocuments` key at all. Shared
    /// by both ZK call sites (`handleDCAPIRequest` and the `sign_presentation`
    /// handler) since the wrapping logic is identical regardless of transport.
    // Not `private`: `SirosWallet+Engine.swift` needs it too - same
    // cross-file-extension-access reason as `keystore` above.
    func buildZkPresentationToken(
        credBytes: [UInt8],
        docType: String,
        spec: ZkSystemSpec,
        disclosedClaimNames: [String],
        result: ZkProofResult
    ) throws -> Data {
        let document = try MdocCbor.parseStoredCredential(credBytes)
        guard let namespace = document.issuerSigned.nameSpaces.keys.first else {
            throw MdocError.malformed("mdoc credential '\(docType)' has no disclosed namespaces")
        }
        let storedItems = document.issuerSigned.nameSpaces[namespace] ?? []

        var disclosedClaims: [(String, CBOR)] = []
        for claimName in disclosedClaimNames {
            if claimName == zkPseudonymClaim {
                if let pseudonym = result.pseudonym {
                    disclosedClaims.append((claimName, .byteString(pseudonym)))
                }
            } else if let match = storedItems.first(where: { $0.item.elementIdentifier == claimName }) {
                disclosedClaims.append((claimName, match.item.elementValue))
            }
        }

        return MdocDeviceResponseBuilder.buildZkDeviceResponse(
            proofBytes: result.proofBytes,
            zkSystemId: spec.id,
            docType: docType,
            timestamp: result.timestamp,
            namespace: namespace,
            disclosedClaims: disclosedClaims,
            issuerAuth: document.issuerSigned.issuerAuth
        )
    }

    /// Direct (non-engine-relayed) trust evaluation, for flows like
    /// `handleDCAPIRequest` that have no `WalletEngineSession` involvement at
    /// all - mirrors `handleTrustEvaluation`'s request shape/AuthZEN
    /// action-name mapping exactly.
    private func evaluateTrustDirect(
        subjectId: String,
        subjectType: String?,
        keyMaterialType: String?,
        x5c: [String]?,
        jwk: [String: Any]?,
        context: [String: Any]?
    ) async throws -> TrustResult {
        lock.lock(); let client = apiClient; lock.unlock()
        guard let client else { throw SirosError.wallet(message: "Not connected") }

        var resource: [String: Any] = [
            "type": keyMaterialType ?? "x5c",
            "id": subjectId,
        ]
        if let x5c {
            resource["key"] = x5c
        } else if let jwk {
            resource["key"] = [jwk]
        }

        var evaluationRequest: [String: Any] = [
            "subject": ["type": "key", "id": subjectId],
            "resource": resource,
            "action": ["name": subjectType == "credential_verifier" ? "credential-verifier" : "credential-issuer"],
        ]
        if let context {
            evaluationRequest["context"] = context
        }

        let response = try await client.evaluateTrust(evaluationRequest)
        let decision = response["decision"] as? Bool ?? false
        let respContext = response["context"] as? [String: Any]

        // Mirrors the Kotlin SDK's `evaluateTrustDirect` exactly: unlike
        // `handleTrustEvaluation` (the engine-relayed path), this direct-call
        // variant deliberately does NOT populate `trustCache` on success -
        // only `handleDCAPIRequest`'s catch block reads it, as a fallback
        // when the live call itself fails.
        return TrustResult(
            trusted: decision,
            framework: respContext?["framework"] as? String,
            reason: (respContext?["reason"] as? String) ?? (respContext?["message"] as? String),
            entityName: respContext?["entity_name"] as? String,
            entityLogo: respContext?["logo_uri"] as? String,
            clientIdScheme: nil,
            identifier: subjectId,
            domain: respContext?["domain"] as? String
        )
    }

    /// Find the verifier's response-encryption key (`use: "enc"`) from DC API `client_metadata.jwks`.
    private static func findEncryptionJwk(_ clientMetadata: [String: Any]?) -> [String: Any]? {
        guard let jwks = clientMetadata?["jwks"] as? [String: Any],
              let keys = jwks["keys"] as? [[String: Any]] else {
            return nil
        }
        return keys.first(where: { ($0["use"] as? String) == "enc" }) ?? keys.first
    }
}

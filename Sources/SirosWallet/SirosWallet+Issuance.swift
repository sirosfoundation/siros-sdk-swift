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

extension SirosWallet {
    // MARK: - Issuance

    /// Discover all available credentials across all visible issuers.
    ///
    /// Returns a flat list of `CredentialOffer` items ready for display in a
    /// picker UI. Each item can be passed to `startIssuanceByOffer`.
    public func getAvailableCredentials() async throws -> [CredentialOffer] {
        lock.lock(); let client = apiClient; lock.unlock()
        guard let client else {
            throw SirosError.wallet(message: "Not connected")
        }

        // Step 1: Get issuers from backend
        let rawIssuers = try await client.getIssuers()
        let issuersData: Data
        if let dict = rawIssuers as? [[String: Any]] {
            issuersData = try JSONSerialization.data(withJSONObject: dict)
        } else if let obj = rawIssuers as? [String: Any],
                  let arr = obj["issuers"] as? [[String: Any]] ?? obj["data"] as? [[String: Any]] {
            issuersData = try JSONSerialization.data(withJSONObject: arr)
        } else {
            issuersData = try JSONSerialization.data(withJSONObject: rawIssuers)
        }
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        let issuers = (try? decoder.decode([IssuerEntry].self, from: issuersData))?.filter { $0.visible } ?? []

        // Step 2: For each issuer, fetch metadata and build offers
        var offers: [CredentialOffer] = []
        for issuer in issuers {
            do {
                let metaDict = try await client.getIssuerMetadata(id: Int(issuer.id))
                let metaData = try JSONSerialization.data(withJSONObject: metaDict)
                let metaDecoder = JSONDecoder()
                let metadata = try metaDecoder.decode(IssuerMetadata.self, from: metaData)

                for configId in metadata.credentialConfigurationsSupported.keys {
                    if let offer = Self.buildCredentialOffer(
                        issuerUrl: issuer.credentialIssuerIdentifier,
                        configId: configId,
                        metadata: metadata
                    ) {
                        offers.append(offer)
                    }
                }
            } catch {
                // Skip issuers that fail metadata fetch
                continue
            }
        }
        return offers
    }

    /// Build a `CredentialOffer` (display name/logo/colors) for one credential
    /// configuration from an issuer's already-fetched `IssuerMetadata`, reading
    /// the standard OID4VCI `credential_metadata.display` field (falling back
    /// to the issuer's own top-level `display`). Shared by
    /// `getAvailableCredentials` (lists every configuration a registered
    /// issuer supports) and `startIssuance` (resolves display metadata for the
    /// single configuration named in a scanned/deep-linked offer, including
    /// from issuers - e.g. interop test issuers - never registered with this
    /// wallet).
    ///
    /// Returns `nil` if `configId` isn't actually offered by this issuer.
    ///
    /// `static` (takes no wallet state) so it's unit-testable without
    /// constructing a full `SirosWallet`, which requires a keystore -
    /// unavailable in a plain Linux test run (see `KeystoreManager`'s
    /// CryptoKit-gated default).
    static func buildCredentialOffer(
        issuerUrl: String,
        configId: String,
        metadata: IssuerMetadata
    ) -> CredentialOffer? {
        guard let config = metadata.credentialConfigurationsSupported[configId] else { return nil }
        let issuerDisplay = metadata.display?.first
        let issuerName = issuerDisplay?.name
            ?? URL(string: issuerUrl)?.host
            ?? issuerUrl
        let credDisplay = config.credentialMetadata?.display?.first
        let credName = credDisplay?.name ?? configId

        return CredentialOffer(
            credentialConfigurationId: configId,
            credentialIssuerIdentifier: issuerUrl,
            credentialName: credName,
            credentialDescription: credDisplay?.description,
            issuerName: issuerName,
            backgroundColor: credDisplay?.backgroundColor ?? issuerDisplay?.backgroundColor,
            textColor: credDisplay?.textColor ?? issuerDisplay?.textColor,
            logoUri: credDisplay?.logo?.uri,
            issuerLogoUri: issuerDisplay?.logo?.uri,
            vct: config.vct,
            doctype: config.doctype
        )
    }

    /// Fetch an issuer's standard OID4VCI metadata directly by its URL (not
    /// via `apiClient`, which only knows issuers registered with this
    /// wallet's own backend) - needed to resolve display metadata for
    /// arbitrary/third-party issuers named in a scanned credential offer.
    // Not `private`: `SirosWallet+Renewal.swift`'s `renewCredential` needs
    // it too - same cross-file-extension-access reason as `keystore` above.
    func fetchIssuerMetadata(issuerUrl: String) async throws -> IssuerMetadata {
        let trimmed = issuerUrl.hasSuffix("/") ? String(issuerUrl.dropLast()) : issuerUrl
        guard let url = URL(string: trimmed + "/.well-known/openid-credential-issuer") else {
            throw SirosError.wallet(message: "Invalid issuer URL: \(issuerUrl)")
        }
        let (data, response) = try await URLSession.shared.data(from: url)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw SirosError.wallet(message: "Metadata fetch failed for \(issuerUrl)")
        }
        return try JSONDecoder().decode(IssuerMetadata.self, from: data)
    }

    /// Get (creating once, on first use) this wallet installation's persistent
    /// OAuth Client Attestation instance key ID - see
    /// `SessionStoreProtocol.instanceKeyId`.
    private func ensureInstanceKeyId() async throws -> String {
        if let existing = sessionStore.instanceKeyId {
            return existing
        }
        let keyId = try await keystore.generateKey(algorithm: "ES256")
        sessionStore.instanceKeyId = keyId
        return keyId
    }

    /// Obtain (fetching + caching, refreshing before expiry) a Wallet
    /// Instance Attestation for this wallet instance from this wallet's own
    /// backend (draft-ietf-oauth-attestation-based-client-auth-10 §3.1 /
    /// CS-04 §7.1.2): request a single-use challenge, sign a PoP JWT over it
    /// with the instance key, and exchange both for a WIA JWT.
    ///
    /// Best-effort: returns nil on any failure (network, backend not
    /// configured for WIA, etc.) rather than throwing - a missing/unavailable
    /// client attestation must never block issuance, since not every backend
    /// deployment enables this feature.
    private func ensureWalletInstanceAttestation() async -> String? {
        let now = Int(Date().timeIntervalSince1970)
        lock.lock(); let cached = cachedWia; let expiresAt = cachedWiaExpiresAt; lock.unlock()
        if let wia = cached, expiresAt - now > 60 {
            return wia
        }
        guard let client = apiClient else { return nil }
        do {
            let keyId = try await ensureInstanceKeyId()
            let challengeResponse = try await client.requestWIAChallenge()
            guard let challenge = challengeResponse["challenge"] as? String else { return nil }
            let pop = try await keystore.generateKeyProof(
                keyId: keyId,
                typ: "oauth-client-attestation-pop+jwt",
                // iss doesn't need to equal client_id for THIS PoP - it's
                // validated by our own backend (WIAService.validatePop only
                // checks iss is non-empty), unlike the per-issuer PoP built in
                // resolveClientAttestation. clientAttestationClientId() is
                // still a reasonable choice: consistent, and non-empty.
                issuer: clientAttestationClientId(),
                // Must match the backend's configured wallet_provider_uri, if
                // it enforces one (WIAService.validatePop only checks aud
                // when that's non-empty) - the base backend URL is the only
                // value discoverable client-side without a dedicated endpoint.
                audience: config.backendUrl,
                extraClaims: ["nonce": challenge]
            )
            // Best-effort, on its OWN try/catch (not the outer one): a
            // native-attestation failure must degrade to a plain
            // backend-attested WIA, not abort issuance entirely. No
            // WalletConfig field needed on iOS - unlike Play Integrity,
            // App Attest needs no host-app-supplied config beyond the Xcode
            // entitlement (a project-level setting), so this constructs the
            // provider directly whenever the platform/OS version supports it.
            #if canImport(DeviceCheck)
            var nativeAttestation: [String: Any]?
            let appAttestProvider = AppAttestProvider(
                loadPersistedKeyId: { [weak self] in self?.sessionStore.appAttestKeyId },
                savePersistedKeyId: { [weak self] in self?.sessionStore.appAttestKeyId = $0 }
            )
            if appAttestProvider.isAvailable {
                do {
                    let evidence = try await appAttestProvider.generateEvidence(challenge: challenge, keyId: keyId)
                    nativeAttestation = [
                        "type": evidence.type,
                        "token": evidence.token,
                        "key_id": evidence.keyId,
                        "challenge": evidence.challenge,
                    ]
                } catch {
                    // Best-effort - device capability/entitlement issues are
                    // common and expected (Simulator, no entitlement, key
                    // already attested this install) - but silent failures
                    // here are hard to diagnose in the field, so log them.
                    print("[SirosWallet] App Attest evidence generation failed, continuing without it: \(error)")
                    nativeAttestation = nil
                }
            }
            #else
            let nativeAttestation: [String: Any]? = nil
            #endif
            let wia = try await client.generateWIA(
                pop: pop,
                challenge: challenge,
                // draft-ietf-oauth-attestation-based-client-auth-10: "the sub
                // claim MUST specify client_id value of the OAuth Client" -
                // confirmed via a real geneva2026.mdoc.online conformance run
                // that flagged sub=<instance jkt> as a FAIL.
                clientId: clientAttestationClientId(),
                nativeAttestation: nativeAttestation
            )
            let expiresAt = (CredentialUtils.parseJwtPayload(wia)?["exp"] as? Int) ?? (now + 300)
            lock.lock(); cachedWia = wia; cachedWiaExpiresAt = expiresAt; lock.unlock()
            return wia
        } catch {
            return nil
        }
    }

    /// The wallet_instance_id to send with a Key Attestation request: the
    /// JWK Thumbprint (`cnf.jkt`) of the current session's WIA-issued
    /// instance key, but only when that WIA's `attestation_source` is a
    /// verified native platform attestation (ios_app_attest /
    /// android_play_integrity) - go-wallet-backend's KA trust gate clamps to
    /// K3 for anything else anyway, so there's no value in sending an ID
    /// that won't lift the clamp, and every other failure mode (no WIA, WIA
    /// disabled, non-native tier) must resolve to omitting the field exactly
    /// like today's pre-this-change behavior.
    ///
    /// Peeks the existing WIA cache only - deliberately does NOT call
    /// `ensureWalletInstanceAttestation()` (real Copilot-review finding:
    /// that would trigger a challenge+generateWIA network round trip, and
    /// retry it on every backend key-attestation attempt in deployments
    /// where WIA is unsupported/misconfigured, adding latency for a field
    /// that's optional in the first place). A WIA obtained earlier this
    /// session (e.g. during issuance) is still picked up; one that was
    /// never fetched simply omits the field, exactly like today's behavior.
    func currentWalletInstanceId() -> String? {
        let now = Int(Date().timeIntervalSince1970)
        let nativeAttestationSources: Set<String> = ["ios_app_attest", "android_play_integrity"]
        lock.lock(); let cached = cachedWia; let expiresAt = cachedWiaExpiresAt; lock.unlock()
        guard let wia = cached, expiresAt - now > 60,
              let payload = CredentialUtils.parseJwtPayload(wia),
              let source = payload["attestation_source"] as? String,
              nativeAttestationSources.contains(source),
              let cnf = payload["cnf"] as? [String: Any],
              let jkt = cnf["jkt"] as? String else { return nil }
        return jkt
    }

    /// The OAuth `client_id` this wallet uses in OID4VCI/OID4VP flows.
    /// Mirrors go-wallet-backend's `OID4VCIHandler.clientID` default
    /// (`h.clientID = h.redirectURI`, OID4VCI §7.1's unregistered-client
    /// convention) - known to be correct for any issuer that doesn't have its
    /// own registered client_id override server-side (the common case; a
    /// registered override isn't visible to the client, so a cached WIA/PoP
    /// built against this default would be spec-inconsistent for that rarer
    /// case - a known, accepted limitation rather than something this method
    /// can resolve without per-issuer client_id discovery).
    private func clientAttestationClientId() -> String {
        config.redirectUri
    }

    /// Resolve OAuth Client Attestation (a WIA plus a fresh per-flow PoP) for
    /// an issuance flow targeting `issuerUrl` - the pair the engine forwards
    /// as `OAuth-Client-Attestation`/`OAuth-Client-Attestation-PoP` headers to
    /// the credential issuer.
    ///
    /// The PoP's `aud` targets the issuer's own authorization server if
    /// discoverable from its metadata, falling back to the credential issuer
    /// URL itself for issuers that self-host their AS at the same origin.
    /// Its `iss` is the same client_id used for the WIA's `sub` (see
    /// `ensureWalletInstanceAttestation`) - draft-ietf-oauth-attestation-based-client-auth-10
    /// requires both to match. Its `challenge` claim, when the AS publishes a
    /// `challenge_endpoint` in its metadata, is fetched fresh from there
    /// (§ "Challenge Endpoint" - POST returns `{"attestation_challenge": ...}`);
    /// omitted otherwise, since the claim is optional per spec.
    ///
    /// Best-effort: returns nil on any failure - missing/misconfigured WIA
    /// support must never block issuance itself.
    // Not `private`: `SirosWallet+Lifecycle.swift` needs it too - same
    // cross-file-extension-access reason as `keystore` above.
    func resolveClientAttestation(issuerUrl: String) async -> (String, String)? {
        guard let wia = await ensureWalletInstanceAttestation() else { return nil }
        do {
            let asUrl: String
            if let metadata = try? await fetchIssuerMetadata(issuerUrl: issuerUrl),
               let server = metadata.authorizationServers?.first(where: { !$0.isEmpty }) {
                asUrl = server
            } else {
                asUrl = issuerUrl
            }
            let challenge = await fetchAttestationChallenge(asUrl: asUrl)
            let keyId = try await ensureInstanceKeyId()
            var extraClaims: [String: String] = [:]
            if let challenge { extraClaims["challenge"] = challenge }
            let pop = try await keystore.generateKeyProof(
                keyId: keyId,
                typ: "oauth-client-attestation-pop+jwt",
                issuer: clientAttestationClientId(),
                audience: asUrl,
                extraClaims: extraClaims
            )
            return (wia, pop)
        } catch {
            return nil
        }
    }

    /// Fetch a fresh attestation challenge from `asUrl`'s own metadata-published
    /// `challenge_endpoint` (draft-ietf-oauth-attestation-based-client-auth-10
    /// §"Challenge Endpoint"), if it publishes one. Tries the OAuth 2.0
    /// Authorization Server Metadata well-known path (RFC 8414) first, falling
    /// back to the OIDC discovery path for ASes that only publish there.
    ///
    /// Returns nil (never throws) if the AS doesn't publish a challenge
    /// endpoint, or on any fetch failure - the `challenge` claim is optional
    /// per spec, so its absence must never block attestation entirely.
    private func fetchAttestationChallenge(asUrl: String) async -> String? {
        guard let metadata = await fetchOAuthServerMetadata(asUrl: asUrl),
              let challengeEndpoint = metadata["challenge_endpoint"] as? String,
              let url = URL(string: challengeEndpoint) else {
            return nil
        }
        do {
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.httpBody = Data("{}".utf8)
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { return nil }
            let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            return json?["attestation_challenge"] as? String
        } catch {
            return nil
        }
    }

    private func fetchOAuthServerMetadata(asUrl: String) async -> [String: Any]? {
        let base = asUrl.hasSuffix("/") ? String(asUrl.dropLast()) : asUrl
        for path in ["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"] {
            guard let url = URL(string: base + path) else { continue }
            do {
                let (data, response) = try await URLSession.shared.data(from: url)
                guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { continue }
                if let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    return json
                }
            } catch {
                // Try the next well-known path.
            }
        }
        return nil
    }

    /// Start issuance with a credential offer object.
    public func startIssuanceByOffer(_ offer: CredentialOffer) async throws {
        guard let engine = engineSession else {
            throw SirosError.wallet(message: "Not connected")
        }
        try await ensureEngineConnected(engine)
        lock.lock()
        if issuanceInFlight {
            lock.unlock()
            throw SirosError.wallet(message: "Another issuance is already in progress")
        }
        issuanceInFlight = true
        activeOffer = offer
        lock.unlock()
        do {

            // Try to fetch VCTM (SD-JWT) and MDDL schema (mdoc) - format-blind,
            // like `activeVctm`'s existing fetch: whichever one doesn't match
            // this offer's actual format simply fails to decode and stays nil.
            let vctm = try? await vctmFetcher.fetch(
                issuerUrl: offer.credentialIssuerIdentifier,
                scope: offer.credentialConfigurationId,
                vct: offer.vct,
                registryUrl: resolvedRegistryUrl
            )
            let mddlSchema = await mddlSchemaFetcher.fetch(
                issuerUrl: offer.credentialIssuerIdentifier,
                scope: offer.credentialConfigurationId,
                doctype: offer.doctype,
                registryUrl: resolvedRegistryUrl
            )
            lock.lock()
            activeVctm = vctm
            activeMddlSchema = mddlSchema
            lock.unlock()

            var credOffer: [String: AnyCodable] = [
                "credential_issuer": .string(offer.credentialIssuerIdentifier),
                "credential_configuration_ids": .array([.string(offer.credentialConfigurationId)]),
            ]

            var grants: [String: AnyCodable] = [:]
            if let preAuth = offer.preAuthorizedCode {
                var preAuthGrant: [String: AnyCodable] = ["pre-authorized_code": .string(preAuth)]
                if offer.txCode != nil {
                    preAuthGrant["tx_code"] = .object_(["input_mode": .string("text")])
                }
                grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"] = .object_(preAuthGrant)
            } else {
                grants["authorization_code"] = .object_([:])
            }
            credOffer["grants"] = .object_(grants)

            let offerJson: String
            if let data = try? JSONEncoder().encode(credOffer),
               let s = String(data: data, encoding: .utf8) {
                offerJson = s
            } else {
                offerJson = "{}"
            }

            let clientAttestation = await resolveClientAttestation(issuerUrl: offer.credentialIssuerIdentifier)
            engine.startIssuance(
                offer: offerJson,
                redirectUri: config.redirectUri.isEmpty ? nil : config.redirectUri,
                clientAttestation: clientAttestation?.0,
                clientAttestationPoP: clientAttestation?.1
            )
        } catch {
            // A synchronous start failure here means the flow was never
            // registered server-side, so nothing will ever clear the guard
            // via the normal flow_complete/flow_error path - without this,
            // every future issuance attempt would be permanently blocked.
            resetIssuanceGuards()
            throw error
        }
    }

    /// Start issuance with a raw offer URI or JSON.
    public func startIssuance(offerUri: String) async throws {
        guard let engine = engineSession else {
            throw SirosError.wallet(message: "Not connected")
        }
        try await ensureEngineConnected(engine)
        lock.lock()
        if issuanceInFlight {
            lock.unlock()
            throw SirosError.wallet(message: "Another issuance is already in progress")
        }
        issuanceInFlight = true
        lock.unlock()
        do {
            if let offer = await resolveOfferForDisplay(offerUri) {
                lock.lock(); activeOffer = offer; lock.unlock()
                let vctm = try? await vctmFetcher.fetch(
                    issuerUrl: offer.credentialIssuerIdentifier,
                    scope: offer.credentialConfigurationId,
                    vct: offer.vct,
                    registryUrl: resolvedRegistryUrl
                )
                let mddlSchema = await mddlSchemaFetcher.fetch(
                    issuerUrl: offer.credentialIssuerIdentifier,
                    scope: offer.credentialConfigurationId,
                    doctype: offer.doctype,
                    registryUrl: resolvedRegistryUrl
                )
                lock.lock(); activeVctm = vctm; activeMddlSchema = mddlSchema; lock.unlock()
            }
            // Resolve OAuth Client Attestation once, independent of whether the
            // display-metadata resolution above succeeded - a client that can't
            // be shown a name/logo should still get an attestation attached.
            var attestation: String?
            var attestationPoP: String?
            if let header = await extractOfferHeader(offerUri),
               let pair = await resolveClientAttestation(issuerUrl: header.credentialIssuer) {
                attestation = pair.0
                attestationPoP = pair.1
            }
            if offerUri.hasPrefix("openid-credential-offer://") {
                // Deep-link URI with inline offer - send as "offer" so the engine
                // extracts the credential_offer query parameter instead of HTTP-fetching.
                engine.startIssuance(offer: offerUri, clientAttestation: attestation, clientAttestationPoP: attestationPoP)
            } else if offerUri.hasPrefix("http") {
                // Universal-link-style offer: the credential_offer/credential_offer_uri
                // live in the URI's own query string (e.g. an issuer's wallet-redirect
                // page), so the URI itself is not fetchable as the offer JSON - unlike
                // the engine's openid-credential-offer:// handling, it only strips
                // that query param for that exact scheme, so it must be extracted here.
                let queryItems = URLComponents(string: offerUri)?.queryItems ?? []
                func queryValue(_ name: String) -> String? {
                    queryItems.first(where: { $0.name == name })?.value
                }
                if let credentialOffer = queryValue("credential_offer") {
                    engine.startIssuance(offer: credentialOffer, clientAttestation: attestation, clientAttestationPoP: attestationPoP)
                } else if let credentialOfferUri = queryValue("credential_offer_uri") {
                    engine.startIssuance(credentialOfferUri: credentialOfferUri, clientAttestation: attestation, clientAttestationPoP: attestationPoP)
                } else {
                    engine.startIssuance(credentialOfferUri: offerUri, clientAttestation: attestation, clientAttestationPoP: attestationPoP)
                }
            } else {
                engine.startIssuance(offer: offerUri, clientAttestation: attestation, clientAttestationPoP: attestationPoP)
            }
        } catch {
            // A synchronous start failure here means the flow was never
            // registered server-side, so nothing will ever clear the guard
            // via the normal flow_complete/flow_error path - without this,
            // every future issuance attempt would be permanently blocked.
            resetIssuanceGuards()
            throw error
        }
    }

    /// Just enough of a raw `credential_offer` JSON object to resolve display
    /// metadata - `credential_issuer` and the first `credential_configuration_ids`
    /// entry.
    private struct RawCredentialOfferHeader: Decodable {
        let credentialIssuer: String
        let credentialConfigurationIds: [String]

        enum CodingKeys: String, CodingKey {
            case credentialIssuer = "credential_issuer"
            case credentialConfigurationIds = "credential_configuration_ids"
        }
    }

    /// Resolve display metadata (name/logo/colors) for a scanned/deep-linked
    /// credential offer, ahead of forwarding it to the engine.
    ///
    /// `activeOffer` was previously only ever set by `startIssuanceByOffer`
    /// (the picker-driven path from `getAvailableCredentials`) - the QR/
    /// deep-link entry point here never populated it, so every credential
    /// issued that way (mdoc or SD-JWT, ours or a third-party issuer's) was
    /// stored with no display metadata AND no recorded issuer/config
    /// identifiers at all (both derive from `activeOffer` at storage time),
    /// confirmed against a real geneva2026.mdoc.online mDL credential offer.
    ///
    /// Best-effort: returns `nil` on any failure (unparseable offer,
    /// unreachable issuer, issuer doesn't support the offered configuration)
    /// rather than throwing - a missing display must never block issuance
    /// itself.
    private func resolveOfferForDisplay(_ offerUri: String) async -> CredentialOffer? {
        guard let header = await extractOfferHeader(offerUri),
              let configId = header.credentialConfigurationIds.first else { return nil }
        do {
            let metadata = try await fetchIssuerMetadata(issuerUrl: header.credentialIssuer)
            return Self.buildCredentialOffer(issuerUrl: header.credentialIssuer, configId: configId, metadata: metadata)
        } catch {
            return nil
        }
    }

    /// Extract the raw `credential_offer` JSON object from any of the shapes
    /// `startIssuance` accepts.
    private func extractOfferHeader(_ offerUri: String) async -> RawCredentialOfferHeader? {
        if offerUri.hasPrefix("openid-credential-offer://") || offerUri.hasPrefix("http") {
            let queryItems = URLComponents(string: offerUri)?.queryItems ?? []
            func queryValue(_ name: String) -> String? {
                queryItems.first(where: { $0.name == name })?.value
            }
            if let credentialOffer = queryValue("credential_offer"),
               let data = credentialOffer.data(using: .utf8) {
                return try? JSONDecoder().decode(RawCredentialOfferHeader.self, from: data)
            } else if let credentialOfferUri = queryValue("credential_offer_uri") {
                return await fetchOfferHeader(credentialOfferUri)
            }
            return nil
        } else {
            // Not a URI at all - offerUri is itself the raw offer JSON.
            guard let data = offerUri.data(using: .utf8) else { return nil }
            return try? JSONDecoder().decode(RawCredentialOfferHeader.self, from: data)
        }
    }

    private func fetchOfferHeader(_ uri: String) async -> RawCredentialOfferHeader? {
        guard let url = URL(string: uri) else { return nil }
        do {
            let (data, response) = try await URLSession.shared.data(from: url)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { return nil }
            return try? JSONDecoder().decode(RawCredentialOfferHeader.self, from: data)
        } catch {
            return nil
        }
    }

    /// Start a presentation flow.
    public func startPresentation(requestUri: String) async throws {
        guard let engine = engineSession else {
            throw SirosError.wallet(message: "Not connected")
        }
        try await ensureEngineConnected(engine)
        engine.startPresentation(requestUri: requestUri)
    }
}

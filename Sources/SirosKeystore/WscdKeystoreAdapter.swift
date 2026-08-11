// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit

/// Transaction data item for TS12 payment SCA.
///
/// Each item represents one entry from the `transaction_data` array in an
/// OID4VP authorization request. The `rawJson` is the canonical JSON
/// serialization used for hashing into `transaction_data_hashes`.
public struct TransactionDataItem: Sendable {
    /// Transaction type (e.g. "payment", "login_risk", "account_access", "e_mandate").
    public let type: String
    /// Canonical JSON serialization of this transaction data item.
    public let rawJson: String

    public init(type: String, rawJson: String) {
        self.type = type
        self.rawJson = rawJson
    }
}

/// Adapts a `Signer` (e.g. backed by WSCD/UniFFI bindings) into the
/// full `KeystoreManager` protocol expected by `SirosWallet`.
///
/// This adapter delegates raw key operations (generate, sign, list)
/// to the underlying `Signer` implementation while handling
/// higher-level operations (JWT construction, SD-JWT VP tokens,
/// credential storage) locally.
///
/// Usage:
/// ```swift
/// let wscdSigner: Signer = ... // UniFFI-generated WSCD binding
/// let keystore = WscdKeystoreAdapter(signer: wscdSigner)
/// let wallet = SirosWallet(keystore: keystore)
/// ```
public final class WscdKeystoreAdapter: @unchecked Sendable, KeystoreManager, WscdManager {

    private let signer: Signer

    /// Owns the PRF-protected container (mainKey/prfKeys/jwe -> V3
    /// WalletStateContainer) for this adapter's *credentials* - the WSCD
    /// manages its own signing-key protection, but SIROS ID's core tenet is
    /// that private data, including issued credentials, is always protected
    /// by the passkey's PRF-derived secret independent of whichever WSCD
    /// backs key signing. Reusing `JweKeystore` here (rather than an
    /// adapter-local format) guarantees byte-for-byte compatibility with
    /// wallet-frontend and JweKeystore-backed native clients per
    /// privatedata-spec - the SAME passkey must unlock the SAME credentials
    /// on any client. It's also what lets `S.wscdCredentials` (see
    /// `exportWscdCredentialsState`/`setWscdCredentialsState`) actually
    /// round-trip through backend sync for a WSCD-backed wallet, rather than
    /// only existing in this process's memory.
    ///
    /// Unlike Kotlin's `WscdKeystoreAdapter`, this adapter's `Signer`
    /// protocol has no `exportPrivateKeypairs`/`importPrivateKeypairs`
    /// precedent yet, so a "softkey" plugin's own private key material isn't
    /// folded into `credentialsKeystore.keys` here - a known gap, not
    /// introduced by this change.
    private let credentialsKeystore = JweKeystore()

    /// Non-nil only when `signer` is itself WSCD-backed (i.e. a
    /// `UniFFISigner`) - a plain software `Signer` has no lifecycle or
    /// plugin-registration concept.
    private var wscdManager: WscdManager? { signer as? WscdManager }

    private func requireWscdManager() throws -> WscdManager {
        guard let manager = wscdManager else {
            throw KeystoreError.invalidParameter(
                "WSCD lifecycle/plugin registration not supported by this keystore"
            )
        }
        return manager
    }

    public init(signer: Signer) {
        self.signer = signer
    }

    // MARK: - WscdManager conformance

    public func lifecycleStatus(pluginId: String, contextId: String) async throws -> LifecycleStatus {
        try await requireWscdManager().lifecycleStatus(pluginId: pluginId, contextId: contextId)
    }

    public func registerLifecycle(request: RegisterLifecycleRequest) async throws -> RegistrationOutcome {
        try await requireWscdManager().registerLifecycle(request: request)
    }

    public func activateLifecycle(request: ActivateLifecycleRequest) async throws -> ActivationOutcome {
        try await requireWscdManager().activateLifecycle(request: request)
    }

    public func rotateLifecycle(request: RotateLifecycleRequest) async throws -> RotationOutcome {
        try await requireWscdManager().rotateLifecycle(request: request)
    }

    public func destroyLifecycle(request: DestroyLifecycleRequest) async throws -> DestructionOutcome {
        try await requireWscdManager().destroyLifecycle(request: request)
    }

    public func registerFido2Plugin(transport: Ctap2TransportProvider) throws {
        try requireWscdManager().registerFido2Plugin(transport: transport)
    }

    public func registerR2psPlugin(config: R2psConfig, transport: R2psTransportProvider) throws {
        try requireWscdManager().registerR2psPlugin(config: config, transport: transport)
    }

    // MARK: - KeystoreManager conformance

    public var isUnlocked: Bool {
        credentialsKeystore.isUnlocked
    }

    public func unlock(
        prfOutput: Data,
        encryptedContainer: Data,
        hkdfSalt: Data,
        hkdfInfo: Data
    ) async throws {
        // The WSCD manages its own signing-key protection (no PRF unlock for
        // key material itself), but this adapter's *credentials* (and now
        // `S.wscdCredentials`) are still PRF-protected via
        // `credentialsKeystore` - see its doc comment.
        try await credentialsKeystore.unlock(
            prfOutput: prfOutput,
            encryptedContainer: encryptedContainer,
            hkdfSalt: hkdfSalt,
            hkdfInfo: hkdfInfo
        )
    }

    public func lock() {
        credentialsKeystore.lock()
    }

    /// The persisted (privatedata-synced) copy of every hardware-backed WSCD
    /// plugin's key metadata - see `JweKeystore.exportWscdCredentials`'s doc
    /// comment. Read this after `unlock` to restore a previously-enrolled
    /// key via e.g. `registerFido2PluginWithState`, rather than
    /// `exportFido2State` which only reflects the CURRENT process's live
    /// plugin state.
    public func exportWscdCredentialsState() async -> [String: String] {
        await credentialsKeystore.exportWscdCredentials()
    }

    /// Record a WSCD plugin's freshly-exported key metadata so it round-trips
    /// through privatedata on the next `exportEncryptedContainer` - see
    /// `JweKeystore.setWscdCredentials`.
    public func setWscdCredentialsState(pluginId: String, state: String) async {
        await credentialsKeystore.setWscdCredentials(pluginId: pluginId, state: state)
    }

    public func generateKey(algorithm: String) async throws -> String {
        try checkUnlocked()
        return try await signer.generateKey(algorithm: algorithm)
    }

    public func sign(keyId: String, payload: Data, algorithm: String) async throws -> Data {
        try checkUnlocked()
        return try await signer.sign(keyId: keyId, data: payload)
    }

    public func generateProof(audience: String, nonce: String, freshKey: Bool) async throws -> String {
        try checkUnlocked()
        var keys = try await signer.listKeys()
        if keys.isEmpty || freshKey {
            // Auto-generate a key for VCI proof-of-possession
            let newKeyId = try await signer.generateKey(algorithm: "ES256")
            keys = try await signer.listKeys()
            if freshKey {
                keys = keys.filter { $0.keyId == newKeyId }
            }
        }
        guard let key = keys.first else {
            throw KeystoreError.keyNotFound("no keys available")
        }
        let pubKeyData = try await signer.exportPublicKey(keyId: key.keyId)
        let pubKeyJwk = try jsonDict(from: pubKeyData)

        let header = JwtHelpers.jsonBase64Url([
            "alg": algorithmJoseId(key.algorithm),
            "typ": "openid4vci-proof+jwt",
            "jwk": pubKeyJwk,
        ] as [String: Any])

        let now = Int(Date().timeIntervalSince1970)
        let claims = JwtHelpers.jsonBase64Url([
            "aud": audience,
            "iat": now,
            "nonce": nonce,
        ] as [String: Any])

        let signingInput = "\(header).\(claims)"
        let signature = try await signer.sign(keyId: key.keyId, data: Data(signingInput.utf8))
        let sigB64 = EncryptedContainer.base64UrlEncode(signature)
        return "\(signingInput).\(sigB64)"
    }

    public func generateKeyProof(
        keyId: String,
        typ: String,
        issuer: String,
        audience: String,
        extraClaims: [String: String]
    ) async throws -> String {
        try checkUnlocked()
        let keys = try await signer.listKeys()
        guard let key = keys.first(where: { $0.keyId == keyId }) else {
            throw KeystoreError.keyNotFound("Key not found: \(keyId)")
        }
        let pubKeyData = try await signer.exportPublicKey(keyId: keyId)
        let pubKeyJwk = try jsonDict(from: pubKeyData)

        let header = JwtHelpers.jsonBase64Url([
            "alg": algorithmJoseId(key.algorithm),
            "typ": typ,
            "jwk": pubKeyJwk,
        ] as [String: Any])

        let now = Int(Date().timeIntervalSince1970)
        var claimsDict: [String: Any] = [
            "iss": issuer,
            "aud": audience,
            "iat": now,
            "exp": now + 5 * 60,
            "jti": UUID().uuidString.lowercased(),
        ]
        for (k, v) in extraClaims { claimsDict[k] = v }
        let claims = JwtHelpers.jsonBase64Url(claimsDict)

        let signingInput = "\(header).\(claims)"
        let signature = try await signer.sign(keyId: keyId, data: Data(signingInput.utf8))
        let sigB64 = EncryptedContainer.base64UrlEncode(signature)
        return "\(signingInput).\(sigB64)"
    }

    public func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String {
        try checkUnlocked()
        let keys = try await signer.listKeys()
        let key = try selectSigningKey(keys, kid: kid)

        let header = JwtHelpers.jsonBase64Url([
            "alg": algorithmJoseId(key.algorithm),
            "kid": key.keyId,
        ])

        let now = Int(Date().timeIntervalSince1970)
        let claims = JwtHelpers.jsonBase64Url([
            "aud": audience,
            "iat": now,
            "nonce": nonce,
            "jti": UUID().uuidString.lowercased(),
        ] as [String: Any])

        let signingInput = "\(header).\(claims)"
        let signature = try await signer.sign(keyId: key.keyId, data: Data(signingInput.utf8))
        let sigB64 = EncryptedContainer.base64UrlEncode(signature)
        return "\(signingInput).\(sigB64)"
    }

    public func signVpToken(
        credential: String,
        disclosedClaims: [String]?,
        nonce: String,
        audience: String,
        kid: String?
    ) async throws -> String {
        try await signVpToken(
            credential: credential,
            disclosedClaims: disclosedClaims,
            nonce: nonce,
            audience: audience,
            transactionData: nil,
            kid: kid
        )
    }

    /// Extended VP token signing with transaction data (Phase I: TS12 payment SCA).
    public func signVpToken(
        credential: String,
        disclosedClaims: [String]?,
        nonce: String,
        audience: String,
        transactionData: [TransactionDataItem]?,
        kid: String? = nil
    ) async throws -> String {
        try checkUnlocked()
        let keys = try await signer.listKeys()
        let key = try selectSigningKey(keys, kid: kid)

        // Split SD-JWT: IssuerJWT~disclosure1~disclosure2~...~
        let parts = credential.split(separator: "~", omittingEmptySubsequences: false).map(String.init)
        let issuerJwt = parts[0]
        let disclosures = parts.dropFirst().filter { !$0.isEmpty }

        // Filter disclosures if specific claims requested
        let selectedDisclosures: [String]
        if let claims = disclosedClaims, !claims.isEmpty {
            selectedDisclosures = filterDisclosures(disclosures, claimNames: claims)
        } else {
            selectedDisclosures = Array(disclosures)
        }

        // Build SD-JWT presentation (with trailing ~)
        var sdJwtPresentation = issuerJwt
        for d in selectedDisclosures {
            sdJwtPresentation += "~\(d)"
        }
        sdJwtPresentation += "~"

        // Compute sd_hash = base64url(SHA-256(sdJwtPresentation))
        let sdHashDigest = SHA256.hash(data: Data(sdJwtPresentation.utf8))
        let sdHash = EncryptedContainer.base64UrlEncode(Data(sdHashDigest))

        // Build KB-JWT
        let pubKeyData = try await signer.exportPublicKey(keyId: key.keyId)
        let pubKeyJwk = try jsonDict(from: pubKeyData)

        let kbHeader = JwtHelpers.jsonBase64Url([
            "alg": algorithmJoseId(key.algorithm),
            "typ": "kb+jwt",
            "jwk": pubKeyJwk,
        ] as [String: Any])

        let now = Int(Date().timeIntervalSince1970)
        var kbClaimsDict: [String: Any] = [
            "aud": audience,
            "iat": now,
            "nonce": nonce,
            "sd_hash": sdHash,
        ]

        // Include amr from WSCD security properties (E7: TS12 compliance)
        if let props = try? await signer.securityProperties(keyId: key.keyId),
           !props.amr.isEmpty {
            kbClaimsDict["amr"] = props.amr
        }

        // Phase I: Transaction data hashes (TS12 payment SCA)
        if let txData = transactionData, !txData.isEmpty {
            let hashes = try txData.map { item -> String in
                guard let jsonData = item.rawJson.data(using: .utf8) else {
                    throw KeystoreError.cryptoError("Failed to encode transaction data as UTF-8")
                }
                let digest = SHA256.hash(data: jsonData)
                return EncryptedContainer.base64UrlEncode(Data(digest))
            }
            kbClaimsDict["transaction_data_hashes"] = hashes
            kbClaimsDict["transaction_data_hashes_alg"] = "sha-256"
            kbClaimsDict["jti"] = UUID().uuidString.lowercased()
        }

        let kbClaims = JwtHelpers.jsonBase64Url(kbClaimsDict)

        let signingInput = "\(kbHeader).\(kbClaims)"
        let signature = try await signer.sign(keyId: key.keyId, data: Data(signingInput.utf8))
        let sigB64 = EncryptedContainer.base64UrlEncode(signature)
        let kbJwt = "\(signingInput).\(sigB64)"

        return sdJwtPresentation + kbJwt
    }

    public func signMdocPresentation(
        credentialBytes: Data,
        disclosedClaims: [String]?,
        nonce: String,
        audience: String,
        responseUri: String,
        verifierJwkThumbprint: String?,
        kid: String?
    ) async throws -> Data {
        try checkUnlocked()
        let keys = try await signer.listKeys()
        let key = try selectSigningKey(keys, kid: kid)

        let builder = MdocDeviceResponseBuilder(
            issuerSignedBytes: credentialBytes,
            algorithm: key.algorithm
        )

        return try await builder.build(
            nonce: nonce,
            audience: audience,
            responseUri: responseUri,
            verifierJwkThumbprint: verifierJwkThumbprint,
            disclosedClaims: disclosedClaims,
            signer: { data in try await self.signer.sign(keyId: key.keyId, data: data) }
        )
    }

    public func signMdocPresentationForDCAPI(
        credentialBytes: Data,
        disclosedClaims: [String]?,
        nonce: String,
        origin: String,
        encryptionPublicJwkThumbprint: String?,
        kid: String?
    ) async throws -> Data {
        try checkUnlocked()
        let keys = try await signer.listKeys()
        let key = try selectSigningKey(keys, kid: kid)

        let builder = MdocDeviceResponseBuilder(
            issuerSignedBytes: credentialBytes,
            algorithm: key.algorithm
        )

        return try await builder.buildForDCAPI(
            nonce: nonce,
            origin: origin,
            encryptionPublicJwkThumbprint: encryptionPublicJwkThumbprint,
            disclosedClaims: disclosedClaims,
            signer: { data in try await self.signer.sign(keyId: key.keyId, data: data) }
        )
    }

    public func signMdocPresentationForProximity(
        credentialBytes: Data,
        disclosedClaims: [String]?,
        sessionTranscriptBytes: Data,
        kid: String?
    ) async throws -> Data {
        try checkUnlocked()
        let keys = try await signer.listKeys()
        let key = try selectSigningKey(keys, kid: kid)

        let builder = MdocDeviceResponseBuilder(
            issuerSignedBytes: credentialBytes,
            algorithm: key.algorithm
        )

        return try await builder.buildForProximity(
            sessionTranscriptBytes: sessionTranscriptBytes,
            disclosedClaims: disclosedClaims,
            signer: { data in try await self.signer.sign(keyId: key.keyId, data: data) }
        )
    }

    public func exportEncryptedContainer() async throws -> Data {
        // WSCD signing keys themselves are not exportable as a JWE container
        // - they live in the hardware/remote HSM - but this adapter's
        // credentials, presentation records, and S.wscdCredentials ARE
        // PRF-protected and backend-synced via credentialsKeystore (see its
        // doc comment), exactly like a plain JweKeystore-backed wallet.
        try await credentialsKeystore.exportEncryptedContainer()
    }

    public func listKeys() -> [KeyInfo] {
        let semaphore = DispatchSemaphore(value: 0)
        let box = UnsafeMutablePointer<[KeyInfo]>.allocate(capacity: 1)
        box.initialize(to: [])
        Task.detached { [signer, box] in
            let signerKeys = (try? await signer.listKeys()) ?? []
            box.pointee = signerKeys.map {
                KeyInfo(keyId: $0.keyId, algorithm: $0.algorithm)
            }
            semaphore.signal()
        }
        semaphore.wait()
        let result = box.pointee
        box.deinitialize(count: 1)
        box.deallocate()
        return result
    }

    // MARK: - Attestation (WSCD-specific)

    /// Returns the attestation certificate chain for a key, if available.
    ///
    /// For hardware-backed keys (FIDO2/CTAP2), this provides the
    /// attestation statement that proves key provenance for OID4VCI.
    public func attestationChain(keyId: String) async throws -> AttestationChain? {
        return try await signer.attestationChain(keyId: keyId)
    }

    /// Export the public key in JWK format.
    public func exportPublicKey(keyId: String) async throws -> Data {
        return try await signer.exportPublicKey(keyId: keyId)
    }

    // MARK: - Migration

    /// Migrate a key to a different WSCD plugin.
    ///
    /// If the migration result is `.reEnrollmentRequired`, the wallet
    /// should trigger credential re-issuance with the issuer.
    public func migrateKey(keyId: String, targetPlugin: String) async throws -> MigrationResult {
        return try await signer.migrateKey(keyId: keyId, targetPlugin: targetPlugin)
    }

    /// Return the security properties for a key, or nil if unavailable.
    public func securityProperties(keyId: String) async -> SignerSecurityProperties? {
        return try? await signer.securityProperties(keyId: keyId)
    }

    // MARK: - Credential storage (PRF-protected via credentialsKeystore)

    public func saveCredential(id: Int64, json: String) async throws {
        try await credentialsKeystore.saveCredential(id: id, json: json)
    }

    public func getCredential(id: Int64) async throws -> String? {
        try await credentialsKeystore.getCredential(id: id)
    }

    public func getAllCredentials() async throws -> [Int64: String] {
        try await credentialsKeystore.getAllCredentials()
    }

    public func deleteCredential(id: Int64) async throws {
        try await credentialsKeystore.deleteCredential(id: id)
    }

    public func clearCredentials() async throws {
        try await credentialsKeystore.clearCredentials()
    }

    // MARK: - Presentation history storage (PRF-protected via credentialsKeystore)

    public func savePresentationRecord(id: Int64, json: String) async throws {
        try await credentialsKeystore.savePresentationRecord(id: id, json: json)
    }

    public func getAllPresentationRecords() async throws -> [Int64: String] {
        try await credentialsKeystore.getAllPresentationRecords()
    }

    public func clearPresentationRecords() async throws {
        try await credentialsKeystore.clearPresentationRecords()
    }

    public func generateKeypairs(count: Int) async throws -> [KeypairInfo] {
        try checkUnlocked()
        guard count >= 1 else {
            throw KeystoreError.invalidParameter("count must be >= 1")
        }
        var result: [KeypairInfo] = []
        for _ in 0..<count {
            let keyId = try await generateKey(algorithm: "ES256")
            let pubData = try await signer.exportPublicKey(keyId: keyId)
            guard let jwk = try JSONSerialization.jsonObject(with: pubData) as? [String: Any],
                  jwk["kty"] != nil else {
                throw KeystoreError.invalidParameter("failed to parse exported public key as JWK")
            }
            result.append(KeypairInfo(keyId: keyId, publicKeyJWK: jwk))
        }
        return result
    }

    /// Generate `count` fresh keypairs and self-attest them in a single OID4VCI
    /// Key Attestation JWT (Appendix F.3, "attestation" proof type) - signed
    /// by the first freshly generated key itself, matching the spec's
    /// "issued... by the Wallet's key storage component itself" option, since
    /// this WSCD plugin has no separate wallet-provider/hardware attestation
    /// authority.
    public func generateKeyAttestation(nonce: String, count: Int) async throws -> String {
        try checkUnlocked()
        let keypairs = try await generateKeypairs(count: count)
        guard let signingKey = keypairs.first else {
            throw KeystoreError.invalidParameter("no keys generated for attestation")
        }

        let securityProps = try? await signer.securityProperties(keyId: signingKey.keyId)

        let header = JwtHelpers.jsonBase64Url([
            "alg": algorithmJoseId("ES256"),
            "typ": "key-attestation+jwt",
            "jwk": signingKey.publicKeyJWK,
        ] as [String: Any])

        var claims: [String: Any] = [
            "iat": Int(Date().timeIntervalSince1970),
            "nonce": nonce,
            "attested_keys": keypairs.map { $0.publicKeyJWK },
        ]

        if let keyStorage = securityProps?.keyStorage, !keyStorage.isEmpty {
            claims["key_storage"] = orderedUnique(keyStorage.map { toIso18045AttackPotential($0) ?? "iso_18045_basic" })
        } else {
            claims["key_storage"] = ["iso_18045_basic"]
        }

        if let userAuthentication = securityProps?.userAuthentication, !userAuthentication.isEmpty {
            let mapped = orderedUnique(userAuthentication.compactMap { toIso18045AttackPotential($0, omitIfNone: true) })
            if !mapped.isEmpty {
                claims["user_authentication"] = mapped
            }
        }

        let claimsB64 = JwtHelpers.jsonBase64Url(claims)
        let signingInput = "\(header).\(claimsB64)"
        let signature = try await signer.sign(keyId: signingKey.keyId, data: Data(signingInput.utf8))
        let sigB64 = EncryptedContainer.base64UrlEncode(signature)
        return "\(signingInput).\(sigB64)"
    }

    // MARK: - Private helpers

    private func checkUnlocked() throws {
        guard credentialsKeystore.isUnlocked else {
            throw KeystoreError.locked
        }
    }

    /// Pick the key to sign a presentation with. When `kid` is given (the
    /// credential being presented has a known bound key - see
    /// `StoredCredential.kid`), that EXACT key must be used - a wallet
    /// holding more than one key (e.g. after a batch issuance where each
    /// credential instance is bound to its own device key) would otherwise
    /// silently sign every credential with whichever key happens to be
    /// first, producing a structurally valid but cryptographically wrong
    /// signature for every credential except that one. Throws rather than
    /// silently falling back if the specified key isn't found, since signing
    /// with a different key is never a safe substitute. `kid` is nil only
    /// for genuinely credential-less call shapes (e.g. `signPresentation`'s
    /// legacy no-credential form), where "first available key" is the only
    /// meaningful choice.
    private func selectSigningKey(_ keys: [SignerKeyInfo], kid: String?) throws -> SignerKeyInfo {
        if let kid {
            guard let key = keys.first(where: { $0.keyId == kid }) else {
                throw KeystoreError.keyNotFound("Signing key '\(kid)' not found - this credential's bound key is unavailable")
            }
            return key
        }
        guard let key = keys.first else {
            throw KeystoreError.keyNotFound("no keys available for signing")
        }
        return key
    }

    /// Translate SIROS's internal WSCD key-storage/user-authentication
    /// vocabulary (`software`/`hardware`/`trusted_execution`/`remote_hsm`,
    /// see `SignerSecurityProperties`) into the OID4VCI Key Attestation JWT's
    /// registered `iso_18045_*` attack-potential-resistance values.
    ///
    /// Confirmed via a real conformance-test issuer that passing the raw
    /// internal string through unmapped (e.g. `"software"`) produces a
    /// `key_storage`/`user_authentication` value the issuer doesn't
    /// recognize. Mappings are necessarily approximate (SIROS's vocabulary is
    /// coarser than the ISO 18045 scale) - conservative/lower tiers are
    /// preferred over overclaiming resistance we can't actually back up.
    private func toIso18045AttackPotential(_ raw: String, omitIfNone: Bool = false) -> String? {
        if raw.hasPrefix("iso_18045_") { return raw }
        switch raw.lowercased() {
        case "none": return omitIfNone ? nil : "iso_18045_basic"
        case "software": return "iso_18045_basic"
        case "hardware": return "iso_18045_moderate"
        case "trusted_execution": return "iso_18045_enhanced-basic"
        case "remote_hsm": return "iso_18045_high"
        default: return "iso_18045_basic"
        }
    }

    private func orderedUnique(_ items: [String]) -> [String] {
        var seen = Set<String>()
        return items.filter { seen.insert($0).inserted }
    }

    private func algorithmJoseId(_ algorithm: String) -> String {
        switch algorithm.uppercased() {
        case "ES256", "P-256": return "ES256"
        case "EDDSA", "ED25519": return "EdDSA"
        default: return algorithm
        }
    }

    private func jsonDict(from data: Data) throws -> [String: Any] {
        guard let dict = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw KeystoreError.cryptoError("Invalid JWK JSON")
        }
        return dict
    }

    private func filterDisclosures(_ disclosures: [String], claimNames: [String]) -> [String] {
        disclosures.filter { disclosure in
            guard let data = Data(base64Encoded: padBase64(disclosure)),
                  let array = try? JSONSerialization.jsonObject(with: data) as? [Any],
                  array.count >= 2,
                  let name = array[1] as? String else {
                return false
            }
            return claimNames.contains(name)
        }
    }

    private func padBase64(_ str: String) -> String {
        var s = str.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = s.count % 4
        if remainder > 0 {
            s += String(repeating: "=", count: 4 - remainder)
        }
        return s
    }
}

#endif // canImport(CryptoKit)

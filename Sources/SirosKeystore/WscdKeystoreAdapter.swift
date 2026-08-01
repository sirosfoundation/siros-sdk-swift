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
public final class WscdKeystoreAdapter: @unchecked Sendable, KeystoreManager {

    private let signer: Signer
    private let mutex = NSLock()
    private var _isUnlocked = false
    private var credentials: [String: String] = [:]

    public init(signer: Signer) {
        self.signer = signer
    }

    // MARK: - KeystoreManager conformance

    public var isUnlocked: Bool {
        mutex.lock()
        defer { mutex.unlock() }
        return _isUnlocked
    }

    public func unlock(
        prfOutput: Data,
        encryptedContainer: Data,
        hkdfSalt: Data,
        hkdfInfo: Data
    ) async throws {
        // WSCD-backed keystores don't use PRF unlock —
        // the WSCD manages its own key protection.
        // Mark as unlocked; the WSCD handles auth via its own callbacks.
        mutex.lock()
        defer { mutex.unlock() }
        _isUnlocked = true
    }

    public func lock() {
        mutex.lock()
        defer { mutex.unlock() }
        _isUnlocked = false
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
        guard let jkt = JwtHelpers.jwkThumbprint(pubKeyJwk) else {
            throw KeystoreError.invalidParameter("Failed to compute JWK thumbprint")
        }

        let header = JwtHelpers.jsonBase64Url([
            "alg": algorithmJoseId(key.algorithm),
            "typ": typ,
            "jwk": pubKeyJwk,
        ] as [String: Any])

        let now = Int(Date().timeIntervalSince1970)
        var claimsDict: [String: Any] = [
            "iss": jkt,
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

    public func signPresentation(nonce: String, audience: String, credentialIds: [String]) async throws -> String {
        try checkUnlocked()
        let keys = try await signer.listKeys()
        guard let key = keys.first else {
            throw KeystoreError.keyNotFound("no keys available")
        }

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
        audience: String
    ) async throws -> String {
        try await signVpToken(
            credential: credential,
            disclosedClaims: disclosedClaims,
            nonce: nonce,
            audience: audience,
            transactionData: nil
        )
    }

    /// Extended VP token signing with transaction data (Phase I: TS12 payment SCA).
    public func signVpToken(
        credential: String,
        disclosedClaims: [String]?,
        nonce: String,
        audience: String,
        transactionData: [TransactionDataItem]?
    ) async throws -> String {
        try checkUnlocked()
        let keys = try await signer.listKeys()
        guard let key = keys.first else {
            throw KeystoreError.keyNotFound("no keys available")
        }

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
        verifierJwkThumbprint: String?
    ) async throws -> Data {
        try checkUnlocked()
        let keys = try await signer.listKeys()
        guard let key = keys.first else {
            throw KeystoreError.keyNotFound("no keys available for mDoc signing")
        }

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
        encryptionPublicJwkThumbprint: String?
    ) async throws -> Data {
        try checkUnlocked()
        let keys = try await signer.listKeys()
        guard let key = keys.first else {
            throw KeystoreError.keyNotFound("no keys available for mDoc DC API signing")
        }

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

    public func exportEncryptedContainer() async throws -> Data {
        // WSCD keys are not exportable as a JWE container —
        // they live in the hardware/remote HSM.
        // Return a valid empty JSON object so callers that parse the result
        // (e.g. syncPrivateDataToBackend) don't fail on empty data.
        return Data("{}".utf8)
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
    public func attestationChain(keyId: String) async throws -> [Data]? {
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

    // MARK: - Credential storage (local in-memory)

    public func saveCredential(id: String, json: String) async throws {
        try checkUnlocked()
        mutex.lock()
        defer { mutex.unlock() }
        credentials[id] = json
    }

    public func getCredential(id: String) async throws -> String? {
        try checkUnlocked()
        mutex.lock()
        defer { mutex.unlock() }
        return credentials[id]
    }

    public func getAllCredentials() async throws -> [String: String] {
        try checkUnlocked()
        mutex.lock()
        defer { mutex.unlock() }
        return credentials
    }

    public func deleteCredential(id: String) async throws {
        try checkUnlocked()
        mutex.lock()
        defer { mutex.unlock() }
        credentials.removeValue(forKey: id)
    }

    public func clearCredentials() async throws {
        try checkUnlocked()
        mutex.lock()
        defer { mutex.unlock() }
        credentials.removeAll()
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
        mutex.lock()
        defer { mutex.unlock() }
        guard _isUnlocked else {
            throw KeystoreError.locked
        }
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

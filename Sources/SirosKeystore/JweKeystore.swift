// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(CommonCrypto)
import CommonCrypto
#endif

/// JWE-based keystore implementation fully compatible with the wallet-frontend
/// encrypted container format.
///
/// Uses the same key hierarchy as the TypeScript web wallet:
///   PRF output → HKDF(SHA-256, salt, info="eDiplomas PRF") → prfKey (AES-GCM-256)
///   prfKey → unwrap ECDH private key → ECDH key agreement → AES-KW → unwrap mainKey
///   mainKey → decrypt JWE (alg=A256GCMKW, enc=A256GCM) → WalletStateContainer
///
/// This enables cross-device portability: the same encrypted private data
/// can be used by both the iOS native wallet and the web wallet,
/// provided the same passkey PRF is used on the same authenticator.
public final class JweKeystore: @unchecked Sendable, KeystoreManager {

    #if canImport(CryptoKit)

    private let mutex = NSLock()
    private var keys: [String: P256.Signing.PrivateKey] = [:]
    private var credentials: [Int64: String] = [:]
    private var presentationRecords: [Int64: String] = [:]
    private var _mainKey: SymmetricKey?
    private var containerMetadata: ContainerData?
    // Preserve full WalletStateContainer for round-trip fidelity
    private var preservedWalletState: [String: Any]?

    public init() {}

    public var isUnlocked: Bool {
        mutex.lock()
        defer { mutex.unlock() }
        return _mainKey != nil
    }

    // MARK: - Unlock / Lock

    // swiftlint:disable:next function_body_length
    public func unlock(
        prfOutput: Data,
        encryptedContainer: Data,
        hkdfSalt: Data,
        hkdfInfo: Data
    ) async throws {
        mutex.lock()
        defer { mutex.unlock() }

        if !encryptedContainer.isEmpty {
            let container = try EncryptedContainer.parse(encryptedContainer)
            guard let mainKeyInfo = container.mainKey else {
                throw KeystoreError.containerMissing("Container missing mainKey")
            }

            let prfKeyInfo = container.prfKeys.first(where: { !$0.credentialId.isEmpty && $0.hkdfSalt == hkdfSalt })
                ?? container.prfKeys.first(where: { $0.hkdfSalt == hkdfSalt })
                ?? container.prfKeys.first
            guard let prfKeyInfo else {
                throw KeystoreError.containerMissing("No PRF key entries in container")
            }

            let prfKey = EncryptedContainer.derivePrfKey(
                prfOutput: prfOutput,
                hkdfSalt: prfKeyInfo.hkdfSalt,
                hkdfInfo: prfKeyInfo.hkdfInfo
            )

            let unwrappedMainKey = try EncryptedContainer.unwrapMainKey(
                prfKey: prfKey,
                prfKeyInfo: prfKeyInfo,
                mainKeyInfo: mainKeyInfo
            )
            _mainKey = unwrappedMainKey

            let jwePayload = try decryptJwe(container.jwe, mainKey: unwrappedMainKey)
            if let jweDict = jwePayload as? [String: Any] {
                preservedWalletState = jweDict
            }
            loadWalletState(jwePayload)
            containerMetadata = container
        } else {
            // First-time setup
            let (newMainKey, newMainKeyInfo) = EncryptedContainer.generateMainKey()
            _mainKey = newMainKey

            let prfKey = EncryptedContainer.derivePrfKey(
                prfOutput: prfOutput,
                hkdfSalt: hkdfSalt,
                hkdfInfo: hkdfInfo
            )
            let encapsulation = try EncryptedContainer.wrapMainKey(
                prfKey: prfKey,
                mainKey: newMainKey,
                mainKeyInfo: newMainKeyInfo
            )

            var prfSalt = Data(count: 32)
            // swiftlint:disable:next force_unwrapping
            prfSalt.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }

            containerMetadata = ContainerData(
                jwe: "",
                mainKey: newMainKeyInfo,
                prfKeys: [
                    PrfKeyInfo(
                        credentialId: Data(),
                        transports: nil,
                        prfSalt: prfSalt,
                        hkdfSalt: hkdfSalt,
                        hkdfInfo: hkdfInfo,
                        algorithm: AesGcmKeyAlgorithm(name: "AES-GCM", length: 256),
                        keypair: encapsulation.keypair,
                        unwrapKey: encapsulation.unwrapKey
                    )
                ]
            )
        }
    }

    public func setCredentialId(_ credentialId: Data) {
        mutex.lock()
        defer { mutex.unlock() }
        guard var meta = containerMetadata,
              !meta.prfKeys.isEmpty,
              meta.prfKeys[0].credentialId.isEmpty else { return }
        meta.prfKeys[0].credentialId = credentialId
        containerMetadata = meta
    }

    public func lock() {
        mutex.lock()
        defer { mutex.unlock() }
        keys.removeAll()
        credentials.removeAll()
        presentationRecords.removeAll()
        _mainKey = nil
        containerMetadata = nil
        preservedWalletState = nil
    }

    // MARK: - Key operations

    public func generateKey(algorithm: String = "ES256") async throws -> String {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        let keyId = UUID().uuidString.lowercased()
        let privateKey = P256.Signing.PrivateKey()
        keys[keyId] = privateKey
        return keyId
    }

    public func sign(keyId: String, payload: Data, algorithm: String = "ES256") async throws -> Data {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        guard let key = keys[keyId] else {
            throw KeystoreError.keyNotFound(keyId)
        }
        let header = JwtHelpers.jsonBase64Url(["alg": "ES256", "kid": keyId])
        let payloadB64 = EncryptedContainer.base64UrlEncode(payload)
        let signingInput = "\(header).\(payloadB64)"
        let signature = try key.signature(for: Data(signingInput.utf8))
        let sigB64 = EncryptedContainer.base64UrlEncode(signature.rawRepresentation)
        let jws = "\(signingInput).\(sigB64)"
        return Data(jws.utf8)
    }

    public func generateProof(audience: String, nonce: String, freshKey: Bool) async throws -> String {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()

        let key: P256.Signing.PrivateKey
        if let first = keys.values.first {
            key = first
        } else {
            let keyId = UUID().uuidString.lowercased()
            let newKey = P256.Signing.PrivateKey()
            keys[keyId] = newKey
            key = newKey
        }

        let publicJwk = JwtHelpers.publicKeyJwk(key)
        let header = JwtHelpers.jsonBase64Url([
            "alg": "ES256",
            "typ": "openid4vci-proof+jwt",
            "jwk": publicJwk,
        ] as [String: Any])

        let now = Int(Date().timeIntervalSince1970)
        let claims = JwtHelpers.jsonBase64Url([
            "aud": audience,
            "iat": now,
            "nonce": nonce,
        ] as [String: Any])

        let signingInput = "\(header).\(claims)"
        let signature = try key.signature(for: Data(signingInput.utf8))
        let sigB64 = EncryptedContainer.base64UrlEncode(signature.rawRepresentation)
        return "\(signingInput).\(sigB64)"
    }

    public func generateKeyProof(
        keyId: String,
        typ: String,
        issuer: String,
        audience: String,
        extraClaims: [String: String]
    ) async throws -> String {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()

        guard let key = keys[keyId] else {
            throw KeystoreError.keyNotFound("Key not found: \(keyId)")
        }
        let pubJwk = JwtHelpers.publicKeyJwk(key)

        let header = JwtHelpers.jsonBase64Url([
            "alg": "ES256",
            "typ": typ,
            "jwk": pubJwk,
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
        let signature = try key.signature(for: Data(signingInput.utf8))
        let sigB64 = EncryptedContainer.base64UrlEncode(signature.rawRepresentation)
        return "\(signingInput).\(sigB64)"
    }

    public func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()

        let (keyId, key) = try selectSigningKey(kid: kid)

        let header = JwtHelpers.jsonBase64Url([
            "alg": "ES256",
            "kid": keyId,
        ])

        let now = Int(Date().timeIntervalSince1970)
        let claims = JwtHelpers.jsonBase64Url([
            "aud": audience,
            "iat": now,
            "nonce": nonce,
            "jti": UUID().uuidString.lowercased(),
        ] as [String: Any])

        let signingInput = "\(header).\(claims)"
        let signature = try key.signature(for: Data(signingInput.utf8))
        let sigB64 = EncryptedContainer.base64UrlEncode(signature.rawRepresentation)
        return "\(signingInput).\(sigB64)"
    }

    public func signVpToken(
        credential: String,
        disclosedClaims: [String]?,
        nonce: String,
        audience: String,
        kid: String?
    ) async throws -> String {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()

        let (_, key) = try selectSigningKey(kid: kid)

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
        let publicJwk = JwtHelpers.publicKeyJwk(key)
        let kbHeader = JwtHelpers.jsonBase64Url([
            "alg": "ES256",
            "typ": "kb+jwt",
            "jwk": publicJwk,
        ] as [String: Any])

        let now = Int(Date().timeIntervalSince1970)
        let kbClaims = JwtHelpers.jsonBase64Url([
            "aud": audience,
            "iat": now,
            "nonce": nonce,
            "sd_hash": sdHash,
        ] as [String: Any])

        let signingInput = "\(kbHeader).\(kbClaims)"
        let signature = try key.signature(for: Data(signingInput.utf8))
        let sigB64 = EncryptedContainer.base64UrlEncode(signature.rawRepresentation)
        let kbJwt = "\(signingInput).\(sigB64)"

        return sdJwtPresentation + kbJwt
    }

    public func exportEncryptedContainer() async throws -> Data {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()

        // swiftlint:disable:next force_unwrapping
        let currentMainKey = _mainKey! // safe: requireUnlocked() above guarantees non-nil
        let walletState = buildWalletStateV3()
        let payload = try JSONSerialization.data(withJSONObject: walletState)

        let jweString = try encryptJwe(payload, mainKey: currentMainKey)
        guard var meta = containerMetadata else {
            throw KeystoreError.containerMissing("No container metadata")
        }
        meta.jwe = jweString
        containerMetadata = meta

        return try EncryptedContainer.serialize(meta)
    }

    public func listKeys() -> [KeyInfo] {
        mutex.lock()
        defer { mutex.unlock() }
        return keys.map { KeyInfo(keyId: $0.key, algorithm: "ES256") }
    }

    // MARK: - Credential storage

    public func saveCredential(id: Int64, json: String) async throws {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        credentials[id] = json
    }

    public func getCredential(id: Int64) async throws -> String? {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        return credentials[id]
    }

    public func getAllCredentials() async throws -> [Int64: String] {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        return credentials
    }

    public func deleteCredential(id: Int64) async throws {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        credentials.removeValue(forKey: id)
    }

    public func clearCredentials() async throws {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        credentials.removeAll()
    }

    // MARK: - Presentation history storage

    public func savePresentationRecord(id: Int64, json: String) async throws {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        presentationRecords[id] = json
    }

    public func getAllPresentationRecords() async throws -> [Int64: String] {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        return presentationRecords
    }

    public func clearPresentationRecords() async throws {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        presentationRecords.removeAll()
    }

    public func generateKeypairs(count: Int) async throws -> [KeypairInfo] {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        var result: [KeypairInfo] = []
        for _ in 0..<count {
            let keyId = UUID().uuidString.lowercased()
            let privateKey = P256.Signing.PrivateKey()
            keys[keyId] = privateKey
            let jwk = JwtHelpers.publicKeyJwk(privateKey)
            // Convert [String: String] to [String: Any]
            var jwkAny: [String: Any] = [:]
            for (k, v) in jwk { jwkAny[k] = v }
            result.append(KeypairInfo(keyId: keyId, publicKeyJWK: jwkAny))
        }
        return result
    }

    /// Generate `count` fresh keypairs and self-attest them in a single OID4VCI
    /// Key Attestation JWT. This is a pure in-memory software keystore with no
    /// hardware backing or user-authentication gate, so the only truthful
    /// claim is the baseline "basic" attack-potential level.
    public func generateKeyAttestation(nonce: String, count: Int) async throws -> String {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        guard count >= 1 else {
            throw KeystoreError.invalidParameter("count must be >= 1")
        }

        // Inlined key generation (not generateKeypairs(), which also takes
        // this lock - NSLock isn't reentrant).
        var generated: [(keyId: String, privateKey: P256.Signing.PrivateKey)] = []
        for _ in 0..<count {
            let keyId = UUID().uuidString.lowercased()
            let privateKey = P256.Signing.PrivateKey()
            keys[keyId] = privateKey
            generated.append((keyId: keyId, privateKey: privateKey))
        }

        let signingKey = generated[0]
        let signingJwk = JwtHelpers.publicKeyJwk(signingKey.privateKey)

        let header = JwtHelpers.jsonBase64Url([
            "alg": "ES256",
            "typ": "key-attestation+jwt",
            "jwk": signingJwk,
        ] as [String: Any])

        let attestedKeys = generated.map { JwtHelpers.publicKeyJwk($0.privateKey) }
        let claims = JwtHelpers.jsonBase64Url([
            "iat": Int(Date().timeIntervalSince1970),
            "nonce": nonce,
            "attested_keys": attestedKeys,
            "key_storage": ["iso_18045_basic"],
        ] as [String: Any])

        let signingInput = "\(header).\(claims)"
        let signature = try signingKey.privateKey.signature(for: Data(signingInput.utf8))
        let sigB64 = EncryptedContainer.base64UrlEncode(signature.rawRepresentation)
        return "\(signingInput).\(sigB64)"
    }

    // MARK: - Private helpers

    private func requireUnlocked() throws {
        guard _mainKey != nil else {
            throw KeystoreError.locked
        }
    }

    /// Pick the key to sign a presentation with. See
    /// `WscdKeystoreAdapter.selectSigningKey`'s doc comment for why, when
    /// `kid` is given (the credential being presented has a known bound key
    /// - see `StoredCredential.kid`), that EXACT key must be used - throwing
    /// rather than silently falling back to an arbitrary one if it's
    /// missing. `kid` is nil only for genuinely credential-less call shapes,
    /// where "first available key" (generating one if none exist yet) is
    /// the only meaningful choice.
    private func selectSigningKey(kid: String?) throws -> (keyId: String, key: P256.Signing.PrivateKey) {
        if let kid {
            guard let key = keys[kid] else {
                throw KeystoreError.keyNotFound("Signing key '\(kid)' not found - this credential's bound key is unavailable")
            }
            return (kid, key)
        }
        if let first = keys.first {
            return (first.key, first.value)
        }
        let keyId = UUID().uuidString.lowercased()
        let newKey = P256.Signing.PrivateKey()
        keys[keyId] = newKey
        return (keyId, newKey)
    }

    private func filterDisclosures(_ disclosures: [String], claimNames: [String]) -> [String] {
        let requested = Set(claimNames)
        return disclosures.filter { disclosure in
            let decoded = EncryptedContainer.base64UrlDecode(disclosure)
            guard let str = String(data: decoded, encoding: .utf8),
                  let arr = try? JSONSerialization.jsonObject(with: Data(str.utf8)) as? [Any],
                  arr.count >= 2,
                  let claimName = arr[1] as? String else {
                return true // include unparseable disclosures to be safe
            }
            return requested.contains(claimName)
        }
    }

    // MARK: - Wallet state

    private func loadWalletState(_ json: [String: Any]) {
        // V3 format: { S: { keypairs: [...], credentials: [...], ... } }
        if let state = json["S"] as? [String: Any] {
            loadFromWalletStateV3(state)
        } else if json["keys"] != nil {
            // Legacy Kotlin-only format
            loadLegacyState(json)
        }
    }

    private func loadFromWalletStateV3(_ state: [String: Any]) {
        if let keypairsArray = state["keypairs"] as? [[String: Any]] {
            for entry in keypairsArray {
                guard let keypairObj = entry["keypair"] as? [String: Any],
                      let kid = keypairObj["kid"] as? String,
                      let privateKeyJwk = keypairObj["privateKey"] as? [String: Any],
                      let dStr = privateKeyJwk["d"] as? String else { continue }
                let dData = EncryptedContainer.base64UrlDecode(dStr)
                if let key = try? P256.Signing.PrivateKey(rawRepresentation: dData) {
                    keys[kid] = key
                }
            }
        }

        // credentialId/batchId are privatedata-spec `number`s on the wire
        // (matching wallet-frontend's WalletStateCredential exactly) - read
        // via asInt64/asInt (which accept both NSNumber and String) rather
        // than a strict numeric cast, so a value that arrives quoted (e.g.
        // from a not-yet-migrated container) still parses instead of
        // silently dropping the entry.
        if let credsArray = state["credentials"] as? [[String: Any]] {
            for entry in credsArray {
                guard let credId = Self.asInt64(entry["credentialId"]),
                      let data = entry["data"] as? String else { continue }
                let credKid = entry["kid"] as? String
                let credFormat = (entry["format"] as? String) ?? ""
                let credIssuerIdent = entry["credentialIssuerIdentifier"] as? String
                let credConfigId = entry["credentialConfigurationId"] as? String
                let batchId = Self.asInt64(entry["batchId"]) ?? 0
                let instanceId = Self.asInt(entry["instanceId"]) ?? 0

                // Reconstruct a StoredCredential-shaped JSON blob (snake_case
                // matching StoredCredential's CodingKeys) to preserve kid/
                // batchId/instanceId/etc binding - credentialIssuerIdentifier/
                // credentialConfigurationId are part of privatedata-spec's
                // normative fields (already written by buildWalletStateV3()
                // below) - reconstructing them here too is what lets
                // SirosWallet re-fetch VCTM display metadata after a fresh
                // login.
                var storedDict: [String: Any] = [
                    "id": credId,
                    "format": credFormat,
                    "raw": data,
                    "batch_id": batchId,
                    "instance_id": instanceId,
                ]
                if let credKid, !credKid.isEmpty { storedDict["kid"] = credKid }
                if let credIssuerIdent, !credIssuerIdent.isEmpty {
                    storedDict["credential_issuer_identifier"] = credIssuerIdent
                }
                if let credConfigId, !credConfigId.isEmpty {
                    storedDict["credential_configuration_id"] = credConfigId
                }

                if let storedData = try? JSONSerialization.data(withJSONObject: storedDict),
                   let storedJson = String(data: storedData, encoding: .utf8) {
                    credentials[credId] = storedJson
                }
            }
        }

        // Parse presentations: [{ presentationId, transactionId, data,
        // usedCredentialIds, presentationTimestampSeconds, audience }] -
        // privatedata-spec's normative shape (wallet-frontend's
        // WalletStatePresentation). transactionId/data have no
        // PresentationRecord counterpart (see its doc comment) and are
        // intentionally dropped on reload, not round-tripped.
        if let presentationsArray = state["presentations"] as? [[String: Any]] {
            for entry in presentationsArray {
                guard let presId = Self.asInt64(entry["presentationId"]) else { continue }
                let usedCredentialIds = (entry["usedCredentialIds"] as? [Any])?.compactMap { Self.asInt64($0) } ?? []
                let timestampSeconds = Self.asInt64(entry["presentationTimestampSeconds"]) ?? 0
                let audience = entry["audience"] as? String

                var recordDict: [String: Any] = [
                    "id": presId,
                    "flow_id": "",
                    "credential_ids": usedCredentialIds,
                    "timestamp": timestampSeconds * 1000,
                ]
                if let audience, !audience.isEmpty { recordDict["verifier_name"] = audience }

                if let recordData = try? JSONSerialization.data(withJSONObject: recordDict),
                   let recordJson = String(data: recordData, encoding: .utf8) {
                    presentationRecords[presId] = recordJson
                }
            }
        }
    }

    /// Coerce a JSON value (parsed via `JSONSerialization`, so numbers surface
    /// as `NSNumber`) or a string-encoded number into an `Int64`. Accepting
    /// both keeps parsing robust to a not-yet-migrated container where a
    /// privatedata-spec `number` field might still arrive quoted.
    private static func asInt64(_ value: Any?) -> Int64? {
        if let n = value as? NSNumber { return n.int64Value }
        if let s = value as? String { return Int64(s) }
        return nil
    }

    private static func asInt(_ value: Any?) -> Int? {
        if let n = value as? NSNumber { return n.intValue }
        if let s = value as? String { return Int(s) }
        return nil
    }

    private func parseJsonObject(_ jsonString: String) -> [String: Any]? {
        guard let data = jsonString.data(using: .utf8) else { return nil }
        return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    }

    private func loadLegacyState(_ json: [String: Any]) {
        guard let keysArr = json["keys"] as? [[String: Any]] else { return }
        for stored in keysArr {
            guard let keyId = stored["keyId"] as? String,
                  let jwkStr = stored["jwk"] as? String,
                  let jwkData = jwkStr.data(using: .utf8),
                  let jwk = try? JSONSerialization.jsonObject(with: jwkData) as? [String: Any],
                  let dStr = jwk["d"] as? String else { continue }
            let dData = EncryptedContainer.base64UrlDecode(dStr)
            if let key = try? P256.Signing.PrivateKey(rawRepresentation: dData) {
                keys[keyId] = key
            }
        }
        // Legacy Kotlin-only container predates numeric credential ids
        // entirely - defaults any unparseable (pre-migration UUID-string)
        // key to 0, since this path is only reachable from a container
        // exported before the privatedata-spec numeric-id alignment.
        if let creds = json["credentials"] as? [String: String] {
            credentials = creds.reduce(into: [Int64: String]()) { result, entry in
                result[Int64(entry.key) ?? 0] = entry.value
            }
        }
    }

    private func buildWalletStateV3() -> [String: Any] {
        // Preserve existing state if available, otherwise initialize fresh.
        // NOTE: this must NOT short-circuit and return existingState verbatim -
        // credentials/keys added via saveCredential()/generateKey() since unlock()
        // only live in the `keys`/`credentials` dictionaries below, not in
        // preservedWalletState, so an early return here would silently drop any
        // credential added by a returning user (preservedWalletState is only
        // ever non-nil when unlock() loaded an existing container).
        let existingState = preservedWalletState
        let existingS = existingState?["S"] as? [String: Any]

        let originalKeypairsByKid: [String: [String: Any]] = {
            guard let arr = existingS?["keypairs"] as? [[String: Any]] else { return [:] }
            var result: [String: [String: Any]] = [:]
            for entry in arr {
                if let kid = (entry["keypair"] as? [String: Any])?["kid"] as? String {
                    result[kid] = entry
                }
            }
            return result
        }()

        // credentialId is a privatedata-spec number on the wire (matching
        // wallet-frontend), so compare it numerically rather than as a string.
        let originalCredsById: [Int64: [String: Any]] = {
            guard let arr = existingS?["credentials"] as? [[String: Any]] else { return [:] }
            var result: [Int64: [String: Any]] = [:]
            for entry in arr {
                if let credId = Self.asInt64(entry["credentialId"]) {
                    result[credId] = entry
                }
            }
            return result
        }()

        let keypairs: [[String: Any]] = keys.map { (kid, ecKey) in
            let publicKey = ecKey.publicKey
            let x963 = publicKey.x963Representation
            let x = Data(x963[1..<33])
            let y = Data(x963[33..<65])
            let d = ecKey.rawRepresentation

            let pubJwk: [String: Any] = [
                "kty": "EC",
                "crv": "P-256",
                "x": EncryptedContainer.base64UrlEncode(x),
                "y": EncryptedContainer.base64UrlEncode(y),
            ]
            let privJwk: [String: Any] = [
                "kty": "EC",
                "crv": "P-256",
                "x": EncryptedContainer.base64UrlEncode(x),
                "y": EncryptedContainer.base64UrlEncode(y),
                "d": EncryptedContainer.base64UrlEncode(d),
            ]
            // Preserve DID from original state if available; only compute for fresh keys
            let originalKeypair = originalKeypairsByKid[kid]?["keypair"] as? [String: Any]
            let did = originalKeypair?["did"] as? String ?? ""
            return [
                "kid": kid,
                "keypair": [
                    "kid": kid,
                    "did": did,
                    "alg": "ES256",
                    "publicKey": pubJwk,
                    "privateKey": privJwk,
                ] as [String: Any],
            ]
        }

        // Preserve all metadata fields from the original entry (if this
        // credential already existed in the loaded container); fall back to
        // the credential's own saved JSON (parsed) for a credential added
        // THIS session (saveCredential() then export, with no matching entry
        // in the previously-imported container yet) - without this fallback,
        // a freshly-saved batch credential's batchId/instanceId would
        // silently reset to 0 on every export until the container is
        // reloaded once.
        let creds: [[String: Any]] = credentials.map { (id, data) in
            let original = originalCredsById[id]
            let parsed = parseJsonObject(data)
            let format = (original?["format"] as? String) ?? (parsed?["format"] as? String) ?? ""
            let kid = (original?["kid"] as? String) ?? (parsed?["kid"] as? String) ?? ""
            let instanceId = Self.asInt(original?["instanceId"]) ?? Self.asInt(parsed?["instance_id"]) ?? 0
            let batchId = Self.asInt64(original?["batchId"]) ?? Self.asInt64(parsed?["batch_id"]) ?? 0
            let issuerIdent = (original?["credentialIssuerIdentifier"] as? String)
                ?? (parsed?["credential_issuer_identifier"] as? String) ?? ""
            let configId = (original?["credentialConfigurationId"] as? String)
                ?? (parsed?["credential_configuration_id"] as? String) ?? ""
            let credData = (original?["data"] as? String) ?? (parsed?["raw"] as? String) ?? data
            let entry: [String: Any] = [
                "credentialId": id,
                "format": format,
                "data": credData,
                "kid": kid,
                "instanceId": instanceId,
                "batchId": batchId,
                "credentialIssuerIdentifier": issuerIdent,
                "credentialConfigurationId": configId,
            ]
            return entry
        }

        // presentations is privatedata-spec's normative S.presentations[]
        // (wallet-frontend's WalletStatePresentation) - genuinely built from
        // the in-memory presentationRecords map, not passed through verbatim,
        // so a presentation recorded THIS session actually survives
        // export/reload (see savePresentationRecord). transactionId has no
        // PresentationRecord counterpart (see its doc comment) - each
        // Swift-recorded presentation is treated as its own single-VP
        // transaction, reusing the same id for both fields. `data` (the raw
        // VP) isn't captured at PresentationRecord construction time
        // (recorded at credential-selection time, before the VP is actually
        // signed) - written as "" rather than restructuring that flow, a
        // known, deliberate gap.
        let presentations: [[String: Any]] = presentationRecords.map { (id, data) in
            let parsed = parseJsonObject(data)
            let usedCredentialIds = (parsed?["credential_ids"] as? [Any])?.compactMap { Self.asInt64($0) } ?? []
            let timestampMillis = Self.asInt64(parsed?["timestamp"]) ?? 0
            let audience = (parsed?["verifier_name"] as? String) ?? ""

            return [
                "presentationId": id,
                "transactionId": id,
                "data": "",
                "usedCredentialIds": usedCredentialIds,
                "presentationTimestampSeconds": timestampMillis / 1000,
                "audience": audience,
            ] as [String: Any]
        }

        let lastEventHash = existingState?["lastEventHash"] as? String ?? ""
        let events = existingState?["events"] as? [Any] ?? []
        let settings = existingS?["settings"] as? [String: Any] ?? [
            "openidRefreshTokenMaxAgeInSeconds": "0",
        ]
        let credentialIssuanceSessions = existingS?["credentialIssuanceSessions"] as? [Any] ?? []

        return [
            "lastEventHash": lastEventHash,
            "events": events,
            "S": [
                "schemaVersion": 3,
                "keypairs": keypairs,
                "credentials": creds,
                "presentations": presentations,
                "settings": settings,
                "credentialIssuanceSessions": credentialIssuanceSessions,
            ] as [String: Any],
        ]
    }

    // MARK: - JWE encrypt/decrypt (A256GCMKW / A256GCM)

    /// Decrypt a JWE compact serialization using A256GCMKW / A256GCM.
    private func decryptJwe(_ jweString: String, mainKey: SymmetricKey) throws -> [String: Any] {
        let parts = jweString.split(separator: ".").map(String.init)
        guard parts.count == 5 else {
            throw KeystoreError.invalidContainer("JWE must have 5 parts")
        }

        let headerData = EncryptedContainer.base64UrlDecode(parts[0])
        let encryptedKeyData = EncryptedContainer.base64UrlDecode(parts[1])
        let ivData = EncryptedContainer.base64UrlDecode(parts[2])
        let ciphertextData = EncryptedContainer.base64UrlDecode(parts[3])
        let tagData = EncryptedContainer.base64UrlDecode(parts[4])

        guard let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any] else {
            throw KeystoreError.invalidContainer("Invalid JWE header")
        }

        // Extract the IV from the header for key unwrapping (A256GCMKW)
        guard let headerIv = header["iv"] as? String,
              let headerTag = header["tag"] as? String else {
            throw KeystoreError.invalidContainer("Missing iv/tag in JWE header for A256GCMKW")
        }

        let kwIv = EncryptedContainer.base64UrlDecode(headerIv)
        let kwTag = EncryptedContainer.base64UrlDecode(headerTag)

        // Unwrap the Content Encryption Key (CEK) using A256GCMKW
        let kwNonce = try AES.GCM.Nonce(data: kwIv)
        let kwSealedBox = try AES.GCM.SealedBox(nonce: kwNonce, ciphertext: encryptedKeyData, tag: kwTag)
        let cekData = try AES.GCM.open(kwSealedBox, using: mainKey)
        let cek = SymmetricKey(data: cekData)

        // Decrypt content with A256GCM using the CEK
        let contentNonce = try AES.GCM.Nonce(data: ivData)
        // AAD = base64url-encoded protected header
        let aadData = Data(parts[0].utf8)
        let contentSealedBox = try AES.GCM.SealedBox(
            nonce: contentNonce,
            ciphertext: ciphertextData,
            tag: tagData
        )
        let plaintext = try AES.GCM.open(contentSealedBox, using: cek, authenticating: aadData)

        guard let json = try JSONSerialization.jsonObject(with: plaintext) as? [String: Any] else {
            throw KeystoreError.invalidContainer("JWE payload is not valid JSON object")
        }
        return json
    }

    /// Encrypt a payload as JWE compact serialization using A256GCMKW / A256GCM.
    private func encryptJwe(_ plaintext: Data, mainKey: SymmetricKey) throws -> String {
        // Generate a random CEK (256-bit)
        var cekBytes = Data(count: 32)
        // swiftlint:disable:next force_unwrapping
        cekBytes.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        let cek = SymmetricKey(data: cekBytes)

        // Wrap CEK with A256GCMKW
        let kwNonce = AES.GCM.Nonce()
        let kwSealed = try AES.GCM.seal(cekBytes, using: mainKey, nonce: kwNonce)
        let encryptedKey = kwSealed.ciphertext
        let kwIv = Data(kwNonce)
        let kwTag = kwSealed.tag

        // Build JWE header
        let headerObj: [String: Any] = [
            "alg": "A256GCMKW",
            "enc": "A256GCM",
            "iv": EncryptedContainer.base64UrlEncode(kwIv),
            "tag": EncryptedContainer.base64UrlEncode(kwTag),
        ]
        let headerData = try JSONSerialization.data(withJSONObject: headerObj)
        let headerB64 = EncryptedContainer.base64UrlEncode(headerData)

        // Encrypt content with A256GCM
        let contentNonce = AES.GCM.Nonce()
        let aad = Data(headerB64.utf8)
        let sealed = try AES.GCM.seal(plaintext, using: cek, nonce: contentNonce, authenticating: aad)

        let parts = [
            headerB64,
            EncryptedContainer.base64UrlEncode(encryptedKey),
            EncryptedContainer.base64UrlEncode(Data(contentNonce)),
            EncryptedContainer.base64UrlEncode(sealed.ciphertext),
            EncryptedContainer.base64UrlEncode(sealed.tag),
        ]
        return parts.joined(separator: ".")
    }

    #else
    // Stub for non-Apple platforms where CryptoKit is unavailable
    public init() {}
    public var isUnlocked: Bool { false }
    public func unlock(prfOutput: Data, encryptedContainer: Data, hkdfSalt: Data, hkdfInfo: Data) async throws {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func lock() {}
    public func generateKey(algorithm: String = "ES256") async throws -> String {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func sign(keyId: String, payload: Data, algorithm: String = "ES256") async throws -> Data {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func generateProof(audience: String, nonce: String, freshKey: Bool) async throws -> String {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func signVpToken(credential: String, disclosedClaims: [String]?, nonce: String, audience: String, kid: String?) async throws -> String {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func exportEncryptedContainer() async throws -> Data {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func listKeys() -> [KeyInfo] { [] }
    public func saveCredential(id: Int64, json: String) async throws {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func getCredential(id: Int64) async throws -> String? {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func getAllCredentials() async throws -> [Int64: String] {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func deleteCredential(id: Int64) async throws {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func clearCredentials() async throws {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func savePresentationRecord(id: Int64, json: String) async throws {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func getAllPresentationRecords() async throws -> [Int64: String] {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func clearPresentationRecords() async throws {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func generateKeypairs(count: Int) async throws -> [KeypairInfo] {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    #endif
}

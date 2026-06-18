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
    private var credentials: [String: String] = [:]
    private var _mainKey: SymmetricKey?
    private var containerMetadata: ContainerData?

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

            let prfKeyInfo = container.prfKeys.first(where: { $0.hkdfSalt == hkdfSalt })
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
        defer { self.mutex.unlock() }
        keys.removeAll()
        credentials.removeAll()
        _mainKey = nil
        containerMetadata = nil
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

    public func generateProof(audience: String, nonce: String) async throws -> String {
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

    public func signPresentation(nonce: String, audience: String, credentialIds: [String]) async throws -> String {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()

        let key: P256.Signing.PrivateKey
        let keyId: String
        if let first = keys.first {
            keyId = first.key
            key = first.value
        } else {
            keyId = UUID().uuidString.lowercased()
            let newKey = P256.Signing.PrivateKey()
            keys[keyId] = newKey
            key = newKey
        }

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
        audience: String
    ) async throws -> String {
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

    public func saveCredential(id: String, json: String) async throws {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        credentials[id] = json
    }

    public func getCredential(id: String) async throws -> String? {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        return credentials[id]
    }

    public func getAllCredentials() async throws -> [String: String] {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        return credentials
    }

    public func deleteCredential(id: String) async throws {
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

    // MARK: - Private helpers

    private func requireUnlocked() throws {
        guard _mainKey != nil else {
            throw KeystoreError.locked
        }
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

        if let credsArray = state["credentials"] as? [[String: Any]] {
            for entry in credsArray {
                guard let credId = entry["credentialId"] as? String,
                      let data = entry["data"] as? String else { continue }
                credentials[credId] = data
            }
        }
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
        if let creds = json["credentials"] as? [String: String] {
            credentials = creds
        }
    }

    private func buildWalletStateV3() -> [String: Any] {
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
            return [
                "kid": kid,
                "keypair": [
                    "kid": kid,
                    "did": "",
                    "alg": "ES256",
                    "publicKey": pubJwk,
                    "privateKey": privJwk,
                ] as [String: Any],
            ]
        }

        let creds: [[String: Any]] = credentials.map { (id, data) in
            [
                "credentialId": id,
                "format": "",
                "data": data,
                "kid": "",
                "instanceId": 0,
                "batchId": 0,
                "credentialIssuerIdentifier": "",
                "credentialConfigurationId": "",
            ] as [String: Any]
        }

        return [
            "lastEventHash": "",
            "events": [] as [Any],
            "S": [
                "schemaVersion": 3,
                "keypairs": keypairs,
                "credentials": creds,
                "presentations": [] as [Any],
                "settings": [
                    "openidRefreshTokenMaxAgeInSeconds": "",
                ],
                "credentialIssuanceSessions": [] as [Any],
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
    public func generateProof(audience: String, nonce: String) async throws -> String {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func signPresentation(nonce: String, audience: String, credentialIds: [String]) async throws -> String {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func signVpToken(credential: String, disclosedClaims: [String]?, nonce: String, audience: String) async throws -> String {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func exportEncryptedContainer() async throws -> Data {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func listKeys() -> [KeyInfo] { [] }
    public func saveCredential(id: String, json: String) async throws {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func getCredential(id: String) async throws -> String? {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func getAllCredentials() async throws -> [String: String] {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func deleteCredential(id: String) async throws {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func clearCredentials() async throws {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func generateKeypairs(count: Int) async throws -> [KeypairInfo] {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    #endif
}

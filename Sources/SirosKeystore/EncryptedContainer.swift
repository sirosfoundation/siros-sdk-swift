// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(CommonCrypto)
import CommonCrypto
#endif

/// Kotlin model of the wallet-frontend's `EncryptedContainer` format.
///
/// Enables cross-platform interoperability: the same encrypted private data
/// can be decrypted by both the Swift iOS SDK and the TypeScript web wallet,
/// provided the same passkey PRF is used.
public enum EncryptedContainer {

    // MARK: - Parsing & Serialization

    /// Parse a serialized encrypted container from the backend.
    public static func parse(_ data: Data) throws -> ContainerData {
        guard let text = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
              let jsonData = text.data(using: .utf8),
              let root = try JSONSerialization.jsonObject(with: jsonData) as? [String: Any] else {
            throw KeystoreError.invalidContainer("Cannot parse container JSON")
        }
        return try parseContainer(root)
    }

    /// Serialize a container to the format expected by the backend.
    public static func serialize(_ container: ContainerData) throws -> Data {
        let obj = serializeContainer(container)
        return try JSONSerialization.data(withJSONObject: obj)
    }

    // MARK: - Crypto operations

    #if canImport(CryptoKit)

    /// Derive the PRF wrapping key using HKDF-SHA256.
    public static func derivePrfKey(prfOutput: Data, hkdfSalt: Data, hkdfInfo: Data) -> SymmetricKey {
        let inputKey = SymmetricKey(data: prfOutput)
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKey,
            salt: hkdfSalt,
            info: hkdfInfo,
            outputByteCount: 32
        )
        return derived
    }

    /// Unwrap the main encryption key from a V2 PRF key entry using ECDH.
    public static func unwrapMainKey(
        prfKey: SymmetricKey,
        prfKeyInfo: PrfKeyInfo,
        mainKeyInfo: MainKeyInfo
    ) throws -> SymmetricKey {
        // Step 1: Unwrap the ECDH private key using AES-GCM
        let ecdhPrivateKey = try unwrapEcdhPrivateKey(
            wrappingKey: prfKey,
            privateKeyInfo: prfKeyInfo.keypair.privateKey
        )

        // Step 2: Import mainKey's ephemeral public key
        let ecdhPublicKey = try P256.KeyAgreement.PublicKey(
            x963Representation: mainKeyInfo.publicKey.importKey.keyData
        )

        // Step 3: ECDH key agreement
        let sharedSecret = try ecdhPrivateKey.sharedSecretFromKeyAgreement(with: ecdhPublicKey)
        let aesKwKeyData = sharedSecret.withUnsafeBytes { Data($0) }
        let aesKwKey = SymmetricKey(data: aesKwKeyData.prefix(32))

        // Step 4: AES-KW unwrap the main key
        let unwrappedKeyData = try aesKeyUnwrap(
            kek: aesKwKey,
            wrappedKey: prfKeyInfo.unwrapKey.wrappedKey
        )
        return SymmetricKey(data: unwrappedKeyData)
    }

    /// Wrap a main key for a PRF key entry using ECDH key encapsulation.
    public static func wrapMainKey(
        prfKey: SymmetricKey,
        mainKey: SymmetricKey,
        mainKeyInfo: MainKeyInfo
    ) throws -> PrfKeyEncapsulation {
        // Step 1: Generate a fresh ECDH keypair
        let ecdhPrivateKey = P256.KeyAgreement.PrivateKey()
        let ecdhPublicKey = ecdhPrivateKey.publicKey
        let publicKeyBytes = ecdhPublicKey.x963Representation

        // Step 2: Wrap the ECDH private key with the PRF key using AES-GCM
        let privateKeyJwk = exportEcPrivateKeyJwk(ecdhPrivateKey)
        let nonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(privateKeyJwk, using: prfKey, nonce: nonce)
        let wrappedPrivateKey = sealedBox.ciphertext + sealedBox.tag
        let iv = Data(nonce)

        // Step 3: ECDH agreement with mainKey's public key → AES-KW
        let mainPublicKey = try P256.KeyAgreement.PublicKey(
            x963Representation: mainKeyInfo.publicKey.importKey.keyData
        )
        let sharedSecret = try ecdhPrivateKey.sharedSecretFromKeyAgreement(with: mainPublicKey)
        let aesKwKeyData = sharedSecret.withUnsafeBytes { Data($0) }
        let aesKwKey = SymmetricKey(data: aesKwKeyData.prefix(32))

        // Step 4: AES-KW wrap the main key
        let mainKeyData = mainKey.withUnsafeBytes { Data($0) }
        let wrappedMainKey = try aesKeyWrap(kek: aesKwKey, keyToWrap: mainKeyData)

        return PrfKeyEncapsulation(
            keypair: EncapsulationKeypairInfo(
                publicKey: EncapsulationPublicKeyInfo(
                    importKey: ImportKeyInfo(
                        format: "raw",
                        keyData: publicKeyBytes,
                        algorithm: EcKeyAlgorithm(name: "ECDH", namedCurve: "P-256")
                    )
                ),
                privateKey: EncapsulationPrivateKeyInfo(
                    unwrapKey: PrivateKeyUnwrapInfo(
                        format: "jwk",
                        wrappedKey: wrappedPrivateKey,
                        unwrapAlgo: AesGcmAlgo(name: "AES-GCM", iv: iv),
                        unwrappedKeyAlgo: EcKeyAlgorithm(name: "ECDH", namedCurve: "P-256")
                    )
                )
            ),
            unwrapKey: StaticUnwrapKeyInfo(
                wrappedKey: wrappedMainKey,
                unwrappingKey: UnwrappingKeyInfo(
                    deriveKey: DeriveKeyInfo(
                        algorithm: AlgorithmName(name: "ECDH"),
                        derivedKeyAlgorithm: AesKwAlgorithm(name: "AES-KW", length: 256)
                    )
                )
            )
        )
    }

    /// Generate a fresh main key and its ephemeral ECDH public key info.
    public static func generateMainKey() -> (SymmetricKey, MainKeyInfo) {
        var keyBytes = Data(count: 32)
        keyBytes.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        let mainKey = SymmetricKey(data: keyBytes)

        let ecdhPrivateKey = P256.KeyAgreement.PrivateKey()
        let publicKeyBytes = ecdhPrivateKey.publicKey.x963Representation

        let info = MainKeyInfo(
            publicKey: EncapsulationPublicKeyInfo(
                importKey: ImportKeyInfo(
                    format: "raw",
                    keyData: publicKeyBytes,
                    algorithm: EcKeyAlgorithm(name: "ECDH", namedCurve: "P-256")
                )
            ),
            unwrapKey: MainUnwrapKeyInfo(
                format: "raw",
                unwrapAlgo: "AES-KW",
                unwrappedKeyAlgo: AesGcmKeyAlgorithm(name: "AES-GCM", length: 256)
            )
        )
        return (mainKey, info)
    }

    /// Encrypt data with AES-GCM using the given key.
    public static func aesGcmEncrypt(key: SymmetricKey, plaintext: Data) throws -> (ciphertext: Data, nonce: Data) {
        let nonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(plaintext, using: key, nonce: nonce)
        return (sealedBox.ciphertext + sealedBox.tag, Data(nonce))
    }

    /// Decrypt data with AES-GCM using the given key and IV.
    public static func aesGcmDecrypt(key: SymmetricKey, iv: Data, ciphertext: Data) throws -> Data {
        let nonce = try AES.GCM.Nonce(data: iv)
        // Ciphertext includes the 16-byte tag appended
        let tagLength = 16
        guard ciphertext.count > tagLength else {
            throw KeystoreError.cryptoError("Ciphertext too short")
        }
        let ct = ciphertext.prefix(ciphertext.count - tagLength)
        let tag = ciphertext.suffix(tagLength)
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ct, tag: tag)
        return try AES.GCM.open(sealedBox, using: key)
    }

    // MARK: - Private crypto helpers

    private static func unwrapEcdhPrivateKey(
        wrappingKey: SymmetricKey,
        privateKeyInfo: EncapsulationPrivateKeyInfo
    ) throws -> P256.KeyAgreement.PrivateKey {
        let unwrapInfo = privateKeyInfo.unwrapKey
        let jwkBytes = try aesGcmDecrypt(
            key: wrappingKey,
            iv: unwrapInfo.unwrapAlgo.iv,
            ciphertext: unwrapInfo.wrappedKey
        )
        guard let jwkString = String(data: jwkBytes, encoding: .utf8),
              let jwkData = jwkString.data(using: .utf8),
              let jwk = try JSONSerialization.jsonObject(with: jwkData) as? [String: Any],
              let dStr = jwk["d"] as? String else {
            throw KeystoreError.cryptoError("Invalid JWK for ECDH private key")
        }
        let dData = base64UrlDecode(dStr)
        guard let xStr = jwk["x"] as? String, let yStr = jwk["y"] as? String else {
            throw KeystoreError.cryptoError("Missing x/y in JWK")
        }
        let xData = base64UrlDecode(xStr)
        let yData = base64UrlDecode(yStr)

        // x963 representation: 0x04 || x || y || d (for private key import we use raw representation)
        // P256.KeyAgreement.PrivateKey expects raw scalar
        return try P256.KeyAgreement.PrivateKey(rawRepresentation: dData)
    }

    private static func exportEcPrivateKeyJwk(_ privateKey: P256.KeyAgreement.PrivateKey) -> Data {
        let publicKey = privateKey.publicKey
        let x963 = publicKey.x963Representation
        let x = x963[1..<33]
        let y = x963[33..<65]
        let d = privateKey.rawRepresentation

        let jwk: [String: Any] = [
            "kty": "EC",
            "crv": "P-256",
            "x": base64UrlEncode(x),
            "y": base64UrlEncode(y),
            "d": base64UrlEncode(d),
            "key_ops": ["deriveKey"],
            "ext": true,
        ]
        return (try? JSONSerialization.data(withJSONObject: jwk)) ?? Data()
    }

    // MARK: - AES Key Wrap (RFC 3394)

    /// AES Key Wrap per RFC 3394.
    static func aesKeyWrap(kek: SymmetricKey, keyToWrap: Data) throws -> Data {
        guard keyToWrap.count % 8 == 0, keyToWrap.count >= 16 else {
            throw KeystoreError.cryptoError("Key to wrap must be multiple of 8 bytes and >= 16")
        }
        let n = keyToWrap.count / 8
        var a: UInt64 = 0xA6A6A6A6A6A6A6A6
        var r = (0..<n).map { i in
            Array(keyToWrap[(i*8)..<(i*8+8)])
        }

        let kekData = symmetricKeyBytes(kek)

        for j in 0..<6 {
            for i in 0..<n {
                var block = Data(count: 16)
                withUnsafeBytes(of: a.bigEndian) { block.replaceSubrange(0..<8, with: $0) }
                block.replaceSubrange(8..<16, with: r[i])

                let encrypted = try aesEcbEncrypt(key: kekData, data: block)

                let t = UInt64(n * j + i + 1)
                var aBytes = Array(encrypted.prefix(8))
                var tBytes = [UInt8](repeating: 0, count: 8)
                withUnsafeBytes(of: t.bigEndian) { ptr in
                    for k in 0..<8 { tBytes[k] = ptr[k] }
                }
                for k in 0..<8 { aBytes[k] ^= tBytes[k] }
                a = aBytes.withUnsafeBytes { $0.load(as: UInt64.self) }.bigEndian

                r[i] = Array(encrypted.suffix(8))
            }
        }

        var result = Data(count: 8 + n * 8)
        withUnsafeBytes(of: a.bigEndian) { result.replaceSubrange(0..<8, with: $0) }
        for i in 0..<n {
            result.replaceSubrange((8 + i*8)..<(8 + i*8 + 8), with: r[i])
        }
        return result
    }

    /// AES Key Unwrap per RFC 3394.
    static func aesKeyUnwrap(kek: SymmetricKey, wrappedKey: Data) throws -> Data {
        guard wrappedKey.count % 8 == 0, wrappedKey.count >= 24 else {
            throw KeystoreError.cryptoError("Wrapped key must be multiple of 8 bytes and >= 24")
        }
        let n = wrappedKey.count / 8 - 1
        var a = wrappedKey.prefix(8).withUnsafeBytes { $0.load(as: UInt64.self) }.bigEndian
        var r = (0..<n).map { i in
            Array(wrappedKey[(8 + i*8)..<(8 + i*8 + 8)])
        }

        let kekData = symmetricKeyBytes(kek)

        for j in stride(from: 5, through: 0, by: -1) {
            for i in stride(from: n - 1, through: 0, by: -1) {
                let t = UInt64(n * j + i + 1)
                var aBytes = [UInt8](repeating: 0, count: 8)
                withUnsafeBytes(of: a.bigEndian) { ptr in
                    for k in 0..<8 { aBytes[k] = ptr[k] }
                }
                var tBytes = [UInt8](repeating: 0, count: 8)
                withUnsafeBytes(of: t.bigEndian) { ptr in
                    for k in 0..<8 { tBytes[k] = ptr[k] }
                }
                for k in 0..<8 { aBytes[k] ^= tBytes[k] }

                var block = Data(count: 16)
                block.replaceSubrange(0..<8, with: aBytes)
                block.replaceSubrange(8..<16, with: r[i])

                let decrypted = try aesEcbDecrypt(key: kekData, data: block)

                a = decrypted.prefix(8).withUnsafeBytes { $0.load(as: UInt64.self) }.bigEndian
                r[i] = Array(decrypted.suffix(8))
            }
        }

        guard a == 0xA6A6A6A6A6A6A6A6 else {
            throw KeystoreError.cryptoError("AES Key Unwrap integrity check failed")
        }

        var result = Data()
        for block in r { result.append(contentsOf: block) }
        return result
    }

    private static func symmetricKeyBytes(_ key: SymmetricKey) -> Data {
        key.withUnsafeBytes { ptr in Data(ptr) }
    }

    // AES ECB for key wrap (single block) - uses CommonCrypto on Apple
    private static func aesEcbEncrypt(key: Data, data: Data) throws -> Data {
        return try aesEcbCrypt(key: key, data: data, encrypt: true)
    }

    private static func aesEcbDecrypt(key: Data, data: Data) throws -> Data {
        return try aesEcbCrypt(key: key, data: data, encrypt: false)
    }

    // MARK: - AES ECB implementation

    private static func aesEcbCrypt(key: Data, data: Data, encrypt: Bool) throws -> Data {
        #if canImport(CommonCrypto)
        var outLength = 0
        var outData = Data(count: data.count + 16)
        let status = outData.withUnsafeMutableBytes { outPtr in
            data.withUnsafeBytes { dataPtr in
                key.withUnsafeBytes { keyPtr in
                    CCCrypt(
                        encrypt ? UInt32(kCCEncrypt) : UInt32(kCCDecrypt),
                        UInt32(kCCAlgorithmAES),
                        UInt32(kCCOptionECBMode),
                        keyPtr.baseAddress, key.count,
                        nil,
                        dataPtr.baseAddress, data.count,
                        outPtr.baseAddress, outData.count,
                        &outLength
                    )
                }
            }
        }
        guard status == 0 else {
            throw KeystoreError.cryptoError("AES ECB failed: \(status)")
        }
        return outData.prefix(outLength)
        #else
        throw KeystoreError.cryptoError("AES ECB requires CommonCrypto (Apple platforms only)")
        #endif
    }

    #endif // canImport(CryptoKit)

    // MARK: - Base64URL helpers

    static func base64UrlEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func base64UrlEncode(_ data: any ContiguousBytes) -> String {
        let d = data.withUnsafeBytes { Data($0) }
        return base64UrlEncode(d)
    }

    static func base64UrlDecode(_ string: String) -> Data {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder != 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        return Data(base64Encoded: base64) ?? Data()
    }

    // MARK: - Container JSON parsing

    private static func parseContainer(_ obj: [String: Any]) throws -> ContainerData {
        guard let jwe = obj["jwe"] as? String else {
            throw KeystoreError.invalidContainer("Missing jwe field")
        }
        let mainKey = (obj["mainKey"] as? [String: Any]).flatMap { try? parseMainKeyInfo($0) }
        let prfKeys: [PrfKeyInfo]
        if let arr = obj["prfKeys"] as? [[String: Any]] {
            prfKeys = arr.compactMap { try? parsePrfKeyInfo($0) }
        } else {
            prfKeys = []
        }
        return ContainerData(jwe: jwe, mainKey: mainKey, prfKeys: prfKeys)
    }

    private static func parseMainKeyInfo(_ obj: [String: Any]) throws -> MainKeyInfo {
        guard let publicKey = obj["publicKey"] as? [String: Any],
              let importKey = publicKey["importKey"] as? [String: Any],
              let unwrapKey = obj["unwrapKey"] as? [String: Any] else {
            throw KeystoreError.invalidContainer("Invalid mainKey structure")
        }
        return MainKeyInfo(
            publicKey: EncapsulationPublicKeyInfo(
                importKey: try parseImportKeyInfo(importKey)
            ),
            unwrapKey: MainUnwrapKeyInfo(
                format: unwrapKey["format"] as? String ?? "raw",
                unwrapAlgo: unwrapKey["unwrapAlgo"] as? String ?? "AES-KW",
                unwrappedKeyAlgo: parseAesGcmKeyAlgorithm(unwrapKey["unwrappedKeyAlgo"] as? [String: Any])
            )
        )
    }

    private static func parseImportKeyInfo(_ obj: [String: Any]) throws -> ImportKeyInfo {
        let keyData = decodeBinaryField(obj["keyData"])
        let algo = obj["algorithm"] as? [String: Any]
        return ImportKeyInfo(
            format: obj["format"] as? String ?? "raw",
            keyData: keyData,
            algorithm: EcKeyAlgorithm(
                name: algo?["name"] as? String ?? "ECDH",
                namedCurve: algo?["namedCurve"] as? String ?? "P-256"
            )
        )
    }

    private static func parsePrfKeyInfo(_ obj: [String: Any]) throws -> PrfKeyInfo {
        let credentialId = decodeBinaryField(obj["credentialId"])
        let prfSalt = decodeBinaryField(obj["prfSalt"])
        let hkdfSalt = decodeBinaryField(obj["hkdfSalt"])
        let hkdfInfo = decodeBinaryField(obj["hkdfInfo"])
        let transports = obj["transports"] as? [String]
        let algorithm = (obj["algorithm"] as? [String: Any]).map { parseAesGcmKeyAlgorithm($0) }

        guard let keypairObj = obj["keypair"] as? [String: Any],
              let unwrapKeyObj = obj["unwrapKey"] as? [String: Any] else {
            throw KeystoreError.invalidContainer("Missing keypair or unwrapKey in PRF key")
        }

        return PrfKeyInfo(
            credentialId: credentialId,
            transports: transports,
            prfSalt: prfSalt,
            hkdfSalt: hkdfSalt,
            hkdfInfo: hkdfInfo,
            algorithm: algorithm,
            keypair: try parseEncapsulationKeypair(keypairObj),
            unwrapKey: try parseStaticUnwrapKey(unwrapKeyObj)
        )
    }

    private static func parseEncapsulationKeypair(_ obj: [String: Any]) throws -> EncapsulationKeypairInfo {
        guard let pubObj = (obj["publicKey"] as? [String: Any])?["importKey"] as? [String: Any],
              let privObj = (obj["privateKey"] as? [String: Any])?["unwrapKey"] as? [String: Any] else {
            throw KeystoreError.invalidContainer("Invalid encapsulation keypair")
        }
        let privAlgoObj = privObj["unwrapAlgo"] as? [String: Any]
        let privKeyAlgoObj = privObj["unwrappedKeyAlgo"] as? [String: Any]

        return EncapsulationKeypairInfo(
            publicKey: EncapsulationPublicKeyInfo(importKey: try parseImportKeyInfo(pubObj)),
            privateKey: EncapsulationPrivateKeyInfo(
                unwrapKey: PrivateKeyUnwrapInfo(
                    format: privObj["format"] as? String ?? "jwk",
                    wrappedKey: decodeBinaryField(privObj["wrappedKey"]),
                    unwrapAlgo: AesGcmAlgo(
                        name: privAlgoObj?["name"] as? String ?? "AES-GCM",
                        iv: decodeBinaryField(privAlgoObj?["iv"])
                    ),
                    unwrappedKeyAlgo: EcKeyAlgorithm(
                        name: privKeyAlgoObj?["name"] as? String ?? "ECDH",
                        namedCurve: privKeyAlgoObj?["namedCurve"] as? String ?? "P-256"
                    )
                )
            )
        )
    }

    private static func parseStaticUnwrapKey(_ obj: [String: Any]) throws -> StaticUnwrapKeyInfo {
        let wrappedKey = decodeBinaryField(obj["wrappedKey"])
        guard let unwrappingKey = obj["unwrappingKey"] as? [String: Any],
              let deriveKey = unwrappingKey["deriveKey"] as? [String: Any] else {
            throw KeystoreError.invalidContainer("Invalid staticUnwrapKey")
        }
        let algoObj = deriveKey["algorithm"] as? [String: Any]
        let derivedAlgoObj = deriveKey["derivedKeyAlgorithm"] as? [String: Any]

        return StaticUnwrapKeyInfo(
            wrappedKey: wrappedKey,
            unwrappingKey: UnwrappingKeyInfo(
                deriveKey: DeriveKeyInfo(
                    algorithm: AlgorithmName(name: algoObj?["name"] as? String ?? "ECDH"),
                    derivedKeyAlgorithm: AesKwAlgorithm(
                        name: derivedAlgoObj?["name"] as? String ?? "AES-KW",
                        length: derivedAlgoObj?["length"] as? Int ?? 256
                    )
                )
            )
        )
    }

    private static func parseAesGcmKeyAlgorithm(_ obj: [String: Any]?) -> AesGcmKeyAlgorithm {
        AesGcmKeyAlgorithm(
            name: obj?["name"] as? String ?? "AES-GCM",
            length: obj?["length"] as? Int ?? 256
        )
    }

    // MARK: - Container JSON serialization

    private static func serializeContainer(_ container: ContainerData) -> [String: Any] {
        var obj: [String: Any] = [:]
        if let mainKey = container.mainKey {
            obj["mainKey"] = serializeMainKeyInfo(mainKey)
        }
        obj["prfKeys"] = container.prfKeys.map { serializePrfKeyInfo($0) }
        obj["jwe"] = container.jwe
        return obj
    }

    private static func serializeMainKeyInfo(_ info: MainKeyInfo) -> [String: Any] {
        [
            "publicKey": [
                "importKey": serializeImportKeyInfo(info.publicKey.importKey)
            ],
            "unwrapKey": [
                "format": info.unwrapKey.format,
                "unwrapAlgo": info.unwrapKey.unwrapAlgo,
                "unwrappedKeyAlgo": [
                    "name": info.unwrapKey.unwrappedKeyAlgo.name,
                    "length": info.unwrapKey.unwrappedKeyAlgo.length,
                ] as [String: Any],
            ] as [String: Any],
        ]
    }

    private static func serializeImportKeyInfo(_ info: ImportKeyInfo) -> [String: Any] {
        [
            "format": info.format,
            "keyData": encodeBinaryField(info.keyData),
            "algorithm": [
                "name": info.algorithm.name,
                "namedCurve": info.algorithm.namedCurve,
            ],
        ]
    }

    private static func serializePrfKeyInfo(_ info: PrfKeyInfo) -> [String: Any] {
        var obj: [String: Any] = [
            "credentialId": encodeBinaryField(info.credentialId),
            "prfSalt": encodeBinaryField(info.prfSalt),
            "hkdfSalt": encodeBinaryField(info.hkdfSalt),
            "hkdfInfo": encodeBinaryField(info.hkdfInfo),
            "keypair": serializeEncapsulationKeypair(info.keypair),
            "unwrapKey": serializeStaticUnwrapKey(info.unwrapKey),
        ]
        if let transports = info.transports {
            obj["transports"] = transports
        }
        if let algo = info.algorithm {
            obj["algorithm"] = ["name": algo.name, "length": algo.length] as [String: Any]
        }
        return obj
    }

    private static func serializeEncapsulationKeypair(_ info: EncapsulationKeypairInfo) -> [String: Any] {
        [
            "publicKey": ["importKey": serializeImportKeyInfo(info.publicKey.importKey)],
            "privateKey": [
                "unwrapKey": [
                    "format": info.privateKey.unwrapKey.format,
                    "wrappedKey": encodeBinaryField(info.privateKey.unwrapKey.wrappedKey),
                    "unwrapAlgo": [
                        "name": info.privateKey.unwrapKey.unwrapAlgo.name,
                        "iv": encodeBinaryField(info.privateKey.unwrapKey.unwrapAlgo.iv),
                    ] as [String: Any],
                    "unwrappedKeyAlgo": [
                        "name": info.privateKey.unwrapKey.unwrappedKeyAlgo.name,
                        "namedCurve": info.privateKey.unwrapKey.unwrappedKeyAlgo.namedCurve,
                    ],
                ] as [String: Any],
            ],
        ]
    }

    private static func serializeStaticUnwrapKey(_ info: StaticUnwrapKeyInfo) -> [String: Any] {
        [
            "wrappedKey": encodeBinaryField(info.wrappedKey),
            "unwrappingKey": [
                "deriveKey": [
                    "algorithm": ["name": info.unwrappingKey.deriveKey.algorithm.name],
                    "derivedKeyAlgorithm": [
                        "name": info.unwrappingKey.deriveKey.derivedKeyAlgorithm.name,
                        "length": info.unwrappingKey.deriveKey.derivedKeyAlgorithm.length,
                    ] as [String: Any],
                ] as [String: Any],
            ],
        ]
    }

    // MARK: - Tagged binary encoding

    private static func decodeBinaryField(_ element: Any?) -> Data {
        if let obj = element as? [String: Any], let b64u = obj["$b64u"] as? String {
            return base64UrlDecode(b64u)
        }
        if let str = element as? String {
            return base64UrlDecode(str)
        }
        return Data()
    }

    private static func encodeBinaryField(_ data: Data) -> [String: String] {
        ["$b64u": base64UrlEncode(data)]
    }
}

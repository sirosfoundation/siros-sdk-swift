// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import XCTest
@testable import SirosKeystore

/// Reads and rewrites a container's plaintext the way a *peer* client would -
/// decrypting here rather than adding test-only accessors to production code.
///
/// Shared by the tests that need to look at (or tamper with) what `JweKeystore`
/// actually wrote, independently of what its accessors report. The JWE
/// encrypt/decrypt in the CryptoKit-gated extension below mirrors
/// `JweKeystore`'s private A256GCMKW/A256GCM implementation; `jsonEqual` has
/// no crypto dependency and stays outside the gate so its own behaviour is
/// tested on every platform.
enum ContainerTestSupport {

    /// Recursive structural equality for heterogeneous JSON trees produced by
    /// `JSONSerialization` ([String: Any], [Any], NSNumber, NSString, NSNull).
    ///
    /// `JSONSerialization` surfaces both numbers and booleans as `NSNumber`,
    /// and `NSNumber == NSNumber` compares by value, so `true` would equal `1`
    /// and `false` would equal `0`. A round-trip test that re-typed a boolean
    /// into a number (or the reverse) would therefore pass. Booleans and
    /// numbers are told apart first and never compare equal to each other.
    static func jsonEqual(_ a: Any?, _ b: Any?) -> Bool {
        switch (a, b) {
        case (nil, nil):
            return true
        case (.some(let a), .some(let b)):
            if let a = a as? [String: Any], let b = b as? [String: Any] {
                guard Set(a.keys) == Set(b.keys) else { return false }
                return a.allSatisfy { key, value in jsonEqual(value, b[key]) }
            }
            if let a = a as? [Any], let b = b as? [Any] {
                guard a.count == b.count else { return false }
                return zip(a, b).allSatisfy { jsonEqual($0, $1) }
            }
            if let a = a as? NSNumber, let b = b as? NSNumber {
                guard isBoolean(a) == isBoolean(b) else { return false }
                return a == b
            }
            if let a = a as? String, let b = b as? String { return a == b }
            if a is NSNull && b is NSNull { return true }
            return false
        default:
            return false
        }
    }

    /// Whether an `NSNumber` out of `JSONSerialization` came from a JSON
    /// boolean rather than a JSON number.
    ///
    /// On Apple platforms JSON booleans are the `CFBoolean` singletons, which
    /// have their own CF type. swift-corelibs-foundation has no CFBoolean, but
    /// its `JSONSerialization` builds booleans as `NSNumber(value: Bool)`,
    /// whose `objCType` is "c" (Int8/BOOL), while every JSON number it produces
    /// is an Int, Int64, UInt64 or Double - none of which encode as "c".
    static func isBoolean(_ number: NSNumber) -> Bool {
        #if canImport(Darwin)
        return CFGetTypeID(number) == CFBooleanGetTypeID()
        #else
        return String(cString: number.objCType) == "c"
        #endif
    }
}

#if canImport(CryptoKit)
import CryptoKit

extension ContainerTestSupport {

    /// Decrypt a container to its plaintext `WalletStateContainer` JSON.
    static func plaintext(of container: Data, prfOutput: Data, hkdfSalt: Data) throws -> [String: Any] {
        let parsed = try EncryptedContainer.parse(container)
        let mainKey = try mainKey(of: parsed, prfOutput: prfOutput, hkdfSalt: hkdfSalt)
        return try decryptJwe(parsed.jwe, mainKey: mainKey)
    }

    /// `S.extensions` straight out of the container, or nil when absent.
    static func extensions(of container: Data, prfOutput: Data, hkdfSalt: Data) throws -> [String: Any]? {
        let state = try plaintext(of: container, prfOutput: prfOutput, hkdfSalt: hkdfSalt)
        return (state["S"] as? [String: Any])?["extensions"] as? [String: Any]
    }

    /// Hand-build a container carrying `plaintextState`, unlockable with the
    /// given PRF material - what an existing account's first unlock on this
    /// device looks like.
    static func buildContainer(prfOutput: Data, hkdfSalt: Data, hkdfInfo: Data, plaintextState: [String: Any]) throws -> Data {
        let (mainKey, mainKeyInfo) = EncryptedContainer.generateMainKey()
        let prfKey = EncryptedContainer.derivePrfKey(prfOutput: prfOutput, hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)
        let encapsulation = try EncryptedContainer.wrapMainKey(prfKey: prfKey, mainKey: mainKey, mainKeyInfo: mainKeyInfo)
        let prfKeyInfo = PrfKeyInfo(
            credentialId: Data("test-credential".utf8),
            transports: nil,
            prfSalt: Data(count: 32),
            hkdfSalt: hkdfSalt,
            hkdfInfo: hkdfInfo,
            algorithm: AesGcmKeyAlgorithm(name: "AES-GCM", length: 256),
            keypair: encapsulation.keypair,
            unwrapKey: encapsulation.unwrapKey
        )
        let jwe = try encryptJwe(plaintextState, mainKey: mainKey)
        return try EncryptedContainer.serialize(ContainerData(jwe: jwe, mainKey: mainKeyInfo, prfKeys: [prfKeyInfo]))
    }

    /// Rewrite the plaintext inside an existing container and re-encrypt it
    /// under the same main key, so a test can present the keystore with a
    /// shape only a peer client would have written.
    static func rewrite(
        _ container: Data,
        prfOutput: Data,
        hkdfSalt: Data,
        transform: (inout [String: Any]) -> Void
    ) throws -> Data {
        var parsed = try EncryptedContainer.parse(container)
        let mainKey = try mainKey(of: parsed, prfOutput: prfOutput, hkdfSalt: hkdfSalt)
        var state = try decryptJwe(parsed.jwe, mainKey: mainKey)
        transform(&state)
        parsed.jwe = try encryptJwe(state, mainKey: mainKey)
        return try EncryptedContainer.serialize(parsed)
    }

    /// Rewrite only `S.extensions`, keeping everything else in place.
    /// `transform` receives the existing namespaces (or an empty object).
    static func rewriteExtensions(
        _ container: Data,
        prfOutput: Data,
        hkdfSalt: Data,
        transform: (inout [String: Any]) -> Void
    ) throws -> Data {
        try rewrite(container, prfOutput: prfOutput, hkdfSalt: hkdfSalt) { state in
            var s = state["S"] as? [String: Any] ?? [:]
            var extensions = s["extensions"] as? [String: Any] ?? [:]
            transform(&extensions)
            s["extensions"] = extensions
            state["S"] = s
        }
    }

    // MARK: - Internals

    private static func mainKey(of parsed: ContainerData, prfOutput: Data, hkdfSalt: Data) throws -> SymmetricKey {
        guard let mainKeyInfo = parsed.mainKey else {
            throw KeystoreError.invalidContainer("missing mainKey")
        }
        guard let prfKeyInfo = parsed.prfKeys.first(where: { $0.hkdfSalt == hkdfSalt }) ?? parsed.prfKeys.first else {
            throw KeystoreError.invalidContainer("missing prfKeys entry")
        }
        let prfKey = EncryptedContainer.derivePrfKey(prfOutput: prfOutput, hkdfSalt: prfKeyInfo.hkdfSalt, hkdfInfo: prfKeyInfo.hkdfInfo)
        return try EncryptedContainer.unwrapMainKey(prfKey: prfKey, prfKeyInfo: prfKeyInfo, mainKeyInfo: mainKeyInfo)
    }

    private static func encryptJwe(_ plaintextState: [String: Any], mainKey: SymmetricKey) throws -> String {
        let plaintext = try JSONSerialization.data(withJSONObject: plaintextState)

        var cekBytes = Data(count: 32)
        // swiftlint:disable:next force_unwrapping
        cekBytes.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        let cek = SymmetricKey(data: cekBytes)

        let kwNonce = AES.GCM.Nonce()
        let kwSealed = try AES.GCM.seal(cekBytes, using: mainKey, nonce: kwNonce)

        let headerObj: [String: Any] = [
            "alg": "A256GCMKW",
            "enc": "A256GCM",
            "iv": EncryptedContainer.base64UrlEncode(Data(kwNonce)),
            "tag": EncryptedContainer.base64UrlEncode(kwSealed.tag),
        ]
        let headerData = try JSONSerialization.data(withJSONObject: headerObj)
        let headerB64 = EncryptedContainer.base64UrlEncode(headerData)

        let contentNonce = AES.GCM.Nonce()
        let aad = Data(headerB64.utf8)
        let sealed = try AES.GCM.seal(plaintext, using: cek, nonce: contentNonce, authenticating: aad)

        return [
            headerB64,
            EncryptedContainer.base64UrlEncode(kwSealed.ciphertext),
            EncryptedContainer.base64UrlEncode(Data(contentNonce)),
            EncryptedContainer.base64UrlEncode(sealed.ciphertext),
            EncryptedContainer.base64UrlEncode(sealed.tag),
        ].joined(separator: ".")
    }

    private static func decryptJwe(_ jweString: String, mainKey: SymmetricKey) throws -> [String: Any] {
        let parts = jweString.split(separator: ".").map(String.init)
        guard parts.count == 5 else { throw KeystoreError.invalidContainer("JWE must have 5 parts") }

        let headerData = EncryptedContainer.base64UrlDecode(parts[0])
        let encryptedKeyData = EncryptedContainer.base64UrlDecode(parts[1])
        let ivData = EncryptedContainer.base64UrlDecode(parts[2])
        let ciphertextData = EncryptedContainer.base64UrlDecode(parts[3])
        let tagData = EncryptedContainer.base64UrlDecode(parts[4])

        guard let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any],
              let headerIv = header["iv"] as? String,
              let headerTag = header["tag"] as? String else {
            throw KeystoreError.invalidContainer("Invalid JWE header")
        }
        let kwNonce = try AES.GCM.Nonce(data: EncryptedContainer.base64UrlDecode(headerIv))
        let kwTag = EncryptedContainer.base64UrlDecode(headerTag)
        let kwSealedBox = try AES.GCM.SealedBox(nonce: kwNonce, ciphertext: encryptedKeyData, tag: kwTag)
        let cekData = try AES.GCM.open(kwSealedBox, using: mainKey)
        let cek = SymmetricKey(data: cekData)

        let contentNonce = try AES.GCM.Nonce(data: ivData)
        let aadData = Data(parts[0].utf8)
        let contentSealedBox = try AES.GCM.SealedBox(nonce: contentNonce, ciphertext: ciphertextData, tag: tagData)
        let plaintext = try AES.GCM.open(contentSealedBox, using: cek, authenticating: aadData)

        guard let json = try JSONSerialization.jsonObject(with: plaintext) as? [String: Any] else {
            throw KeystoreError.invalidContainer("JWE payload is not valid JSON object")
        }
        return json
    }
}

#endif

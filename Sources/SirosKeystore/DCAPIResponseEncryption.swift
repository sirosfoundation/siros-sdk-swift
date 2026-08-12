// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

/// Encrypts an OpenID4VP response for the `dc_api.jwt` response mode
/// (OpenID4VP 1.0 Appendix A.3.2, "Response Encryption").
///
/// The W3C Digital Credentials API has no TLS-secured `direct_post` channel
/// for the wallet's response (it's returned via the browser's synchronous
/// `navigator.credentials.get()` callback instead of an HTTP POST), so
/// `dc_api.jwt` always requires the response to be JWE-encrypted to a key the
/// verifier published in its request's `client_metadata.jwks` - unlike the
/// redirect flow, where `direct_post.jwt` encryption is an OPTIONAL hardening
/// on top of an already-TLS-secured POST.
///
/// Mirrors the Kotlin SDK's `DCAPIResponseEncryption` (Nimbus's
/// `ECDHEncrypter`): ECDH-ES key agreement (RFC 7518 §4.6, "Direct Key
/// Agreement" - no key-wrapping, the derived key IS the CEK) against the
/// verifier's EC P-256 public key, A128GCM content encryption by default.
/// This SDK has no JOSE library dependency, so both the Concat KDF (RFC 7518
/// §4.6.2 / NIST SP 800-56A) and the JWE compact serialization are
/// implemented directly here on top of CryptoKit, following the same
/// `#if canImport(CryptoKit)` gating convention as the rest of this module
/// (e.g. `EncryptedContainer`).
public enum DCAPIResponseEncryption {

    #if canImport(CryptoKit)

    /// Compute the RFC 7638 JWK Thumbprint of an EC public JWK: SHA-256 over
    /// `{"crv":...,"kty":...,"x":...,"y":...}` in lexicographic member order
    /// with no insignificant whitespace, base64url-encoded. Used both to
    /// look up which of the verifier's declared encryption keys to encrypt
    /// this response to and to embed in the mdoc `OpenID4VPDCAPIHandover`
    /// session transcript (see `MdocDeviceResponseBuilder`).
    public static func jwkThumbprint(_ jwk: [String: Any]) -> String? {
        guard let crv = jwk["crv"] as? String,
              let kty = jwk["kty"] as? String,
              let x = jwk["x"] as? String,
              let y = jwk["y"] as? String else {
            return nil
        }
        let canonical = "{\"crv\":\"\(crv)\",\"kty\":\"\(kty)\",\"x\":\"\(x)\",\"y\":\"\(y)\"}"
        let digest = SHA256.hash(data: Data(canonical.utf8))
        return EncryptedContainer.base64UrlEncode(Data(digest))
    }

    /// - Parameters:
    ///   - responseJson: the full response payload to encrypt, e.g. `{"vp_token": {...}}`.
    ///   - verifierJwk: the verifier's response-encryption public key (from
    ///     `client_metadata.jwks`, the entry with `use: "enc"`) - MUST be an EC P-256 key.
    ///   - enc: the JWE content-encryption algorithm identifier. Defaults to `"A128GCM"`.
    /// - Returns: the compact-serialized JWE string.
    public static func encryptResponse(
        responseJson: String,
        verifierJwk: [String: Any],
        enc: String = "A128GCM"
    ) throws -> String {
        guard (verifierJwk["kty"] as? String) == "EC",
              (verifierJwk["crv"] as? String) == "P-256",
              let xStr = verifierJwk["x"] as? String,
              let yStr = verifierJwk["y"] as? String else {
            let kty = verifierJwk["kty"] as? String ?? "unknown"
            throw KeystoreError.invalidParameter("DC API response encryption requires an EC P-256 verifier key, got \(kty)")
        }
        let x = EncryptedContainer.base64UrlDecode(xStr)
        let y = EncryptedContainer.base64UrlDecode(yStr)
        let verifierPublicKey = try P256.KeyAgreement.PublicKey(x963Representation: Data([0x04]) + x + y)

        let keyDataLenBits: Int
        switch enc {
        case "A256GCM": keyDataLenBits = 256
        case "A192GCM": keyDataLenBits = 192
        default: keyDataLenBits = 128
        }

        // Ephemeral keypair for this single ECDH-ES key-agreement operation
        // (RFC 7518 §4.6) - never reused across calls.
        let ephemeralPrivate = P256.KeyAgreement.PrivateKey()
        let ephemeralX963 = ephemeralPrivate.publicKey.x963Representation
        let epk: [String: Any] = [
            "kty": "EC",
            "crv": "P-256",
            "x": EncryptedContainer.base64UrlEncode(Data(ephemeralX963[1..<33])),
            "y": EncryptedContainer.base64UrlEncode(Data(ephemeralX963[33..<65])),
        ]

        var header: [String: Any] = [
            "alg": "ECDH-ES",
            "enc": enc,
            "epk": epk,
        ]
        // The verifier looks up which of its (possibly many concurrent)
        // ephemeral decryption keys to use by the JWE header's kid - it
        // generates that key specifically with one and expects it echoed
        // back here. Omitting this was a real bug: decryption failed with
        // "kid not found in JWT header" before the verifier could even
        // attempt decryption.
        if let kid = verifierJwk["kid"] as? String {
            header["kid"] = kid
        }

        guard let headerData = try? JSONSerialization.data(withJSONObject: header, options: [.sortedKeys]) else {
            throw KeystoreError.cryptoError("Failed to serialize DC API response JWE header")
        }
        let headerB64 = EncryptedContainer.base64UrlEncode(headerData)
        let aad = Data(headerB64.utf8)

        let sharedSecret = try ephemeralPrivate.sharedSecretFromKeyAgreement(with: verifierPublicKey)
        let z = sharedSecret.withUnsafeBytes { Data($0) }
        let cek = SymmetricKey(data: concatKDF(z: z, algorithmId: enc, keyDataLenBits: keyDataLenBits))

        let nonce = AES.GCM.Nonce()
        let sealedBox = try AES.GCM.seal(Data(responseJson.utf8), using: cek, nonce: nonce, authenticating: aad)

        let ivB64 = EncryptedContainer.base64UrlEncode(Data(nonce))
        let ciphertextB64 = EncryptedContainer.base64UrlEncode(sealedBox.ciphertext)
        let tagB64 = EncryptedContainer.base64UrlEncode(sealedBox.tag)

        // ECDH-ES ("Direct Key Agreement", RFC 7518 §4.6) has no wrapped CEK
        // to convey - the JWE Encrypted Key segment is empty.
        return "\(headerB64)..\(ivB64).\(ciphertextB64).\(tagB64)"
    }

    /// Concat KDF (NIST SP 800-56A §5.8.1, RFC 7518 §4.6.2) with SHA-256 as
    /// the hash function - a single round always suffices here since none of
    /// the `enc` values this SDK supports need more than 256 output bits.
    /// No `PartyUInfo`/`PartyVInfo` (`apu`/`apv`) are used - matching Nimbus's
    /// `ECDHEncrypter` default, which likewise omits them unless the header
    /// carries explicit `apu`/`apv` claims.
    private static func concatKDF(z: Data, algorithmId: String, keyDataLenBits: Int) -> Data {
        var otherInfo = Data()
        appendLengthPrefixed(&otherInfo, Data(algorithmId.utf8)) // AlgorithmID
        appendLengthPrefixed(&otherInfo, Data())                 // PartyUInfo (empty)
        appendLengthPrefixed(&otherInfo, Data())                 // PartyVInfo (empty)
        withUnsafeBytes(of: UInt32(keyDataLenBits).bigEndian) { otherInfo.append(contentsOf: $0) } // SuppPubInfo

        let keyDataLenBytes = keyDataLenBits / 8
        var output = Data()
        var counter: UInt32 = 1
        while output.count < keyDataLenBytes {
            var counterBytes = Data()
            withUnsafeBytes(of: counter.bigEndian) { counterBytes.append(contentsOf: $0) }
            output.append(contentsOf: SHA256.hash(data: counterBytes + z + otherInfo))
            counter += 1
        }
        return output.prefix(keyDataLenBytes)
    }

    private static func appendLengthPrefixed(_ data: inout Data, _ value: Data) {
        withUnsafeBytes(of: UInt32(value.count).bigEndian) { data.append(contentsOf: $0) }
        data.append(value)
    }

    #endif
}

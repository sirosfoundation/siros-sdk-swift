// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

/// Helpers for building minimal JWTs (header.payload.signature) using CryptoKit P256.
enum JwtHelpers {

    #if canImport(CryptoKit)

    /// Encode a JSON dictionary as a base64url string.
    static func jsonBase64Url(_ dict: [String: Any]) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: dict, options: .sortedKeys) else {
            return ""
        }
        return EncryptedContainer.base64UrlEncode(data)
    }

    /// Export a P256.Signing.PrivateKey's public key as a JWK dictionary.
    static func publicKeyJwk(_ privateKey: P256.Signing.PrivateKey) -> [String: String] {
        let publicKey = privateKey.publicKey
        let x963 = publicKey.x963Representation
        let x = Data(x963[1..<33])
        let y = Data(x963[33..<65])
        return [
            "kty": "EC",
            "crv": "P-256",
            "x": EncryptedContainer.base64UrlEncode(x),
            "y": EncryptedContainer.base64UrlEncode(y),
        ]
    }

    /// Parse JWT claims from a compact JWT string.
    static func parseJwtPayload(_ jwt: String) -> [String: Any]? {
        let parts = jwt.split(separator: ".").map(String.init)
        guard parts.count >= 2 else { return nil }
        let payloadData = EncryptedContainer.base64UrlDecode(parts[1])
        return try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any]
    }

    /// Parse JWT header from a compact JWT string.
    static func parseJwtHeader(_ jwt: String) -> [String: Any]? {
        let parts = jwt.split(separator: ".").map(String.init)
        guard !parts.isEmpty else { return nil }
        let headerData = EncryptedContainer.base64UrlDecode(parts[0])
        return try? JSONSerialization.jsonObject(with: headerData) as? [String: Any]
    }

    /// Compute the RFC 7638 JWK Thumbprint of an EC public JWK: SHA-256 over
    /// `{"crv":...,"kty":...,"x":...,"y":...}` in lexicographic member order
    /// with no insignificant whitespace, base64url-encoded.
    static func jwkThumbprint(_ jwk: [String: Any]) -> String? {
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

    #endif
}

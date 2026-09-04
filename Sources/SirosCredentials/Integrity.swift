// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

#if canImport(CryptoKit)
import CryptoKit
#else
// swift-crypto's `Crypto` module mirrors CryptoKit's API 1:1, including the
// SHA256/384/512 types used below.
import Crypto
#endif

/// Subresource-integrity digests, as SD-JWT VC Type Metadata uses them.
///
/// The `vct#integrity`, `schema_uri#integrity`, `extends#integrity` and
/// `uri#integrity` members all carry a W3C SRI string: an algorithm name, a
/// dash, and the base64 digest of the resource's bytes — `sha256-47DEQpj8...`.
///
/// These exist so the *issuer* can pin what a credential type means. Without
/// checking them, whoever serves the type metadata decides how a credential is
/// displayed and which claims it is understood to carry, independently of the
/// issuer who vouched for it.
public enum Integrity {

    /// Whether `content` matches `expected`.
    ///
    /// An unparseable or unknown-algorithm value returns false rather than
    /// true: a digest that cannot be checked is not a digest that passed, and
    /// the caller decides what "cannot check" should mean.
    public static func matches(_ content: Data, _ expected: String) -> Bool {
        let trimmed = expected.trimmingCharacters(in: .whitespacesAndNewlines)

        // SRI permits several space-separated digests, strongest first. Any one
        // matching is a match.
        if trimmed.contains(" ") {
            return trimmed
                .split(separator: " ")
                .filter { !$0.isEmpty }
                .contains { matches(content, String($0)) }
        }

        guard let dash = trimmed.firstIndex(of: "-"), dash != trimmed.startIndex else {
            return false
        }
        let algorithm = String(trimmed[trimmed.startIndex..<dash]).lowercased()
        let encoded = String(trimmed[trimmed.index(after: dash)...])
        guard let expectedDigest = decodeBase64(encoded) else { return false }

        let actual: Data
        switch algorithm {
        case "sha256": actual = Data(SHA256.hash(data: content))
        case "sha384": actual = Data(SHA384.hash(data: content))
        case "sha512": actual = Data(SHA512.hash(data: content))
        default: return false
        }

        // Constant-time comparison: the digests being compared are public, but
        // the habit is worth keeping and costs nothing here.
        guard actual.count == expectedDigest.count else { return false }
        var difference: UInt8 = 0
        for (a, b) in zip(actual, expectedDigest) { difference |= a ^ b }
        return difference == 0
    }

    /// SRI is standard base64, but the URL-safe alphabet is tolerated:
    /// rejecting a correct digest over its spelling would be a worse failure
    /// than accepting either encoding of the same bytes.
    private static func decodeBase64(_ value: String) -> Data? {
        var padded = value
        let remainder = padded.count % 4
        if remainder > 0 { padded += String(repeating: "=", count: 4 - remainder) }
        if let data = Data(base64Encoded: padded) { return data }
        let standard = padded.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        return Data(base64Encoded: standard)
    }
}

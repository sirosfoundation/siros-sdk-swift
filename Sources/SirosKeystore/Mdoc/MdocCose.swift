// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
@preconcurrency import SwiftCBOR

/// Minimal COSE_Sign1 construction (RFC 8152 §4.2), scoped to what a wallet
/// (holder) needs to produce a `DeviceAuth.deviceSignature` for an ISO
/// 18013-5 DeviceResponse - signing only, no verification (that's a
/// verifier-side concern). Mirrors `sirosfoundation/vc/pkg/mdoc/cose.go`'s
/// `Sign1Detached` for the algorithm/header/Sig_structure shape.
///
/// Note: unlike the Go reference, no ECDSA DER->raw signature conversion is
/// needed here - this SDK's signer abstraction (WSCD/UniFFI-backed) already
/// returns raw r||s signatures, confirmed by the existing JWS signing paths
/// (`generateProof`/`signPresentation` in `WscdKeystoreAdapter`) which embed
/// the same signer output directly as a JWS signature with no conversion.
public enum MdocCose {

    /// COSE algorithm identifiers per RFC 8152 §8.1/§8.2, relevant subset.
    private static let algES256: Int64 = -7
    private static let algES384: Int64 = -35
    private static let algES512: Int64 = -36
    private static let algEdDSA: Int64 = -8

    private static let headerAlgorithm: UInt64 = 1
    private static let coseSign1Tag = CBOR.Tag(rawValue: 18)

    private static func algorithmValue(_ algorithm: String) -> Int64 {
        switch algorithm.uppercased() {
        case "ES256": return algES256
        case "ES384": return algES384
        case "ES512": return algES512
        case "EDDSA", "ED25519": return algEdDSA
        default: return algES256
        }
    }

    /// Build a detached COSE_Sign1 over `externalAad` (the ISO 18013-5
    /// DeviceAuthentication bytes, for a DeviceResponse device signature).
    /// Returns the CBOR-encoded tag-18 4-element array
    /// `[protected, unprotected, null, signature]`.
    ///
    /// - Parameter signer: signs raw bytes with the device key; must return a
    ///   raw (not DER) signature for ECDSA algorithms.
    public static func sign1Detached(
        algorithm: String,
        externalAad: [UInt8],
        signer: (@Sendable ([UInt8]) async throws -> [UInt8])
    ) async throws -> CBOR {
        let algValue = algorithmValue(algorithm)

        let protectedHeaders: CBOR = .map([.unsignedInt(headerAlgorithm): negativeSafe(algValue)])
        let protectedBytes = protectedHeaders.encode()

        // Sig_structure = ["Signature1", protected, external_aad, payload]
        // Detached: payload is an empty byte string.
        let sigStructure: CBOR = .array([
            .utf8String("Signature1"),
            .byteString(protectedBytes),
            .byteString(externalAad),
            .byteString([]),
        ])
        let toBeSigned = sigStructure.encode()

        let signature = try await signer(toBeSigned)

        let coseSign1: CBOR = .array([
            .byteString(protectedBytes),
            .map([:]),
            .null,
            .byteString(signature),
        ])

        return .tagged(coseSign1Tag, coseSign1)
    }

    /// COSE algorithm identifiers (RFC 8152 §8.1/§8.2) are CBOR major-type-1
    /// negative integers when < 0; SwiftCBOR represents those via
    /// `.negativeInt(UInt64)` where the encoded value is `-1 - n`, not `Int64`
    /// directly - this converts our small negative Int64 constants correctly.
    private static func negativeSafe(_ value: Int64) -> CBOR {
        if value >= 0 {
            return .unsignedInt(UInt64(value))
        }
        return .negativeInt(UInt64(-1 - value))
    }
}

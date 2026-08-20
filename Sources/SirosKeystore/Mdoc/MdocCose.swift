// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
import Foundation
@preconcurrency import SwiftCBOR
#if canImport(CryptoKit)
import CryptoKit
#endif

/// Minimal COSE_Sign1 construction/verification (RFC 8152 §4.2/§4.4), scoped
/// to an mdoc wallet's needs: signing a `DeviceAuth.deviceSignature` for an
/// ISO 18013-5 DeviceResponse, and - new for RICAL reader-authentication
/// support (Annex F) - verifying an INCOMING COSE_Sign1 (a reader's
/// `readerAuth`). This is a deliberate, first-time departure from this SDK's
/// prior convention of treating incoming COSE_Sign1 structures (issuerAuth)
/// as opaque and never verifying them locally. Mirrors
/// `sirosfoundation/vc/pkg/mdoc/cose.go`'s `Sign1Detached`/`Verify1` and the
/// Kotlin SDK's `MdocCose.kt` (`verify1`/`extractX5Chain`/
/// `buildReaderAuthenticationBytes`) for the algorithm/header/Sig_structure
/// shape - this is the Swift port of that file.
///
/// Note: unlike the Go/Kotlin references, no raw<->DER signature conversion
/// is needed here in either direction - CryptoKit's `ECDSASignature` natively
/// accepts/produces the raw r||s COSE/JOSE wire format via
/// `rawRepresentation`, confirmed by the existing verification precedent in
/// `DCAPIRequestParser.swift`'s `verifySignature`.
public enum MdocCose {

    /// COSE algorithm identifiers per RFC 8152 §8.1/§8.2, relevant subset.
    private static let algES256: Int64 = -7
    private static let algES384: Int64 = -35
    private static let algES512: Int64 = -36
    private static let algEdDSA: Int64 = -8

    private static let headerAlgorithm: UInt64 = 1

    private static func algorithmValue(_ algorithm: String) -> Int64 {
        switch algorithm.uppercased() {
        case "ES256": return algES256
        case "ES384": return algES384
        case "ES512": return algES512
        case "EDDSA", "ED25519": return algEdDSA
        default: return algES256
        }
    }

    /// Build a detached COSE_Sign1 over `payload` (the ISO 18013-5
    /// DeviceAuthentication bytes, for a DeviceResponse device signature).
    /// Returns the CBOR-encoded, bare (untagged) 4-element array
    /// `[protected, unprotected, null, signature]`.
    ///
    /// "Detached" describes the OUTPUT wire format only (the 3rd element of
    /// the returned array is CBOR null, since the verifier reconstructs
    /// DeviceAuthentication itself from context rather than needing it
    /// embedded) - the signature is still computed over the real `payload`
    /// bytes in the Sig_structure's `payload` position, with `external_aad`
    /// left empty (`h''`). This was previously inverted (payload hardcoded
    /// empty, the real content passed as external_aad instead) and the
    /// result was wrapped in CBOR tag 18 - both real bugs matching Google's
    /// own reference wallet's construction
    /// (https://github.com/digitalcredentialsdev/CMWallet's
    /// `generateDeviceResponse()`, which uses a bare untagged array with the
    /// real content as `payload`), found and fixed in the Kotlin SDK first
    /// (see MdocCose.kt) after Google's public digital-credentials.dev demo
    /// rejected mdocs built with the inverted/tagged shape.
    ///
    /// - Parameter signer: signs raw bytes with the device key; must return a
    ///   raw (not DER) signature for ECDSA algorithms.
    public static func sign1Detached(
        algorithm: String,
        payload: [UInt8],
        signer: (@Sendable ([UInt8]) async throws -> [UInt8])
    ) async throws -> CBOR {
        let algValue = algorithmValue(algorithm)

        let protectedHeaders: CBOR = .map([.unsignedInt(headerAlgorithm): negativeSafe(algValue)])
        let protectedBytes = protectedHeaders.encode()

        // Sig_structure = ["Signature1", protected, external_aad, payload]
        let sigStructure: CBOR = .array([
            .utf8String("Signature1"),
            .byteString(protectedBytes),
            .byteString([]),
            .byteString(payload),
        ])
        let toBeSigned = sigStructure.encode()

        let signature = try await signer(toBeSigned)

        // Bare 4-element array, NOT wrapped in COSE tag 18 - see doc comment.
        return .array([
            .byteString(protectedBytes),
            .map([:]),
            .null,
            .byteString(signature),
        ])
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

    /// Decodes a CBOR-encoded signed integer (COSE alg values are always
    /// negative) to `Int64` - the inverse of `negativeSafe`.
    private static func int64Value(_ cbor: CBOR) -> Int64? {
        switch cbor {
        case .unsignedInt(let v): return Int64(v)
        case .negativeInt(let v): return -1 - Int64(v)
        default: return nil
        }
    }

    /// Verifies an incoming COSE_Sign1's signature over `payload` (used for
    /// the detached case, e.g. a `readerAuth` whose payload is reconstructed
    /// from context rather than embedded - the same detachment convention
    /// `sign1Detached` produces) against `publicKeyX963` (an uncompressed
    /// SEC1/X9.62 point - `0x04 || X || Y` - the same representation
    /// `SecKeyCopyExternalRepresentation` returns for an EC key, see
    /// `DCAPIRequestParser.swift`'s `ecPublicKeyBytes(fromCertBase64:)`).
    /// Curve-agnostic at the API boundary (mirrors the Kotlin port's plain
    /// `java.security.PublicKey` parameter) even though CryptoKit itself
    /// types P-256/P-384/P-521 keys separately - the algorithm read from
    /// `sign1`'s protected header (COSE label 1) picks the right one
    /// internally. Reads the signing algorithm from `sign1`'s protected
    /// header; the RICAL annex (F.3.2) restricts this to
    /// ES256/ES384/ES512/EdDSA, but EdDSA verification isn't implemented
    /// here yet since no current caller needs it - added if/when one does,
    /// rather than guessing at untested code (matches the Kotlin port's
    /// same scoping decision).
    ///
    /// - Parameter sign1: the 4-element COSE_Sign1 array: `[protected,
    ///   unprotected, payload-or-null, signature]`.
    /// - Parameter payload: the actual signed payload bytes (required even
    ///   when `sign1`'s own payload slot is CBOR null, i.e. detached).
    public static func verify1(_ sign1: CBOR, payload: [UInt8], publicKeyX963: [UInt8]) -> Bool {
        #if canImport(CryptoKit)
        guard case .array(let arr) = sign1, arr.count == 4 else { return false }
        guard case .byteString(let protectedBytes) = arr[0] else { return false }
        guard case .byteString(let signature) = arr[3] else { return false }

        guard let protectedHeaders = try? CBOR.decode(protectedBytes),
              let algCbor = protectedHeaders?[.unsignedInt(headerAlgorithm)],
              let coseAlg = int64Value(algCbor) else {
            return false
        }

        let sigStructure: CBOR = .array([
            .utf8String("Signature1"),
            .byteString(protectedBytes),
            .byteString([]),
            .byteString(payload),
        ])
        let toBeSigned = Data(sigStructure.encode())
        let rawSignature = Data(signature)
        let keyData = Data(publicKeyX963)

        switch coseAlg {
        case algES256:
            guard let key = try? P256.Signing.PublicKey(x963Representation: keyData),
                  let sig = try? P256.Signing.ECDSASignature(rawRepresentation: rawSignature) else {
                return false
            }
            return key.isValidSignature(sig, for: toBeSigned)
        case algES384:
            guard let key = try? P384.Signing.PublicKey(x963Representation: keyData),
                  let sig = try? P384.Signing.ECDSASignature(rawRepresentation: rawSignature) else {
                return false
            }
            return key.isValidSignature(sig, for: toBeSigned)
        case algES512:
            guard let key = try? P521.Signing.PublicKey(x963Representation: keyData),
                  let sig = try? P521.Signing.ECDSASignature(rawRepresentation: rawSignature) else {
                return false
            }
            return key.isValidSignature(sig, for: toBeSigned)
        default:
            return false
        }
        #else
        return false
        #endif
    }

    /// Extracts the x5chain (COSE header label 33) from a COSE_Sign1's
    /// unprotected header (index 1 of the 4-element array) - the standard
    /// mdoc issuerAuth/deviceAuth/readerAuth convention, matching the
    /// Kotlin port's `extractX5Chain`. Returns DER-encoded certificate
    /// bytes, leaf first.
    public static func extractX5Chain(_ sign1: CBOR) -> [[UInt8]] {
        guard case .array(let arr) = sign1, arr.count >= 2 else { return [] }
        guard let x5chain = arr[1][.unsignedInt(x5ChainHeaderLabel)] else { return [] }
        switch x5chain {
        case .byteString(let bytes):
            return [bytes]
        case .array(let items):
            return items.compactMap {
                if case .byteString(let b) = $0 { return b }
                return nil
            }
        default:
            return []
        }
    }

    private static let x5ChainHeaderLabel: UInt64 = 33

    /// Builds `ReaderAuthenticationBytes` per ISO 18013-5:2021 §9.1.4 -
    /// `#6.24(bstr .cbor ["ReaderAuthentication", SessionTranscript,
    /// ItemsRequestBytes])` - the detached content a reader's `readerAuth`
    /// COSE_Sign1 actually signs (its own payload slot is CBOR null).
    /// Matches the Kotlin port's `buildReaderAuthenticationBytes`.
    ///
    /// - Parameter sessionTranscript: the bare (untagged) `SessionTranscript`
    ///   array bytes, the same shape `ProximitySessionCrypto` takes.
    /// - Parameter itemsRequestTaggedBytes: the exact tag-24-wrapped
    ///   `itemsRequest` CBOR bytes as they appeared in the `DocRequest` - the
    ///   identical bytes, not a re-encoding, per the spec's "Same as in mdoc
    ///   request".
    public static func buildReaderAuthenticationBytes(
        sessionTranscript: [UInt8],
        itemsRequestTaggedBytes: [UInt8]
    ) throws -> [UInt8] {
        guard let transcript = try CBOR.decode(sessionTranscript) else {
            throw KeystoreError.cryptoError("empty sessionTranscript")
        }
        guard let itemsRequestTagged = try CBOR.decode(itemsRequestTaggedBytes) else {
            throw KeystoreError.cryptoError("empty itemsRequest")
        }
        let readerAuthentication: CBOR = .array([
            .utf8String("ReaderAuthentication"),
            transcript,
            itemsRequestTagged,
        ])
        return CBOR.tagged(.encodedCBORDataItem, .byteString(readerAuthentication.encode())).encode()
    }
}

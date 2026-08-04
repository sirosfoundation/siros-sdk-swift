// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
@preconcurrency import SwiftCBOR
#if canImport(CryptoKit)
import CryptoKit
#endif

/// ISO 18013-5 §9.1.1/§12.2.5 session encryption: ECKA-DH key agreement
/// between `EDeviceKey`/`EReaderKey`, HKDF-SHA256 deriving `SKDevice`/
/// `SKReader`, and AES-256-GCM encryption/decryption of `SessionEstablishment`/
/// `SessionData` payloads with the spec's deterministic IV.
///
/// Verified against the real ISO/IEC 18013-5 Annex D.5.1 worked example - see
/// `ProximitySessionCryptoTests.swift`, which reproduces the exact
/// `EDeviceKey`/`EReaderKey` values, decrypts the vector's own
/// `SessionEstablishment`/`SessionData` ciphertexts, and confirms the
/// plaintexts are the exact Annex D.4.1.1/D.4.1.2 mdoc request/response CBOR
/// (independently re-derived and cross-checked with a standalone Python
/// script during the Kotlin implementation - see
/// [[reference_iso18013_5_local_pdf]] memory). Ported from
/// `org.siros.sdk.keystore.mdoc.ProximitySessionCrypto` (Kotlin).
///
/// EC/AEAD primitives are Apple-only (`CryptoKit`) - matching this repo's
/// established `#if canImport(CryptoKit)` convention (see `JweKeystore`),
/// this whole type is gated; on non-Apple platforms every function throws
/// rather than silently no-op'ing.
public enum ProximitySessionCrypto {

    /// Fixed 8-byte IV identifier the mdoc reader uses, per §12.2.5.
    private static let readerIdentifier = [UInt8](repeating: 0, count: 8)

    /// Fixed 8-byte IV identifier the mdoc uses, per §12.2.5.
    private static let mdocIdentifier: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 1]

    public struct SessionKeys: Sendable {
        public let skReader: [UInt8]
        public let skDevice: [UInt8]

        public init(skReader: [UInt8], skDevice: [UInt8]) {
            self.skReader = skReader
            self.skDevice = skDevice
        }
    }

    #if canImport(CryptoKit)

    /// Derive `SKReader`/`SKDevice` per §12.2.5: ECKA-DH between
    /// `eDeviceKeyPrivate` and `eReaderKeyPublic` produces `ZAB`; HKDF-SHA256
    /// with `salt = SHA-256(SessionTranscriptBytes)` (the tag-24-WRAPPED
    /// form - computed internally here, distinct from the bare array bytes
    /// `ProximitySessionTranscript.build` returns) and `info = "SKReader"`/
    /// `"SKDevice"` derives both 32-byte keys.
    ///
    /// - Parameter sessionTranscript: the bare (untagged) `SessionTranscript`
    ///   array bytes from `ProximitySessionTranscript.build`.
    public static func deriveSessionKeys(
        eDeviceKeyPrivate: P256.KeyAgreement.PrivateKey,
        eReaderKeyPublic: P256.KeyAgreement.PublicKey,
        sessionTranscript: [UInt8]
    ) throws -> SessionKeys {
        let zab = try ecdh(eDeviceKeyPrivate, eReaderKeyPublic)
        let sessionTranscriptBytes = CBOR.tagged(.encodedCBORDataItem, .byteString(sessionTranscript)).encode()
        let salt = Array(SHA256.hash(data: sessionTranscriptBytes))
        return SessionKeys(
            skReader: hkdfSha256(ikm: zab, salt: salt, info: Array("SKReader".utf8), length: 32),
            skDevice: hkdfSha256(ikm: zab, salt: salt, info: Array("SKDevice".utf8), length: 32)
        )
    }

    /// Encryptor/decryptor for one session key, tracking its own monotonic
    /// message counter (never reused). Reference type (a `class`, matching
    /// Kotlin) since the counter is mutated across successive calls.
    public final class SessionCipher: @unchecked Sendable {
        private let key: SymmetricKey
        private let identifier: [UInt8]
        private var counter: UInt32 = 1

        public init(key: [UInt8], identifier: [UInt8]) {
            self.key = SymmetricKey(data: key)
            self.identifier = identifier
        }

        /// AES-256-GCM encrypt with the next IV for this key; empty AAD, per §12.2.5.
        /// Output is `ciphertext || tag` (16-byte tag appended), matching the
        /// JCE/Java GCM convention this was originally verified against - NOT
        /// CryptoKit's `combined` representation (which prepends the nonce).
        public func encrypt(_ plaintext: [UInt8]) throws -> [UInt8] {
            let nonce = try AES.GCM.Nonce(data: nextIv())
            let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce)
            return sealed.ciphertext + sealed.tag
        }

        /// AES-256-GCM decrypt with the next IV for this key; empty AAD, per §12.2.5.
        /// Expects `ciphertext || tag` (16-byte tag appended), matching `encrypt`'s output.
        public func decrypt(_ ciphertext: [UInt8]) throws -> [UInt8] {
            guard ciphertext.count >= 16 else {
                throw KeystoreError.cryptoError("ciphertext too short to contain a GCM tag")
            }
            let tag = Array(ciphertext.suffix(16))
            let actualCiphertext = Array(ciphertext.dropLast(16))
            let nonce = try AES.GCM.Nonce(data: nextIv())
            let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: actualCiphertext, tag: tag)
            return Array(try AES.GCM.open(sealedBox, using: key))
        }

        private func nextIv() -> [UInt8] {
            let c = counter
            let counterBytes: [UInt8] = [
                UInt8((c >> 24) & 0xFF), UInt8((c >> 16) & 0xFF), UInt8((c >> 8) & 0xFF), UInt8(c & 0xFF),
            ]
            counter += 1
            return identifier + counterBytes
        }
    }

    /// Cipher for messages the mdoc READER encrypts (mdoc requests) - used by the mdoc to decrypt them.
    public static func readerCipher(_ skReader: [UInt8]) -> SessionCipher {
        SessionCipher(key: skReader, identifier: readerIdentifier)
    }

    /// Cipher for messages the MDOC encrypts (mdoc responses).
    public static func deviceCipher(_ skDevice: [UInt8]) -> SessionCipher {
        SessionCipher(key: skDevice, identifier: mdocIdentifier)
    }

    /// Parse a `SessionEstablishment.eReaderKey` field (`#6.24`-tagged `COSE_Key`) into a public key.
    public static func parseEReaderKeyPublic(_ eReaderKeyBytes: [UInt8]) throws -> P256.KeyAgreement.PublicKey {
        guard let tagged = try CBOR.decode(eReaderKeyBytes) else {
            throw KeystoreError.cryptoError("empty eReaderKey")
        }
        guard case .tagged(let tag, let content) = tagged, tag == .encodedCBORDataItem,
              case .byteString(let coseKeyBytes) = content else {
            throw KeystoreError.cryptoError("eReaderKey is not a tag-24-wrapped COSE_Key")
        }
        guard let coseKey = try CBOR.decode(coseKeyBytes) else {
            throw KeystoreError.cryptoError("empty COSE_Key")
        }
        let coseKeyX: CBOR = -2
        let coseKeyY: CBOR = -3
        guard case .byteString(let x)? = coseKey[coseKeyX],
              case .byteString(let y)? = coseKey[coseKeyY]
        else {
            throw KeystoreError.cryptoError("COSE_Key missing x/y")
        }
        let x963 = Data([0x04]) + Data(x) + Data(y)
        return try P256.KeyAgreement.PublicKey(x963Representation: x963)
    }

    /// §11.1.3.1 `Ident` characteristic value: `HKDF-SHA256(IKM=EDeviceKeyBytes,
    /// salt=<none>, info="BLEIdent", L=16)`. In "mdoc central client mode",
    /// the mdoc reads this from the reader's GATT service and MUST terminate
    /// the connection if it doesn't match - it's the only defense against
    /// connecting to the wrong (or an impersonating) reader.
    ///
    /// RFC 5869 §2.2: when no salt is provided, HKDF-Extract uses a salt of
    /// `HashLen` zero bytes (32, for SHA-256) - NOT a zero-length byte array.
    public static func computeIdent(_ eDeviceKeyBytes: [UInt8]) -> [UInt8] {
        hkdfSha256(ikm: eDeviceKeyBytes, salt: [UInt8](repeating: 0, count: 32), info: Array("BLEIdent".utf8), length: 16)
    }

    private static func ecdh(_ priv: P256.KeyAgreement.PrivateKey, _ pub: P256.KeyAgreement.PublicKey) throws -> [UInt8] {
        let secret = try priv.sharedSecretFromKeyAgreement(with: pub)
        return secret.withUnsafeBytes { Array($0) }
    }

    private static func hkdfSha256(ikm: [UInt8], salt: [UInt8], info: [UInt8], length: Int) -> [UInt8] {
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: Data(salt),
            info: Data(info),
            outputByteCount: length
        )
        return key.withUnsafeBytes { Array($0) }
    }

    #else

    // Non-Apple stub: ECDH/HKDF/AES-GCM all require CryptoKit, unavailable
    // on this platform (matching `JweKeystore`'s established convention).
    // `deriveSessionKeys` itself can't even be declared here (its real
    // signature takes CryptoKit `P256.KeyAgreement` types) - there is no
    // meaningful proximity session crypto without CryptoKit, so callers on
    // this platform (there are none in this SDK; the BLE peripheral glue is
    // Apple-only) would need their own platform gate regardless.

    public final class SessionCipher: @unchecked Sendable {
        public init() {}
        public func encrypt(_ plaintext: [UInt8]) throws -> [UInt8] {
            throw KeystoreError.cryptoError("CryptoKit not available on this platform")
        }
        public func decrypt(_ ciphertext: [UInt8]) throws -> [UInt8] {
            throw KeystoreError.cryptoError("CryptoKit not available on this platform")
        }
    }

    public static func readerCipher(_ skReader: [UInt8]) -> SessionCipher { SessionCipher() }
    public static func deviceCipher(_ skDevice: [UInt8]) -> SessionCipher { SessionCipher() }

    public static func computeIdent(_ eDeviceKeyBytes: [UInt8]) -> [UInt8] {
        fatalError("CryptoKit required for ProximitySessionCrypto. Not available on this platform.")
    }

    #endif
}

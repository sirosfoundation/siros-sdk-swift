// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@preconcurrency import SwiftCBOR
@testable import SirosKeystore

#if canImport(CryptoKit)
import CryptoKit

/// Verifies `ProximitySessionCrypto` against the real ISO/IEC 18013-5 Annex
/// D.5.1 "Session encryption" worked example - the same source PDF as
/// `NfcHandoverSelectTests` (see that file's doc comment). Independently
/// re-derived and cross-checked byte-for-byte with a standalone Python
/// script (`cryptography` library: real ECDH + HKDF + AES-256-GCM) before
/// being hardcoded in the Kotlin SDK this is ported from
/// (`ProximitySessionCryptoTest.kt`), including a full decrypt of the
/// vector's own `SessionEstablishment` ciphertext down to the exact Annex
/// D.4.1.1 mdoc request CBOR.
///
/// CryptoKit-only (real ECDH/HKDF/AES-GCM) - cannot compile or run on
/// Linux; this test only exercises the Apple-platform implementation and
/// needs to be run on real macOS/iOS hardware (or the Mac mini builder) to
/// actually verify anything. A Linux build only ever compiles the
/// `#else` stub paths in `ProximitySessionCrypto`, never this file.
final class ProximitySessionCryptoTests: XCTestCase {

    // Annex D.5.1's ephemeral device/reader key pairs (P-256).
    private let eDeviceKeyX = "5a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe"
    private let eDeviceKeyY = "b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67"
    private let eDeviceKeyD = "c1917a1579949a042f1ba9fc53a2df9b1bc47adf31c10f813ed75702d1c1f136"
    private let eReaderKeyX = "60e3392385041f51403051f2415531cb56dd3f999c71687013aac6768bc8187e"
    private let eReaderKeyY = "e58deb8fdbe907f7dd5368245551a34796f7d2215c440c339bb0f7b67beccdfa"
    private let eReaderKeyD = "de3b4b9e5f72dd9b58406ae3091434da48a6f9fd010d88fcb0958e2cebec947c"

    private let expectedSkReader = "58d277d8719e62a1561d248f403f477e9e6c37bf5d5fc5126f8f4c727c22dfc9"
    private let expectedSkDevice = "81d170e07fbdac93c1a676242c2576124a380d87bb73ed9ce4834de2272cf409"

    /// Bare (untagged) `SessionTranscript` array bytes from Annex D.5.1 - see
    /// `ProximitySessionCrypto.deriveSessionKeys`'s doc comment on why bare,
    /// not tag-24-wrapped.
    private let bareSessionTranscriptHex =
        "83d8185858a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d9" +
        "3e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67d81858" +
        "4ba40102200121582060e3392385041f51403051f2415531cb56dd3f999c71687013aac6768bc8187e225820e58deb8f" +
        "dbe907f7dd5368245551a34796f7d2215c440c339bb0f7b67beccdfa8258c391020f487315d10209616301013001046d" +
        "646f631a200c016170706c69636174696f6e2f766e642e626c7565746f6f74682e6c652e6f6f6230081b28128b372828" +
        "01021c015c1e580469736f2e6f72673a31383031333a646576696365656e676167656d656e746d646f63a20063312e30" +
        "018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe22" +
        "5820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc6758cd910225487215910202637201" +
        "02110204616301013000110206616301036e6663005102046163010157001a201e016170706c69636174696f6e2f766e" +
        "642e626c7565746f6f74682e6c652e6f6f6230081b28078080bf2801021c021107c832fff6d26fa0beb34dfcd555d482" +
        "3a1c11010369736f2e6f72673a31383031333a6e66636e6663015a172b016170706c69636174696f6e2f766e642e7766" +
        "612e6e616e57030101032302001324fec9a70b97ac9684a4e326176ef5b981c5e8533e5f00298cfccbc35e700a6b0204" +
        "14"

    /// Annex D.5.1's full `SessionEstablishment` CBOR message.
    private let sessionEstablishmentHex =
        "a26a655265616465724b6579d818584ba40102200121582060e3392385041f51403051f2415531cb56dd3f999c716870" +
        "13aac6768bc8187e225820e58deb8fdbe907f7dd5368245551a34796f7d2215c440c339bb0f7b67beccdfa6464617461" +
        "5902df52ada2acbeb6c390f2ca0bc659b484678eb94dd45074386aadece23777b44606e42e2846bc2e2ee3c1e867b1d1" +
        "685e41354a021abb0fda36f09cf5d5c51b561d3be41c9347ae71cf2b49de9dec7b44046ab02247931b210c9157840c15" +
        "14a6027b08810716adf61966344979314ac3ae9f40e66e015c1254a684108bd093e8772ec333fb663fd6803af02ea10b" +
        "dbe83a999f75b55a180f872139fb57ac04acd58ca15eca150cde1c3b849401188b7a30ce887dd7b71b12eda2fc6ec6e5" +
        "235a6c9498351fcd301f2292a4ebba7555285cee84ead96ef1677b0af8239f6a7a52af4b8809b1d52ab21a162ca31ade" +
        "21c57bd1d9970a2832aac41c7d52d1c4fee4ee64030a218df51363be701792fa6c515c489bd39dcad6fba48f1d6eb19e" +
        "9c769531a3bf9998a32c01841305f23844ca3db6a1ff0d0d917343d62fc72ad58eab01a3198116f19606609f94e35eac" +
        "b78d23c59c67852a361915fe87848cdba5630c99fab71aeff72d131cf442654f7708ec48216416f2d996cf6cf91012b7" +
        "71b88907b1d1629dfa794343e653c31207482e2f6621cd4b5dcf3b3c328625c33fe98be99c5f264a264315be41bafdc7" +
        "26f8bcde5920de0a71884d860af44c1ff1b3d78b2e8d720d85dae53fea2b3fa1806162a4be02d039567c5eb2419c2ad8" +
        "79af48fcb7df55ca94f1b00f62187fa2329c8227aae0130ec052ca3e2102e57e72911b328cfdcfbaaf6b9364660f6134" +
        "15382644c30c0bd4e222c5cf94ba5a73679c53d5ced95ca50787c2289a0c17358393c1e0f2272361002fb9b160606888" +
        "a59ef7a2c389f68b7cb424572db026b17cf2bdcafcb67c8292d92b50050356900a62a82b16f854759052b00f0f4673a4" +
        "6229f43257e8e8325401b3fecc8c6d2258baf7f7c2fbbafab3a1b6aded4eceac1eafd5b61118df93bc0a622b03504fde" +
        "47cebb224e983db12677e316c22aae042d6ce4adae0d8b0f40437b8e1afa0859c9501beb63974496859a60f11069b196" +
        "5b4ffac5779a96191f89eac7caa688b9e67c"

    private func hex(_ s: String) -> [UInt8] {
        let clean = s.replacingOccurrences(of: " ", with: "").replacingOccurrences(of: "\n", with: "")
        var result: [UInt8] = []
        var idx = clean.startIndex
        while idx < clean.endIndex {
            let next = clean.index(idx, offsetBy: 2)
            result.append(UInt8(clean[idx..<next], radix: 16)!)
            idx = next
        }
        return result
    }

    private func ecPrivateKey(_ d: String) throws -> P256.KeyAgreement.PrivateKey {
        try P256.KeyAgreement.PrivateKey(rawRepresentation: hex(d))
    }

    private func ecPublicKey(_ x: String, _ y: String) throws -> P256.KeyAgreement.PublicKey {
        let x963 = [0x04] + hex(x) + hex(y)
        return try P256.KeyAgreement.PublicKey(x963Representation: x963)
    }

    func testDeriveSessionKeys_matchesTheOfficialVectorsExactly() throws {
        let eDevicePriv = try ecPrivateKey(eDeviceKeyD)
        let eReaderPub = try ecPublicKey(eReaderKeyX, eReaderKeyY)
        let sessionTranscript = hex(bareSessionTranscriptHex)

        let keys = try ProximitySessionCrypto.deriveSessionKeys(
            eDeviceKeyPrivate: eDevicePriv,
            eReaderKeyPublic: eReaderPub,
            sessionTranscript: sessionTranscript
        )

        XCTAssertEqual(keys.skReader, hex(expectedSkReader))
        XCTAssertEqual(keys.skDevice, hex(expectedSkDevice))
    }

    func testDeriveSessionKeys_isSymmetric_fromTheReadersPerspective() throws {
        // The mdoc reader computes the SAME keys using (EReaderKey.Priv, EDeviceKey.Pub) - §12.2.5.
        let eReaderPriv = try ecPrivateKey(eReaderKeyD)
        let eDevicePub = try ecPublicKey(eDeviceKeyX, eDeviceKeyY)
        let sessionTranscript = hex(bareSessionTranscriptHex)

        let keys = try ProximitySessionCrypto.deriveSessionKeys(
            eDeviceKeyPrivate: eReaderPriv,
            eReaderKeyPublic: eDevicePub,
            sessionTranscript: sessionTranscript
        )

        XCTAssertEqual(keys.skReader, hex(expectedSkReader))
        XCTAssertEqual(keys.skDevice, hex(expectedSkDevice))
    }

    func testReaderCipher_decryptsTheOfficialSessionEstablishmentCiphertext_toARealMdocRequest() throws {
        let eDevicePriv = try ecPrivateKey(eDeviceKeyD)
        let eReaderPub = try ecPublicKey(eReaderKeyX, eReaderKeyY)
        let sessionTranscript = hex(bareSessionTranscriptHex)
        let keys = try ProximitySessionCrypto.deriveSessionKeys(
            eDeviceKeyPrivate: eDevicePriv,
            eReaderKeyPublic: eReaderPub,
            sessionTranscript: sessionTranscript
        )

        let established = try ProximitySessionMessages.parseSessionEstablishment(hex(sessionEstablishmentHex))
        let plaintext = try ProximitySessionCrypto.readerCipher(keys.skReader).decrypt(established.encryptedData)

        let request = try CBOR.decode(plaintext)
        guard case .utf8String(let version)? = request?["version"] else {
            return XCTFail("missing version")
        }
        XCTAssertEqual(version, "1.0")
        guard case .array(let docRequests)? = request?["docRequests"] else {
            return XCTFail("missing docRequests")
        }
        XCTAssertGreaterThanOrEqual(docRequests.count, 1)
    }

    func testDeviceCipher_roundTrips_withTheMdocIdentifierAndIncrementingCounter() throws {
        let key = (0..<32).map { UInt8($0) }
        let plaintext = Array("same mdoc response, encrypted twice".utf8)

        let encryptor = ProximitySessionCrypto.deviceCipher(key)
        let ciphertext1 = try encryptor.encrypt(plaintext)
        let ciphertext2 = try encryptor.encrypt(plaintext)

        XCTAssertNotEqual(
            ciphertext1, ciphertext2,
            "re-encrypting the same plaintext must change the ciphertext once the counter increments the IV"
        )

        let decryptor = ProximitySessionCrypto.deviceCipher(key)
        XCTAssertEqual(try decryptor.decrypt(ciphertext1), plaintext)
        XCTAssertEqual(try decryptor.decrypt(ciphertext2), plaintext)
    }

    func testParseEReaderKeyPublic_recoversTheSameKeyUsedToDeriveTheOfficialVector() throws {
        let established = try ProximitySessionMessages.parseSessionEstablishment(hex(sessionEstablishmentHex))
        let parsedPub = try ProximitySessionCrypto.parseEReaderKeyPublic(established.eReaderKeyBytes)

        let x963 = parsedPub.x963Representation
        XCTAssertEqual([UInt8](x963[1..<33]), hex(eReaderKeyX))
        XCTAssertEqual([UInt8](x963[33..<65]), hex(eReaderKeyY))
    }
}

#endif

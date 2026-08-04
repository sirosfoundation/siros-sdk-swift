// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@preconcurrency import SwiftCBOR
@testable import SirosKeystore

/// Verifies `DeviceRequestParser` against a real ISO/IEC 18013-5 mdoc
/// request: the plaintext recovered by the Kotlin SDK's
/// `ProximitySessionCryptoTest`'s own decrypt of the Annex D.5.1
/// `SessionEstablishment` ciphertext (which is, per the spec's own text,
/// exactly the Annex D.4.1.1 request) - reusing that already-verified
/// plaintext instead of re-transcribing D.4.1.1's raw hex separately (its
/// own dump includes a long `readerAuth` X.509 chain across a page break,
/// which isn't needed to test parsing). Ported from
/// `org.siros.sdk.keystore.mdoc.DeviceRequestParserTest` (Kotlin).
///
/// Pure CBOR parsing - no platform-crypto dependency, runs on every platform.
final class DeviceRequestParserTests: XCTestCase {

    private let realDeviceRequestHex =
        "a26776657273696f6e63312e306b646f63526571756573747381a26c6974656d7352657175657374d8185893a267646f" +
        "6354797065756f72672e69736f2e31383031332e352e312e6d444c6a6e616d65537061636573a1716f72672e69736f2e" +
        "31383031332e352e31a66b66616d696c795f6e616d65f56f646f63756d656e745f6e756d626572f57264726976696e67" +
        "5f70726976696c65676573f56a69737375655f64617465f56b6578706972795f64617465f568706f727472616974f46a" +
        "726561646572417574688443a10126a118215901b7308201b330820158a00302010202147552715f6add323d4934a1ba" +
        "175dc945755d8b50300a06082a8648ce3d04030230163114301206035504030c0b72656164657220726f6f74301e170d" +
        "3230313030313030303030305a170d3233313233313030303030305a3011310f300d06035504030c0672656164657230" +
        "59301306072a8648ce3d020106082a8648ce3d03010703420004f8912ee0f912b6be683ba2fa0121b2630e601b2b628d" +
        "ff3b44f6394eaa9abdbcc2149d29d6ff1a3e091135177e5c3d9c57f3bf839761eed02c64dd82ae1d3bbfa38188308185" +
        "301c0603551d1f041530133011a00fa00d820b6578616d706c652e636f6d301d0603551d0e04160414f2dfc4acafc5f3" +
        "0b464fada20bfcd533af5e07f5301f0603551d23041830168014cfb7a881baea5f32b6fb91cc29590c50dfac416e300e" +
        "0603551d0f0101ff04040302078030150603551d250101ff040b3009060728818c5d050106300a06082a8648ce3d0403" +
        "020349003046022100fb9ea3b686fd7ea2f0234858ff8328b4efef6a1ef71ec4aae4e307206f9214930221009b94f0d7" +
        "39dfa84cca29efed529dd4838acfd8b6bee212dc6320c46feb839a35f658401f3400069063c189138bdcd2f631427c58" +
        "9424113fc9ec26cebcacacfcdb9695d28e99953becabc4e30ab4efacc839a81f9159933d192527ee91b449bb7f80bf"

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

    func testParseRealMdlRequest_extractsDocTypeAndRequestedElements() throws {
        let docRequests = try DeviceRequestParser.parse(hex(realDeviceRequestHex))

        XCTAssertEqual(docRequests.count, 1)
        let doc = docRequests[0]
        XCTAssertEqual(doc.docType, "org.iso.18013.5.1.mDL")
        XCTAssertNotNil(doc.requestedItems["org.iso.18013.5.1"])

        let elements = Set(doc.requestedItems["org.iso.18013.5.1"] ?? [])
        XCTAssertEqual(
            elements,
            Set(["family_name", "document_number", "driving_privileges", "issue_date", "expiry_date", "portrait"])
        )
    }

    func testDisclosedClaims_flattensAcrossNamespaces() throws {
        let docRequests = try DeviceRequestParser.parse(hex(realDeviceRequestHex))
        XCTAssertEqual(docRequests[0].disclosedClaims().count, 6)
    }

    func testParse_missingDocRequests_throws() {
        let bytes = CBOR.map([.utf8String("version"): .utf8String("1.0")]).encode()

        XCTAssertThrowsError(try DeviceRequestParser.parse(bytes))
    }
}

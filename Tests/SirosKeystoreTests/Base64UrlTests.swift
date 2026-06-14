// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore

final class Base64UrlTests: XCTestCase {

    func testBase64UrlRoundTrip() {
        let input = Data([0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD])
        let encoded = EncryptedContainer.base64UrlEncode(input)
        let decoded = EncryptedContainer.base64UrlDecode(encoded)
        XCTAssertEqual(input, decoded)
    }

    func testBase64UrlNoPadding() {
        let encoded = EncryptedContainer.base64UrlEncode(Data([1, 2, 3]))
        XCTAssertFalse(encoded.contains("="))
    }

    func testBase64UrlNoSlash() {
        // Generate data that would produce + and / in standard base64
        let data = Data([0xFB, 0xFF, 0xFE])
        let encoded = EncryptedContainer.base64UrlEncode(data)
        XCTAssertFalse(encoded.contains("+"))
        XCTAssertFalse(encoded.contains("/"))
    }

    func testBase64UrlDecodeWithPadding() {
        // Standard base64 with padding should also decode
        let decoded = EncryptedContainer.base64UrlDecode("AQID")
        XCTAssertEqual(decoded, Data([1, 2, 3]))
    }

    func testBase64UrlDecodeEmpty() {
        let decoded = EncryptedContainer.base64UrlDecode("")
        XCTAssertTrue(decoded.isEmpty)
    }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@preconcurrency import SwiftCBOR
@testable import SirosKeystore

#if canImport(CryptoKit)
import CryptoKit

/// Structural conformance tests against ISO 18013-5 §8.2.1.1's
/// `DeviceEngagement` CDDL (map keys 0/1/2, `Security` array shape,
/// tag-24-wrapped `EDeviceKeyBytes`, `BleOptions` key numbers). Verified
/// against the SHAPE of Annex D.3.1's worked example, not its exact byte
/// values - matching the Kotlin SDK's `DeviceEngagementTest.kt`, which notes
/// the example's hex was only available via OCR'd PDF text in that session
/// and wasn't trustworthy enough to hardcode as a byte-exact fixture
/// (canonical map-key ordering isn't required by the spec anyway, so a
/// byte-exact comparison against a fresh keypair wouldn't be meaningful
/// regardless). A clean copy of the official vector should replace this with
/// real byte-exact assertions when available.
final class DeviceEngagementTests: XCTestCase {

    func testCreate_bothBleModes_producesSpecShapedStructure() throws {
        let engagement = try DeviceEngagement.create(
            supportsCentralClientMode: true,
            supportsPeripheralServerMode: true
        )

        let decoded = try CBOR.decode(engagement.deviceEngagementBytes)
        guard case .utf8String(let version)? = decoded?[CBOR.unsignedInt(0)] else {
            return XCTFail("missing version")
        }
        XCTAssertEqual(version, "1.0")

        guard case .array(let security)? = decoded?[CBOR.unsignedInt(1)] else {
            return XCTFail("missing Security")
        }
        XCTAssertEqual(security.count, 2)
        guard case .unsignedInt(let cipherSuite) = security[0] else {
            return XCTFail("cipher suite not an int")
        }
        XCTAssertEqual(cipherSuite, 1)

        let eDeviceKeyBytes = security[1]
        guard case .tagged(let tag, let content) = eDeviceKeyBytes, tag == .encodedCBORDataItem,
              case .byteString(let coseKeyBytes) = content else {
            return XCTFail("EDeviceKeyBytes not tag-24-wrapped")
        }
        let coseKey = try CBOR.decode(coseKeyBytes)
        guard case .unsignedInt(let kty)? = coseKey?[CBOR(integerLiteral: 1)] else {
            return XCTFail("missing kty")
        }
        XCTAssertEqual(kty, 2) // EC2
        guard case .unsignedInt(let crv)? = coseKey?[CBOR(integerLiteral: -1)] else {
            return XCTFail("missing crv")
        }
        XCTAssertEqual(crv, 1) // P-256

        let x963 = engagement.publicKey.x963Representation
        guard case .byteString(let x)? = coseKey?[CBOR(integerLiteral: -2)],
              case .byteString(let y)? = coseKey?[CBOR(integerLiteral: -3)] else {
            return XCTFail("missing x/y")
        }
        XCTAssertEqual(x, [UInt8](x963[1..<33]))
        XCTAssertEqual(y, [UInt8](x963[33..<65]))

        guard case .array(let retrievalMethods)? = decoded?[CBOR.unsignedInt(2)] else {
            return XCTFail("missing DeviceRetrievalMethods")
        }
        XCTAssertEqual(retrievalMethods.count, 1)
        let ble = retrievalMethods[0]
        guard case .unsignedInt(let bleType)? = ble[CBOR.unsignedInt(0)],
              case .unsignedInt(let bleVersion)? = ble[CBOR.unsignedInt(1)] else {
            return XCTFail("malformed BLE retrieval method")
        }
        XCTAssertEqual(bleType, 2)
        XCTAssertEqual(bleVersion, 1)
        let bleOptions = ble[CBOR.unsignedInt(2)]
        guard case .boolean(let supportsPeripheral)? = bleOptions?[CBOR.unsignedInt(0)],
              case .boolean(let supportsCentral)? = bleOptions?[CBOR.unsignedInt(1)] else {
            return XCTFail("missing BleOptions flags")
        }
        XCTAssertTrue(supportsPeripheral)
        XCTAssertTrue(supportsCentral)
        guard case .byteString(let peripheralUuidBytes)? = bleOptions?[CBOR.unsignedInt(10)],
              case .byteString(let centralUuidBytes)? = bleOptions?[CBOR.unsignedInt(11)] else {
            return XCTFail("missing BLE UUIDs")
        }
        XCTAssertEqual(peripheralUuidBytes.count, 16)
        XCTAssertEqual(centralUuidBytes.count, 16)
    }

    func testCreate_centralOnly_omitsPeripheralUuidAndSetsFlagsCorrectly() throws {
        let engagement = try DeviceEngagement.create(
            supportsCentralClientMode: true,
            supportsPeripheralServerMode: false
        )

        XCTAssertNil(engagement.peripheralServerModeUuid)
        let decoded = try CBOR.decode(engagement.deviceEngagementBytes)
        guard case .array(let retrievalMethods)? = decoded?[CBOR.unsignedInt(2)] else {
            return XCTFail("missing DeviceRetrievalMethods")
        }
        let bleOptions = retrievalMethods[0][CBOR.unsignedInt(2)]
        guard case .boolean(let supportsPeripheral)? = bleOptions?[CBOR.unsignedInt(0)],
              case .boolean(let supportsCentral)? = bleOptions?[CBOR.unsignedInt(1)] else {
            return XCTFail("missing BleOptions flags")
        }
        XCTAssertFalse(supportsPeripheral)
        XCTAssertTrue(supportsCentral)
        XCTAssertNil(bleOptions?[CBOR.unsignedInt(10)])
        guard case .byteString(let centralUuidBytes)? = bleOptions?[CBOR.unsignedInt(11)] else {
            return XCTFail("missing central UUID")
        }
        XCTAssertEqual(centralUuidBytes.count, 16)
    }

    func testCreate_neitherBleMode_throws() {
        XCTAssertThrowsError(
            try DeviceEngagement.create(supportsCentralClientMode: false, supportsPeripheralServerMode: false)
        )
    }

    func testMdocUri_isMdocSchemePrefixedBase64UrlWithoutPadding() throws {
        let engagement = try DeviceEngagement.create()

        XCTAssertTrue(engagement.mdocUri.hasPrefix("mdoc:"))
        let encoded = String(engagement.mdocUri.dropFirst("mdoc:".count))
        XCTAssertFalse(encoded.contains("="), "must not contain padding")

        var base64 = encoded.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 { base64 += "=" }
        guard let decodedData = Data(base64Encoded: base64) else {
            return XCTFail("not valid base64url")
        }
        XCTAssertEqual([UInt8](decodedData), engagement.deviceEngagementBytes)
    }

    func testCreate_generatesFreshKeyAndUuidsPerCall() throws {
        let first = try DeviceEngagement.create()
        let second = try DeviceEngagement.create()

        XCTAssertNotEqual(first.deviceEngagementBytes, second.deviceEngagementBytes)
        XCTAssertNotEqual(first.centralClientModeUuid, second.centralClientModeUuid)
    }
}

#endif

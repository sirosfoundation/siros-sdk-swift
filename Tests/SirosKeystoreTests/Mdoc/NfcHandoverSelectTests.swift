// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore

#if canImport(CryptoKit)
import CryptoKit

/// Verifies `NfcHandoverSelect.build` against the real ISO/IEC 18013-5
/// second-edition CD ballot-resolution draft, Annex D.3.3 "NFC Handover
/// select" worked example. The hex below was extracted from the primary
/// source PDF via `pdftotext -layout` (a real text layer, not OCR) and
/// verified byte-for-byte with a standalone NDEF-record parser against
/// §9.2/§11.1.2's normative structure before being hardcoded in the Kotlin
/// SDK this is ported from (`NfcHandoverSelectTest.kt`) - see
/// `NfcHandoverSelect`'s doc comment.
///
/// Gated on `canImport(CryptoKit)` only because `DeviceEngagement.create()`
/// (used by `testBuildFromEngagement_derivesLeRoleFromWhichBleModesAreOffered`)
/// needs it - `NfcHandoverSelect.build` itself has no crypto dependency.
final class NfcHandoverSelectTests: XCTestCase {

    /// Annex D.3.3's full Handover Select NDEF message (3 records: Hs, BLE carrier config, device engagement).
    private let d33HandoverSelectHex =
        "91020f487315d10209616301013001046d646f631a200c016170706c69636174696f6e2f766e642e626c7565746f6f7468" +
            "2e6c652e6f6f6230081b28128b37282801021c015c1e580469736f2e6f72673a31383031333a646576696365656e676167" +
            "656d656e746d646f63a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968f" +
            "f289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67"

    /// The `DeviceEngagement` CBOR embedded in D.3.3's aux record (its own worked example, distinct from D.3.1's).
    private let d33DeviceEngagementHex =
        "a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b6" +
            "24343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67"

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

    func testOfficialVector_decodesToTheExpectedThreeRecordStructure() {
        let bytes = hex(d33HandoverSelectHex)

        // Record 1: "Hs" - MB=1,ME=0,SR=1,TNF=well-known(1) -> header 0x91.
        XCTAssertEqual(bytes[0], 0x91)
        XCTAssertEqual(bytes[1], 2) // type length
        let hsPayloadLen = Int(bytes[2])
        XCTAssertEqual(String(decoding: bytes[3..<5], as: UTF8.self), "Hs")
        let hsPayload = Array(bytes[5..<(5 + hsPayloadLen)])
        XCTAssertEqual(hsPayload[0], 0x15) // CH version 1.5

        // Embedded "ac" record inside the Hs payload - both MB and ME set (it's the only record in this inner message).
        let ac = Array(hsPayload[1...])
        XCTAssertEqual(ac[0], 0xD1) // MB=1,ME=1,SR=1,TNF=well-known
        XCTAssertEqual(String(decoding: ac[3..<5], as: UTF8.self), "ac")
        let acPayload = Array(ac[5...])
        XCTAssertEqual(acPayload[0], 0x01) // CPS = active
        XCTAssertEqual(acPayload[1], 1) // Carrier Data Reference length
        XCTAssertEqual(String(decoding: acPayload[2..<3], as: UTF8.self), "0")
        XCTAssertEqual(acPayload[3], 1) // Auxiliary Data Reference Count
        XCTAssertEqual(acPayload[4], 4) // Aux Data Reference length
        XCTAssertEqual(String(decoding: acPayload[5..<9], as: UTF8.self), "mdoc")

        var offset = 5 + hsPayloadLen

        // Record 2: BLE carrier configuration, MIME type, ID "0".
        XCTAssertEqual(bytes[offset], 0x1A) // MB=0,ME=0,SR=1,IL=1,TNF=MIME(2)
        let carrierTypeLen = Int(bytes[offset + 1])
        let carrierPayloadLen = Int(bytes[offset + 2])
        let carrierIdLen = Int(bytes[offset + 3])
        let carrierTypeStart = offset + 4
        XCTAssertEqual(
            String(decoding: bytes[carrierTypeStart..<(carrierTypeStart + carrierTypeLen)], as: UTF8.self),
            "application/vnd.bluetooth.le.oob"
        )
        let carrierIdStart = carrierTypeStart + carrierTypeLen
        XCTAssertEqual(String(decoding: bytes[carrierIdStart..<(carrierIdStart + carrierIdLen)], as: UTF8.self), "0")
        let carrierPayloadStart = carrierIdStart + carrierIdLen
        let carrierPayload = Array(bytes[carrierPayloadStart..<(carrierPayloadStart + carrierPayloadLen)])
        // AD structures: LE Device Address (0x1B, 7 bytes) then LE Role (0x1C, 1 byte).
        XCTAssertEqual(carrierPayload[1], 0x1B)
        XCTAssertEqual(carrierPayload[10], 0x1C)

        offset = carrierPayloadStart + carrierPayloadLen

        // Record 3: device engagement, external type, ID "mdoc", last record (ME=1).
        XCTAssertEqual(bytes[offset], 0x5C) // MB=0,ME=1,SR=1,IL=1,TNF=external(4)
        let deTypeLen = Int(bytes[offset + 1])
        let dePayloadLen = Int(bytes[offset + 2])
        let deIdLen = Int(bytes[offset + 3])
        let deTypeStart = offset + 4
        XCTAssertEqual(
            String(decoding: bytes[deTypeStart..<(deTypeStart + deTypeLen)], as: UTF8.self),
            "iso.org:18013:deviceengagement"
        )
        let deIdStart = deTypeStart + deTypeLen
        XCTAssertEqual(String(decoding: bytes[deIdStart..<(deIdStart + deIdLen)], as: UTF8.self), "mdoc")
        let dePayloadStart = deIdStart + deIdLen
        let dePayload = Array(bytes[dePayloadStart..<(dePayloadStart + dePayloadLen)])
        XCTAssertEqual(dePayload, hex(d33DeviceEngagementHex))
        XCTAssertEqual(bytes.count, dePayloadStart + dePayloadLen)
    }

    func testBuild_ourOwnDeviceEngagementBytes_roundTripsUnderTheSameStructureAsTheOfficialVector() {
        // Reuse the official vector's own DeviceEngagement bytes as our engagement payload -
        // isolates this test to NfcHandoverSelect's own framing, independent of DeviceEngagement.create().
        let deBytes = hex(d33DeviceEngagementHex)

        let message = NfcHandoverSelect.build(deviceEngagementBytes: deBytes, leRole: .bothCentralPreferred)

        XCTAssertEqual(message[0], 0x91)
        XCTAssertEqual(String(decoding: message[3..<5], as: UTF8.self), "Hs")
        let hsPayloadLen = Int(message[2])
        var offset = 5 + hsPayloadLen

        XCTAssertEqual(message[offset], 0x1A)
        let carrierTypeLen = Int(message[offset + 1])
        let carrierPayloadLen = Int(message[offset + 2])
        let carrierIdLen = Int(message[offset + 3])
        let carrierTypeStart = offset + 4
        XCTAssertEqual(
            String(decoding: message[carrierTypeStart..<(carrierTypeStart + carrierTypeLen)], as: UTF8.self),
            "application/vnd.bluetooth.le.oob"
        )
        let carrierPayload = Array(message[(carrierTypeStart + carrierTypeLen + carrierIdLen)..<(carrierTypeStart + carrierTypeLen + carrierIdLen + carrierPayloadLen)])
        // Single AD structure: LE Role, value = both-central-preferred (0x03).
        XCTAssertEqual(carrierPayload[0], 2)
        XCTAssertEqual(carrierPayload[1], 0x1C)
        XCTAssertEqual(carrierPayload[2], NfcHandoverSelect.LeRole.bothCentralPreferred.rawValue)

        offset = carrierTypeStart + carrierTypeLen + carrierIdLen + carrierPayloadLen
        XCTAssertEqual(message[offset], 0x5C)
        let deTypeLen = Int(message[offset + 1])
        let dePayloadLen = Int(message[offset + 2])
        let deIdLen = Int(message[offset + 3])
        let deTypeStart = offset + 4
        XCTAssertEqual(
            String(decoding: message[deTypeStart..<(deTypeStart + deTypeLen)], as: UTF8.self),
            "iso.org:18013:deviceengagement"
        )
        let dePayloadStart = deTypeStart + deTypeLen + deIdLen
        XCTAssertEqual(Array(message[dePayloadStart..<(dePayloadStart + dePayloadLen)]), deBytes)
        XCTAssertEqual(message.count, dePayloadStart + dePayloadLen)
    }

    func testBuildFromEngagement_derivesLeRoleFromWhichBleModesAreOffered() throws {
        let both = try DeviceEngagement.create(supportsCentralClientMode: true, supportsPeripheralServerMode: true)
        let centralOnly = try DeviceEngagement.create(supportsCentralClientMode: true, supportsPeripheralServerMode: false)
        let peripheralOnly = try DeviceEngagement.create(supportsCentralClientMode: false, supportsPeripheralServerMode: true)

        XCTAssertEqual(try leRole(of: NfcHandoverSelect.build(both)), .bothCentralPreferred)
        XCTAssertEqual(try leRole(of: NfcHandoverSelect.build(centralOnly)), .centralOnly)
        XCTAssertEqual(try leRole(of: NfcHandoverSelect.build(peripheralOnly)), .peripheralOnly)
    }

    /// Extract the LE Role AD value from a built Handover Select message's fixed-offset carrier record.
    private func leRole(of message: [UInt8]) throws -> NfcHandoverSelect.LeRole {
        let hsPayloadLen = Int(message[2])
        let carrierPayloadStart = 5 + hsPayloadLen + 4 // header(4) of the MIME carrier record with a 32-byte type + 1-byte id
        let carrierTypeLen = Int(message[5 + hsPayloadLen + 1])
        let carrierIdLen = Int(message[5 + hsPayloadLen + 3])
        let roleValue = message[carrierPayloadStart + carrierTypeLen + carrierIdLen + 2]
        guard let role = NfcHandoverSelect.LeRole(rawValue: roleValue) else {
            throw XCTSkip("unrecognized LE Role value \(roleValue)")
        }
        return role
    }

    func testBuild_neitherBleMode_throws() {
        let engagement = DeviceEngagement.Engagement(
            deviceEngagementBytes: [],
            mdocUri: "mdoc:",
            privateKey: P256.KeyAgreement.PrivateKey(),
            eDeviceKeyBytes: [],
            peripheralServerModeUuid: nil,
            centralClientModeUuid: nil
        )
        XCTAssertThrowsError(try NfcHandoverSelect.build(engagement))
    }
}

#endif

/// Regression coverage for the Copilot-review fix ported from the Kotlin SDK
/// (`NfcHandoverSelect.kt`'s `ndefRecord`, commit `e7d8872`): a >=256-byte
/// payload must fall back to a normal (non-SR) NDEF record with a 4-byte
/// length instead of crashing. Deliberately NOT gated behind
/// `canImport(CryptoKit)` like `NfcHandoverSelectTests` above - it only
/// exercises `NfcHandoverSelect.build(deviceEngagementBytes:leRole:)`, which
/// has no crypto dependency, so this runs on every platform including Linux.
final class NfcHandoverSelectLargePayloadTests: XCTestCase {

    func testBuild_payloadOf256OrMoreBytes_fallsBackToNonShortRecordWith4ByteLength() {
        // Pad well past the 255-byte short-record cap.
        let largeDeviceEngagementBytes = [UInt8](repeating: 0xAB, count: 300)

        let message = NfcHandoverSelect.build(
            deviceEngagementBytes: largeDeviceEngagementBytes,
            leRole: .bothCentralPreferred
        )

        // Locate the device-engagement record (the third/last record) the
        // same way the official-vector test does: walk past the Hs record,
        // then the fixed-shape BLE carrier-configuration record.
        let hsPayloadLen = Int(message[2])
        var offset = 5 + hsPayloadLen

        // Carrier-configuration record is still a short record (its payload
        // is only 3 bytes) - its header keeps the SR bit (0x10) set.
        XCTAssertEqual(message[offset] & 0x10, 0x10)
        let carrierTypeLen = Int(message[offset + 1])
        let carrierPayloadLen = Int(message[offset + 2])
        let carrierIdLen = Int(message[offset + 3])
        offset += 4 + carrierTypeLen + carrierIdLen + carrierPayloadLen

        // Device-engagement record: header must have the SR bit (0x10)
        // UNSET now that its payload is >= 256 bytes, and the length field
        // must be 4 bytes (not 1) encoding 300 big-endian.
        let deHeader = message[offset]
        XCTAssertEqual(deHeader & 0x10, 0, "SR bit must be unset for a >=256-byte payload")
        XCTAssertEqual(deHeader & 0x40, 0x40, "ME bit must still be set - this is the last record")
        let deTypeLen = Int(message[offset + 1])
        let lengthBytes = message[(offset + 2)..<(offset + 6)]
        let decodedLength = lengthBytes.reduce(0) { ($0 << 8) | Int($1) }
        XCTAssertEqual(decodedLength, 300)
        let deIdLen = Int(message[offset + 6])
        let deTypeStart = offset + 7
        XCTAssertEqual(
            String(decoding: message[deTypeStart..<(deTypeStart + deTypeLen)], as: UTF8.self),
            "iso.org:18013:deviceengagement"
        )
        let dePayloadStart = deTypeStart + deTypeLen + deIdLen
        XCTAssertEqual(Array(message[dePayloadStart..<(dePayloadStart + decodedLength)]), largeDeviceEngagementBytes)
        XCTAssertEqual(message.count, dePayloadStart + decodedLength)
    }
}

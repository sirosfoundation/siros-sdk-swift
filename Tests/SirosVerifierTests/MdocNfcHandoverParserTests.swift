// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import XCTest
@testable import SirosVerifier

final class MdocNfcHandoverParserTests: XCTestCase {
    func testOfficialAnnexD33PreservesSelectAndBuildsExactHandoverCBOR() throws {
        let select = Fixture.hex(Fixture.officialD33HandoverSelect)

        let handover = try MdocNfcHandoverParser.parse(select)

        XCTAssertEqual(handover.handoverSelectBytes, select)
        XCTAssertEqual(handover.handoverCbor, Fixture.hex(Fixture.officialD33HandoverCBOR))
        XCTAssertEqual(handover.deviceEngagementBytes, Fixture.hex(Fixture.officialD33DeviceEngagement))
        XCTAssertEqual(handover.engagement.deviceEngagementBytes, handover.deviceEngagementBytes)
        XCTAssertEqual(
            handover.eDeviceKeyBytes,
            [0xD8, 0x18] + Fixture.cborBytes(Fixture.hex(Fixture.officialD33COSEKey))
        )
        // D.3.3 has an LE device address and LE Role, but neither an OOB
        // Service UUID nor DeviceEngagement BLE options.
        XCTAssertNil(handover.ble)
        XCTAssertFalse(handover.bleSupported)
        XCTAssertEqual(try MdocNfcHandoverParser.parse(select), handover)
    }

    func testBuilderEquivalentMessagesMapAllLERolesAndPreferredUUIDs() throws {
        let bothCentral = try XCTUnwrap(MdocNfcHandoverParser.parse(Fixture.handover()).ble)
        XCTAssertTrue(bothCentral.supportsPeripheralServerMode)
        XCTAssertTrue(bothCentral.supportsCentralClientMode)
        XCTAssertEqual(bothCentral.peripheralServerModeUuid, Fixture.peripheralUUID)
        XCTAssertEqual(bothCentral.centralClientModeUuid, Fixture.centralUUID)

        let bothPeripheral = try XCTUnwrap(MdocNfcHandoverParser.parse(
            Fixture.handover(roleValue: 0x02, uuids: [Fixture.peripheralUUID])
        ).ble)
        XCTAssertTrue(bothPeripheral.supportsPeripheralServerMode)
        XCTAssertTrue(bothPeripheral.supportsCentralClientMode)
        XCTAssertEqual(bothPeripheral.peripheralServerModeUuid, Fixture.peripheralUUID)
        XCTAssertEqual(bothPeripheral.centralClientModeUuid, Fixture.centralUUID)

        let centralOnly = try XCTUnwrap(MdocNfcHandoverParser.parse(Fixture.handover(
            deviceEngagement: Fixture.engagement(peripheral: false),
            roleValue: 0x01,
            uuids: [Fixture.centralUUID]
        )).ble)
        XCTAssertFalse(centralOnly.supportsPeripheralServerMode)
        XCTAssertTrue(centralOnly.supportsCentralClientMode)
        XCTAssertNil(centralOnly.peripheralServerModeUuid)
        XCTAssertEqual(centralOnly.centralClientModeUuid, Fixture.centralUUID)

        let peripheralOnly = try XCTUnwrap(MdocNfcHandoverParser.parse(Fixture.handover(
            deviceEngagement: Fixture.engagement(central: false),
            roleValue: 0x00,
            uuids: [Fixture.peripheralUUID]
        )).ble)
        XCTAssertTrue(peripheralOnly.supportsPeripheralServerMode)
        XCTAssertFalse(peripheralOnly.supportsCentralClientMode)
        XCTAssertEqual(peripheralOnly.peripheralServerModeUuid, Fixture.peripheralUUID)
        XCTAssertNil(peripheralOnly.centralClientModeUuid)
    }

    func testOOBOnlySingleRoleUUIDMapsWithoutInventingOtherMode() throws {
        let central = try XCTUnwrap(MdocNfcHandoverParser.parse(Fixture.handover(
            deviceEngagement: Fixture.hex(Fixture.officialD33DeviceEngagement),
            roleValue: 0x01,
            uuids: [Fixture.centralUUID]
        )).ble)
        XCTAssertFalse(central.supportsPeripheralServerMode)
        XCTAssertTrue(central.supportsCentralClientMode)
        XCTAssertEqual(central.centralClientModeUuid, Fixture.centralUUID)

        let peripheral = try XCTUnwrap(MdocNfcHandoverParser.parse(Fixture.handover(
            deviceEngagement: Fixture.hex(Fixture.officialD33DeviceEngagement),
            roleValue: 0x00,
            uuids: [Fixture.peripheralUUID]
        )).ble)
        XCTAssertTrue(peripheral.supportsPeripheralServerMode)
        XCTAssertFalse(peripheral.supportsCentralClientMode)
        XCTAssertEqual(peripheral.peripheralServerModeUuid, Fixture.peripheralUUID)
    }

    func testAmbiguousBothRoleOOBWithoutDEOptionsYieldsNoBLEMetadata() throws {
        let handover = try MdocNfcHandoverParser.parse(Fixture.handover(
            deviceEngagement: Fixture.hex(Fixture.officialD33DeviceEngagement),
            roleValue: 0x03,
            uuids: [Fixture.peripheralUUID, Fixture.centralUUID]
        ))
        XCTAssertNil(handover.ble)
        XCTAssertFalse(handover.bleSupported)
    }

    func testShortAndNormalPayloadLengthsAreSupported() throws {
        let shortBytes = Fixture.handover()
        let normalBytes = Fixture.handover(forceNormalRecords: true)
        let short = try MdocNfcHandoverParser.parse(shortBytes)
        let normal = try MdocNfcHandoverParser.parse(normalBytes)

        XCTAssertEqual(short.deviceEngagementBytes, normal.deviceEngagementBytes)
        XCTAssertEqual(short.ble, normal.ble)
        XCTAssertEqual(normal.handoverCbor, Fixture.nfcHandover(normalBytes))
        XCTAssertNotEqual(short.handoverCbor, normal.handoverCbor)
    }

    func testDuplicateAndMissingDeviceEngagementAreRejected() {
        assertRejected(Fixture.handover(duplicateDeviceEngagement: true))
        assertRejected(Fixture.ndefMessage([
            Fixture.handoverSelectRecord(),
            Fixture.bluetoothCarrierRecord(roleValue: 0x03, uuids: [Fixture.centralUUID]),
        ]))
    }

    func testChunkedBadMessageFlagsAndInvalidTNFAreRejected() {
        let valid = Fixture.handover()
        var chunked = valid
        chunked[0] = 0xB1
        var missingMB = valid
        missingMB[0] = 0x11
        var reservedTNF = valid
        reservedTNF[0] = 0x96
        var unchangedTNF = valid
        unchangedTNF[0] = 0x97
        var unknownTNFWithType = valid
        unknownTNFWithType[0] = 0x95
        var emptyTNFWithType = valid
        emptyTNFWithType[0] = 0x90

        var notHandoverSelect = Fixture.handoverSelectRecord()
        notHandoverSelect.type = Array("Hr".utf8)
        let wrongFirstRecord = Fixture.ndefMessage([
            notHandoverSelect,
            Fixture.bluetoothCarrierRecord(roleValue: 0x03, uuids: [Fixture.centralUUID]),
            Fixture.deviceEngagementRecord(Fixture.engagement()),
        ])

        for candidate in [
            chunked, missingMB, reservedTNF, unchangedTNF, unknownTNFWithType,
            emptyTNFWithType, wrongFirstRecord, Fixture.handover(repeatedMessageBegin: true),
        ] {
            assertRejected(candidate)
        }
    }

    func testTruncatedMalformedLengthTrailingAndMissingMEAreRejected() {
        let valid = Fixture.handover()
        var malformedNormalLength = Fixture.handover(forceNormalRecords: true)
        // The first normal record claims a 4096-byte payload.
        malformedNormalLength[2] = 0x00
        malformedNormalLength[3] = 0x00
        malformedNormalLength[4] = 0x10
        malformedNormalLength[5] = 0x00

        for candidate in [
            [],
            Array(valid.prefix(1)),
            Array(valid.prefix(5)),
            Array(valid.dropLast()),
            malformedNormalLength,
            valid + [0x00],
            Fixture.handover(messageEnd: false),
        ] {
            assertRejected(candidate)
        }
    }

    func testOversizedInputIsRejectedBeforeNDEFParsing() {
        let candidate = [UInt8](
            repeating: 0,
            count: MdocNfcHandoverParser.maximumHandoverSelectSize + 1
        )
        XCTAssertThrowsError(try MdocNfcHandoverParser.parse(candidate)) { error in
            XCTAssertEqual(error as? MdocNfcHandoverError, .handoverTooLarge)
        }
    }

    func testMalformedBluetoothADLengthsAndRolesAreRejected() {
        let malformedPayloads = [
            [0x00],
            Fixture.hex("031c00"), // Declares three bytes after length, but only two remain.
            Fixture.ad(Fixture.adLERole, []),
            Fixture.ad(Fixture.adLERole, [0x00, 0x01]),
            Fixture.ad(Fixture.adLERole, [0x04]),
            Fixture.ad(Fixture.adCompleteUUIDs, []),
            Fixture.ad(Fixture.adCompleteUUIDs, [UInt8](repeating: 0, count: 15)),
            Fixture.ad(Fixture.adCompleteUUIDs, [UInt8](repeating: 0, count: 17)),
        ]
        for payload in malformedPayloads {
            assertRejected(Fixture.handover(carrierPayload: payload))
        }
    }

    func testConflictingRolesAndUUIDsAreRejected() {
        let roleConflict = Fixture.handover(
            deviceEngagement: Fixture.engagement(peripheral: false),
            roleValue: 0x00,
            uuids: [Fixture.peripheralUUID]
        )
        let unknownUUID = Fixture.handover(uuids: [Fixture.otherUUID])
        let wrongCentralPreferredUUID = Fixture.handover(
            roleValue: 0x03,
            uuids: [Fixture.peripheralUUID]
        )
        let wrongPeripheralPreferredUUID = Fixture.handover(
            roleValue: 0x02,
            uuids: [Fixture.centralUUID]
        )
        let duplicateRoleConflict = Fixture.handover(
            carrierPayload: Fixture.ad(Fixture.adLERole, [0x00]) +
                Fixture.ad(Fixture.adLERole, [0x01])
        )
        let ambiguousSingleRoleUUIDs = Fixture.handover(
            deviceEngagement: Fixture.hex(Fixture.officialD33DeviceEngagement),
            roleValue: 0x01,
            uuids: [Fixture.centralUUID, Fixture.peripheralUUID]
        )

        for candidate in [
            roleConflict, unknownUUID, wrongCentralPreferredUUID,
            wrongPeripheralPreferredUUID, duplicateRoleConflict, ambiguousSingleRoleUUIDs,
        ] {
            assertRejected(candidate)
        }
    }

    func testMultipleUUIDsAndUnknownADStructuresUseBluetoothByteOrder() throws {
        let payload = Fixture.ad(0xFF, [0x01, 0x02]) + Fixture.bluetoothOOB(
            roleValue: 0x03,
            uuids: [Fixture.peripheralUUID, Fixture.centralUUID]
        )
        let handover = try MdocNfcHandoverParser.parse(Fixture.handover(carrierPayload: payload))

        XCTAssertEqual(handover.ble?.peripheralServerModeUuid, Fixture.peripheralUUID)
        XCTAssertEqual(handover.ble?.centralClientModeUuid, Fixture.centralUUID)
    }

    func testStrictDeviceEngagementValidationIsReused() {
        assertRejected(Fixture.handover(deviceEngagement: [0x00]))
        assertRejected(Fixture.handover(deviceEngagement: Array(Fixture.engagement().dropLast())))
    }

    private func assertRejected(
        _ select: [UInt8],
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(try MdocNfcHandoverParser.parse(select), file: file, line: line) { error in
            XCTAssertTrue(error is MdocNfcHandoverError, "unexpected error: \(error)", file: file, line: line)
        }
    }
}

// MARK: - Independent NDEF/CBOR fixtures

private enum Fixture {
    static let adCompleteUUIDs: UInt8 = 0x07
    static let adLERole: UInt8 = 0x1C

    static let officialD33COSEKey =
        "a4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe" +
        "225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67"
    static let officialD33DeviceEngagement = "a20063312e30018201d818584b" + officialD33COSEKey
    static let officialD33HandoverSelect =
        "91020f487315d10209616301013001046d646f631a200c016170706c69636174696f6e2f766e642e626c7565746f6f7468" +
        "2e6c652e6f6f6230081b28128b37282801021c015c1e580469736f2e6f72673a31383031333a646576696365656e676167" +
        "656d656e746d646f63a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968f" +
        "f289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67"
    static let officialD33HandoverCBOR = "8258c3" + officialD33HandoverSelect + "f6"

    static let peripheralUUID = UUID(uuidString: "00112233-4455-6677-8899-aabbccddeeff")!
    static let centralUUID = UUID(uuidString: "10213243-5465-7687-98a9-bacbdcedfe0f")!
    static let otherUUID = UUID(uuidString: "01020304-0506-0708-090a-0b0c0d0e0f10")!

    struct RecordSpec {
        var tnf: UInt8
        var type: [UInt8]
        var id: [UInt8]?
        var payload: [UInt8]
        var forceNormal = false
    }

    /// Fixture equivalent to the verifier-independent NfcHandoverSelect.build framing.
    static func handover(
        deviceEngagement: [UInt8]? = nil,
        roleValue: UInt8? = 0x03,
        uuids: [UUID] = [centralUUID],
        carrierPayload: [UInt8]? = nil,
        forceNormalRecords: Bool = false,
        duplicateDeviceEngagement: Bool = false,
        messageEnd: Bool = true,
        repeatedMessageBegin: Bool = false
    ) -> [UInt8] {
        let de = deviceEngagement ?? engagement()
        var records = [
            handoverSelectRecord(forceNormal: forceNormalRecords),
            bluetoothCarrierRecord(
                roleValue: roleValue,
                uuids: uuids,
                rawPayload: carrierPayload,
                forceNormal: forceNormalRecords
            ),
            deviceEngagementRecord(de, forceNormal: forceNormalRecords),
        ]
        if duplicateDeviceEngagement {
            records.append(deviceEngagementRecord(de, forceNormal: forceNormalRecords))
        }
        return ndefMessage(
            records,
            messageEnd: messageEnd,
            repeatedMessageBegin: repeatedMessageBegin
        )
    }

    static func handoverSelectRecord(forceNormal: Bool = false) -> RecordSpec {
        let ac = ndefRecord(
            RecordSpec(tnf: 0x01, type: Array("ac".utf8), id: nil, payload: hex("01013001046d646f63")),
            messageBegin: true,
            messageEnd: true
        )
        return RecordSpec(
            tnf: 0x01,
            type: Array("Hs".utf8),
            id: nil,
            payload: [0x15] + ac,
            forceNormal: forceNormal
        )
    }

    static func bluetoothCarrierRecord(
        roleValue: UInt8?,
        uuids: [UUID],
        rawPayload: [UInt8]? = nil,
        forceNormal: Bool = false
    ) -> RecordSpec {
        RecordSpec(
            tnf: 0x02,
            type: Array("application/vnd.bluetooth.le.oob".utf8),
            id: [0x30],
            payload: rawPayload ?? bluetoothOOB(roleValue: roleValue, uuids: uuids),
            forceNormal: forceNormal
        )
    }

    static func deviceEngagementRecord(_ bytes: [UInt8], forceNormal: Bool = false) -> RecordSpec {
        RecordSpec(
            tnf: 0x04,
            type: Array("iso.org:18013:deviceengagement".utf8),
            id: Array("mdoc".utf8),
            payload: bytes,
            forceNormal: forceNormal
        )
    }

    static func bluetoothOOB(roleValue: UInt8?, uuids: [UUID]) -> [UInt8] {
        var result: [UInt8] = []
        if let roleValue {
            result += ad(adLERole, [roleValue])
        }
        if !uuids.isEmpty {
            result += ad(adCompleteUUIDs, uuids.flatMap(littleEndianUUIDBytes))
        }
        return result
    }

    static func ad(_ type: UInt8, _ data: [UInt8]) -> [UInt8] {
        [UInt8(data.count + 1), type] + data
    }

    static func ndefMessage(
        _ records: [RecordSpec],
        messageEnd: Bool = true,
        repeatedMessageBegin: Bool = false
    ) -> [UInt8] {
        records.enumerated().flatMap { index, record in
            ndefRecord(
                record,
                messageBegin: index == 0 || (repeatedMessageBegin && index == 1),
                messageEnd: messageEnd && index == records.count - 1
            )
        }
    }

    static func ndefRecord(
        _ record: RecordSpec,
        messageBegin: Bool,
        messageEnd: Bool
    ) -> [UInt8] {
        let short = !record.forceNormal && record.payload.count < 256
        var header = record.tnf
        if messageBegin { header |= 0x80 }
        if messageEnd { header |= 0x40 }
        if short { header |= 0x10 }
        if record.id != nil { header |= 0x08 }
        var result = [header, UInt8(record.type.count)]
        if short {
            result.append(UInt8(record.payload.count))
        } else {
            result.append(contentsOf: [
                UInt8((record.payload.count >> 24) & 0xFF),
                UInt8((record.payload.count >> 16) & 0xFF),
                UInt8((record.payload.count >> 8) & 0xFF),
                UInt8(record.payload.count & 0xFF),
            ])
        }
        if let id = record.id {
            result.append(UInt8(id.count))
        }
        result += record.type
        if let id = record.id { result += id }
        return result + record.payload
    }

    /// Independent canonical test encoder for `[bstr(select), null]`.
    static func nfcHandover(_ select: [UInt8]) -> [UInt8] {
        let prefix: [UInt8]
        switch select.count {
        case 0..<24:
            prefix = [0x40 | UInt8(select.count)]
        case 24...0xFF:
            prefix = [0x58, UInt8(select.count)]
        case 0x100...0xFFFF:
            prefix = [0x59, UInt8(select.count >> 8), UInt8(select.count & 0xFF)]
        default:
            prefix = [
                0x5A, UInt8(select.count >> 24), UInt8((select.count >> 16) & 0xFF),
                UInt8((select.count >> 8) & 0xFF), UInt8(select.count & 0xFF),
            ]
        }
        return [0x82] + prefix + select + [0xF6]
    }

    static func engagement(peripheral: Bool = true, central: Bool = true) -> [UInt8] {
        var options = [cborUInt(0) + cborBool(peripheral), cborUInt(1) + cborBool(central)]
        if peripheral {
            options.append(cborUInt(10) + cborBytes(uuidBytes(peripheralUUID)))
        }
        if central {
            options.append(cborUInt(11) + cborBytes(uuidBytes(centralUUID)))
        }
        let bleOptions = cborMap(options)
        let method = cborArray([cborUInt(2), cborUInt(1), bleOptions])
        return cborMap([
            cborUInt(0) + cborText("1.0"),
            cborUInt(1) + cborArray([
                cborUInt(1),
                cborTag24(cborBytes(hex(officialD33COSEKey))),
            ]),
            cborUInt(2) + cborArray([method]),
        ])
    }

    static func uuidBytes(_ uuid: UUID) -> [UInt8] {
        let value = uuid.uuid
        return [
            value.0, value.1, value.2, value.3, value.4, value.5, value.6, value.7,
            value.8, value.9, value.10, value.11, value.12, value.13, value.14, value.15,
        ]
    }

    static func littleEndianUUIDBytes(_ uuid: UUID) -> [UInt8] {
        Array(uuidBytes(uuid).reversed())
    }

    static func cborMap(_ entries: [[UInt8]]) -> [UInt8] {
        cborHeader(major: 5, argument: entries.count) + entries.flatMap { $0 }
    }

    static func cborArray(_ items: [[UInt8]]) -> [UInt8] {
        cborHeader(major: 4, argument: items.count) + items.flatMap { $0 }
    }

    static func cborText(_ value: String) -> [UInt8] {
        let encoded = Array(value.utf8)
        return cborHeader(major: 3, argument: encoded.count) + encoded
    }

    static func cborBytes(_ value: [UInt8]) -> [UInt8] {
        cborHeader(major: 2, argument: value.count) + value
    }

    static func cborUInt(_ value: Int) -> [UInt8] {
        cborHeader(major: value >= 0 ? 0 : 1, argument: value >= 0 ? value : -1 - value)
    }

    static func cborBool(_ value: Bool) -> [UInt8] {
        [value ? 0xF5 : 0xF4]
    }

    static func cborTag24(_ value: [UInt8]) -> [UInt8] {
        [0xD8, 0x18] + value
    }

    static func cborHeader(major: UInt8, argument: Int) -> [UInt8] {
        precondition(argument >= 0)
        let initial = major << 5
        switch argument {
        case 0..<24:
            return [initial | UInt8(argument)]
        case 24...0xFF:
            return [initial | 24, UInt8(argument)]
        default:
            return [initial | 25, UInt8(argument >> 8), UInt8(argument & 0xFF)]
        }
    }

    static func hex(_ value: String) -> [UInt8] {
        let digits = value.filter { !$0.isWhitespace }
        precondition(digits.count % 2 == 0)
        return stride(from: 0, to: digits.count, by: 2).map { offset in
            let start = digits.index(digits.startIndex, offsetBy: offset)
            let end = digits.index(start, offsetBy: 2)
            return UInt8(digits[start..<end], radix: 16)!
        }
    }
}

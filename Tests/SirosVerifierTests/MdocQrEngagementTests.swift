// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosVerifier

final class MdocQrEngagementTests: XCTestCase {
    // P-256 generator point, two fixed BLE UUIDs, and deliberately
    // non-canonical top-level map order (2, 0, 1).
    private let goldenHex = """
        a30281830201a400f501f50a5000112233445566778899aabbccddeeff0b50ffeeddccbbaa998877665544332211000063312e30018201d818584ba4010220012158206b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2962258204fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
        """
    private let goldenURI = "mdoc:owKBgwIBpAD1AfUKUAARIjNEVWZ3iJmqu8zd7v8LUP_u3cy7qpmId2ZVRDMiEQAAYzEuMAGCAdgYWEukAQIgASFYIGsX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWIlggT-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"

    func testGoldenParsesAndPreservesEveryTranscriptByte() throws {
        let original = hex(goldenHex)
        let engagement = try MdocQrEngagement.parse(goldenURI)

        XCTAssertEqual(engagement.deviceEngagementBytes, original)
        XCTAssertEqual(engagement.eDeviceKeyBytes, validEDeviceKey)
        XCTAssertEqual(engagement.qrHandover, [0xF6])
        XCTAssertEqual(engagement.handover, [0xF6])
        XCTAssertEqual(engagement.ble, engagement.bleRetrievalMetadata)
        XCTAssertEqual(engagement.ble?.supportsPeripheralServerMode, true)
        XCTAssertEqual(engagement.ble?.supportsCentralClientMode, true)
        XCTAssertEqual(
            engagement.peripheralServerModeUuid?.uuidString,
            "00112233-4455-6677-8899-AABBCCDDEEFF"
        )
        XCTAssertEqual(
            engagement.centralClientModeUuid?.uuidString,
            "FFEEDDCC-BBAA-9988-7766-554433221100"
        )
        XCTAssertEqual(try MdocQrEngagement(mdocURI: goldenURI), engagement)
        XCTAssertEqual(try MdocQrEngagement.parse(mdocUri: goldenURI), engagement)
    }

    func testAbsentRetrievalMethodsProducesNoBLEMetadata() throws {
        let bytes = makeEngagement(includeBLE: false)
        let engagement = try MdocQrEngagement.parse(uri(bytes))

        XCTAssertEqual(engagement.deviceEngagementBytes, bytes)
        XCTAssertNil(engagement.ble)
        XCTAssertNil(engagement.peripheralServerModeUuid)
        XCTAssertNil(engagement.centralClientModeUuid)
    }

    func testNonPreferredTagAndLengthWidthsAreNotReencoded() throws {
        // Valid but non-preferred encodings: tag 24 in 64 bits and a 16-bit
        // byte-string length. A decoder/re-encoder would destroy both spans.
        let exactKey = [0xDB, 0, 0, 0, 0, 0, 0, 0, 0x18, 0x59, 0, UInt8(validCOSEKey.count)] + validCOSEKey
        let security = [0x82, 0x01] + exactKey
        let bytes = makeEngagement(security: security, includeBLE: false)

        let engagement = try MdocQrEngagement.parse(uri(bytes))

        XCTAssertEqual(engagement.eDeviceKeyBytes, exactKey)
        XCTAssertEqual(engagement.deviceEngagementBytes, bytes)
    }

    func testRejectsNonCanonicalOrInvalidBase64URL() {
        let invalid = [
            "",
            "MDOC:Zg",
            "mdoc",
            "mdoc:",
            "mdoc:A",
            "mdoc:Zg==",
            "mdoc:Z+g",
            "mdoc:Z/g",
            "mdoc:Zg\n",
            "mdoc:Zg%3D",
            "mdoc:Zh", // Same decoded byte as Zg, but nonzero unused bits.
        ]
        for candidate in invalid {
            XCTAssertThrowsError(try MdocQrEngagement.parse(candidate), "accepted \(candidate)") { error in
                guard case MdocQrEngagementError.invalidURI = error else {
                    return XCTFail("unexpected error for \(candidate): \(error)")
                }
            }
        }
    }

    func testRejectsDecodedPayloadAbove16384BytesBeforeCBORDecoding() {
        let candidate = uri([UInt8](repeating: 0, count: MdocQrEngagement.maximumDecodedSize + 1))
        XCTAssertThrowsError(try MdocQrEngagement.parse(candidate)) { error in
            XCTAssertEqual(error as? MdocQrEngagementError, .payloadTooLarge)
        }
    }

    func testRejectsTrailingTruncatedDuplicateAndUnsupportedTopLevelShapes() {
        let duplicateVersion = cborMap([
            defaultVersionEntry,
            [0x18, 0x00] + Array(defaultVersionEntry.dropFirst()),
            securityEntry,
        ])
        let unknownKey = cborMap([defaultVersionEntry, securityEntry, [0x03, 0xF6]])
        let missingSecurity = cborMap([defaultVersionEntry])
        let wrongVersion = makeEngagement(version: "1.1")
        let taggedRoot = [0xD8, 0x18] + cborByteString(validEngagement)
        let indefiniteRoot: [UInt8] = [0xBF, 0x00, 0x63] + Array("1.0".utf8) + [0xFF]
        let impossibleLength: [UInt8] = [0x5B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        let invalid = [
            validEngagement + [0x00],
            Array(validEngagement.dropLast()),
            duplicateVersion,
            unknownKey,
            missingSecurity,
            wrongVersion,
            taggedRoot,
            indefiniteRoot,
            impossibleLength,
        ]

        assertAllRejected(invalid)
    }

    func testRejectsInvalidSecurityAndCOSEKeyShapes() {
        let wrongSuite = makeEngagement(security: [0x82, 0x02] + validEDeviceKey, includeBLE: false)
        let shortSecurity = makeEngagement(security: [0x81, 0x01], includeBLE: false)
        let untaggedKey = makeEngagement(security: [0x82, 0x01] + cborByteString(validCOSEKey), includeBLE: false)
        let wrongTag = makeEngagement(security: [0x82, 0x01, 0xD7] + cborByteString(validCOSEKey), includeBLE: false)
        let innerTrailing = makeEngagement(coseKey: validCOSEKey + [0x00], includeBLE: false)
        let duplicateKty = makeEngagement(coseKey: cborMap(coseEntries + [[0x01, 0x02]]), includeBLE: false)
        let extraCOSEEntry = makeEngagement(coseKey: cborMap(coseEntries + [[0x02, 0xF6]]), includeBLE: false)
        let wrongKty = makeEngagement(coseKey: makeCOSEKey(kty: 1), includeBLE: false)
        let wrongCurve = makeEngagement(coseKey: makeCOSEKey(curve: 2), includeBLE: false)
        let shortX = makeEngagement(coseKey: makeCOSEKey(x: Array(p256X.dropLast())), includeBLE: false)
        let offCurve = makeEngagement(
            coseKey: makeCOSEKey(x: [UInt8](repeating: 0, count: 32), y: [UInt8](repeating: 0, count: 32)),
            includeBLE: false
        )

        assertAllRejected([
            wrongSuite, shortSecurity, untaggedKey, wrongTag, innerTrailing,
            duplicateKty, extraCOSEEntry, wrongKty, wrongCurve, shortX, offCurve,
        ])
    }

    func testRejectsUnsupportedRetrievalMethodShapes() {
        let empty = makeEngagement(methods: [0x80])
        let twoMethods = makeEngagement(methods: [0x82] + validBLEMethod + validBLEMethod)
        let wrongType = makeEngagement(methods: cborArray([makeBLEMethod(type: 1)]))
        let wrongVersion = makeEngagement(methods: cborArray([makeBLEMethod(version: 2)]))
        let shortMethod = makeEngagement(methods: [0x81, 0x82, 0x02, 0x01])
        let nonMapOptions = makeEngagement(methods: cborArray([[0x83, 0x02, 0x01, 0xF6]]))
        let emptyOptions = makeEngagement(methods: cborArray([makeBLEMethod(options: [])]))
        assertAllRejected([empty, twoMethods, wrongType, wrongVersion, shortMethod, nonMapOptions, emptyOptions])
    }

    func testRejectsInconsistentBLEFlagsAndUUIDs() {
        let falseWithUUID = makeBLEOptions(peripheral: false, central: true, includePeripheralUUID: true)
        let trueWithoutUUID = makeBLEOptions(peripheral: true, central: true, includeCentralUUID: false)
        let shortUUID = cborMap([
            bleFlag(0, true), bleFlag(1, true),
            bleUUID(10, Array(peripheralUUID.dropLast())), bleUUID(11, centralUUID),
        ])
        let bothFalse = makeBLEOptions(
            peripheral: false,
            central: false,
            includePeripheralUUID: false,
            includeCentralUUID: false
        )
        let unknownOption = cborMap([bleFlag(0, true), bleFlag(1, false), bleUUID(10, peripheralUUID), [0x02, 0xF6]])
        let duplicateFlag = cborMap([
            bleFlag(0, true), bleFlag(0, true), bleFlag(1, false), bleUUID(10, peripheralUUID),
        ])
        let nonBytesUUID = cborMap([bleFlag(0, true), bleFlag(1, false), [0x0A, 0xF6]])
        let nonBooleanFlag = cborMap([[0x00, 0x01], bleFlag(1, false)])
        let options = [
            falseWithUUID, trueWithoutUUID, shortUUID, bothFalse,
            unknownOption, duplicateFlag, nonBytesUUID, nonBooleanFlag,
        ]
        assertAllRejected(options.map { makeEngagement(methods: cborArray([makeBLEMethod(options: $0)])) })
    }

    func testSingleModeEngagementsExposeOnlyTheirOwnUUID() throws {
        let peripheralOnly = makeBLEOptions(peripheral: true, central: false, includeCentralUUID: false)
        let centralOnly = makeBLEOptions(peripheral: false, central: true, includePeripheralUUID: false)

        let first = try MdocQrEngagement.parse(uri(makeEngagement(
            methods: cborArray([makeBLEMethod(options: peripheralOnly)])
        )))
        let second = try MdocQrEngagement.parse(uri(makeEngagement(
            methods: cborArray([makeBLEMethod(options: centralOnly)])
        )))

        XCTAssertEqual(first.ble?.peripheralServerModeUuid?.uuidString, "00112233-4455-6677-8899-AABBCCDDEEFF")
        XCTAssertNil(first.ble?.centralClientModeUuid)
        XCTAssertNil(second.ble?.peripheralServerModeUuid)
        XCTAssertEqual(second.ble?.centralClientModeUuid?.uuidString, "FFEEDDCC-BBAA-9988-7766-554433221100")
    }

    private func assertAllRejected(_ candidates: [[UInt8]], file: StaticString = #filePath, line: UInt = #line) {
        for bytes in candidates {
            XCTAssertThrowsError(try MdocQrEngagement.parse(uri(bytes)), file: file, line: line)
        }
    }
}

// MARK: - Independent fixture encoder (test code only)

private var p256X: [UInt8] {
    hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
}

private var p256Y: [UInt8] {
    hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
}

private var peripheralUUID: [UInt8] { hex("00112233445566778899aabbccddeeff") }
private var centralUUID: [UInt8] { hex("ffeeddccbbaa99887766554433221100") }
private var validCOSEKey: [UInt8] { makeCOSEKey() }
private var validEDeviceKey: [UInt8] { [0xD8, 0x18] + cborByteString(validCOSEKey) }
private var validSecurity: [UInt8] { [0x82, 0x01] + validEDeviceKey }
private var defaultVersionEntry: [UInt8] { versionEntry() }
private var securityEntry: [UInt8] { [0x01] + validSecurity }
private var validBLEOptions: [UInt8] { makeBLEOptions() }
private var validBLEMethod: [UInt8] { makeBLEMethod() }
private var validMethods: [UInt8] { cborArray([validBLEMethod]) }
private var validEngagement: [UInt8] { makeEngagement() }

private var coseEntries: [[UInt8]] {
    [
        [0x01, 0x02],
        [0x20, 0x01],
        [0x21] + cborByteString(p256X),
        [0x22] + cborByteString(p256Y),
    ]
}

private func makeCOSEKey(
    kty: UInt8 = 2,
    curve: UInt8 = 1,
    x: [UInt8]? = nil,
    y: [UInt8]? = nil
) -> [UInt8] {
    cborMap([
        [0x01, kty],
        [0x20, curve],
        [0x21] + cborByteString(x ?? p256X),
        [0x22] + cborByteString(y ?? p256Y),
    ])
}

private func makeEngagement(
    version: String = "1.0",
    security: [UInt8]? = nil,
    coseKey: [UInt8]? = nil,
    methods: [UInt8]? = nil,
    includeBLE: Bool = true
) -> [UInt8] {
    let actualSecurity = security ?? ([0x82, 0x01] + [0xD8, 0x18] + cborByteString(coseKey ?? validCOSEKey))
    var entries = [versionEntry(version), [0x01] + actualSecurity]
    if includeBLE { entries.append([0x02] + (methods ?? validMethods)) }
    return cborMap(entries)
}

private func versionEntry(_ version: String = "1.0") -> [UInt8] {
    let utf8 = Array(version.utf8)
    return [0x00, 0x60 + UInt8(utf8.count)] + utf8
}

private func makeBLEMethod(type: UInt8 = 2, version: UInt8 = 1, options: [UInt8]? = nil) -> [UInt8] {
    [0x83, type, version] + (options ?? validBLEOptions)
}

private func makeBLEOptions(
    peripheral: Bool = true,
    central: Bool = true,
    includePeripheralUUID: Bool = true,
    includeCentralUUID: Bool = true
) -> [UInt8] {
    var entries = [bleFlag(0, peripheral), bleFlag(1, central)]
    if includePeripheralUUID { entries.append(bleUUID(10, peripheralUUID)) }
    if includeCentralUUID { entries.append(bleUUID(11, centralUUID)) }
    return cborMap(entries)
}

private func bleFlag(_ key: UInt8, _ value: Bool) -> [UInt8] {
    [key, value ? 0xF5 : 0xF4]
}

private func bleUUID(_ key: UInt8, _ bytes: [UInt8]) -> [UInt8] {
    [key] + cborByteString(bytes)
}

private func cborArray(_ items: [[UInt8]]) -> [UInt8] {
    precondition(items.count < 24)
    return [0x80 + UInt8(items.count)] + items.flatMap { $0 }
}

private func cborMap(_ entries: [[UInt8]]) -> [UInt8] {
    precondition(entries.count < 24)
    return [0xA0 + UInt8(entries.count)] + entries.flatMap { $0 }
}

private func cborByteString(_ bytes: [UInt8]) -> [UInt8] {
    if bytes.count < 24 { return [0x40 + UInt8(bytes.count)] + bytes }
    if bytes.count <= 255 { return [0x58, UInt8(bytes.count)] + bytes }
    preconditionFailure("fixture byte string too large")
}

private func uri(_ bytes: [UInt8]) -> String {
    let encoded = Data(bytes).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
    return "mdoc:" + encoded
}

private func hex(_ string: String) -> [UInt8] {
    let digits = string.filter { !$0.isWhitespace }
    precondition(digits.count % 2 == 0)
    return stride(from: 0, to: digits.count, by: 2).map { offset in
        let start = digits.index(digits.startIndex, offsetBy: offset)
        let end = digits.index(start, offsetBy: 2)
        return UInt8(digits[start..<end], radix: 16)!
    }
}

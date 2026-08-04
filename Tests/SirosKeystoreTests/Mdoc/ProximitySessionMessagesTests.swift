// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@preconcurrency import SwiftCBOR
@testable import SirosKeystore

/// Ported from `org.siros.sdk.keystore.mdoc.ProximitySessionMessagesTest`
/// (Kotlin). Pure CBOR framing logic - no platform-crypto dependency, runs
/// on every platform.
final class ProximitySessionMessagesTests: XCTestCase {

    func testBuildAndParseSessionData_roundTripsWithDataOnly() throws {
        let data: [UInt8] = [1, 2, 3, 4]
        let bytes = ProximitySessionMessages.buildSessionData(encryptedData: data)

        let decoded = try CBOR.decode(bytes)
        guard case .byteString(let decodedData)? = decoded?["data"] else {
            return XCTFail("missing data")
        }
        XCTAssertEqual(decodedData, data)
        XCTAssertNil(decoded?["status"])
    }

    func testBuildSessionData_statusOnly_omitsData() throws {
        let bytes = ProximitySessionMessages.buildSessionData(
            encryptedData: nil,
            status: ProximitySessionMessages.StatusCode.sessionTermination
        )

        let decoded = try CBOR.decode(bytes)
        XCTAssertNil(decoded?["data"])
        guard case .unsignedInt(let status)? = decoded?["status"] else {
            return XCTFail("missing status")
        }
        XCTAssertEqual(status, 20)
    }

    func testParseSessionEstablishment_extractsEReaderKeyAndData() throws {
        let eReaderKey: CBOR = .tagged(.encodedCBORDataItem, .byteString(CBOR.map([.unsignedInt(1): .unsignedInt(2)]).encode()))
        let map: CBOR = .map([
            .utf8String("eReaderKey"): eReaderKey,
            .utf8String("data"): .byteString([9, 8, 7]),
        ])

        let parsed = try ProximitySessionMessages.parseSessionEstablishment(map.encode())

        XCTAssertEqual(parsed.eReaderKeyBytes, eReaderKey.encode())
        XCTAssertEqual(parsed.encryptedData, [9, 8, 7])
    }

    func testParseSessionEstablishment_missingEReaderKey_throws() {
        let map: CBOR = .map([.utf8String("data"): .byteString([1])])
        XCTAssertThrowsError(try ProximitySessionMessages.parseSessionEstablishment(map.encode()))
    }

    /// §9.1.1: eReaderKey must be a #6.24-tagged COSE_Key - an untagged value
    /// should fail here with a clear message, not deep inside key parsing.
    /// Mirrors the Kotlin SDK's equivalent validation
    /// (`ProximitySessionMessages.parseSessionEstablishment`).
    func testParseSessionEstablishment_untaggedEReaderKey_throws() {
        let map: CBOR = .map([
            .utf8String("eReaderKey"): .map([.unsignedInt(1): .unsignedInt(2)]),
            .utf8String("data"): .byteString([1]),
        ])
        XCTAssertThrowsError(try ProximitySessionMessages.parseSessionEstablishment(map.encode()))
    }
}

final class BleMessageChunkerTests: XCTestCase {

    func testChunk_messageSmallerThanMaxSize_singleLastChunk() {
        let message: [UInt8] = [1, 2, 3]
        let chunks = BleMessageChunker.chunk(message, maxChunkSize: 10)

        XCTAssertEqual(chunks.count, 1)
        XCTAssertEqual(chunks[0][0], 0x00)
        XCTAssertEqual(Array(chunks[0].dropFirst()), message)
    }

    func testChunk_emptyMessage_singleEmptyLastChunk() {
        let chunks = BleMessageChunker.chunk([], maxChunkSize: 10)

        XCTAssertEqual(chunks.count, 1)
        XCTAssertEqual(chunks[0], [0x00])
    }

    func testChunk_messageLargerThanMaxSize_splitsWithCorrectPrefixes() {
        let message: [UInt8] = (0..<25).map { UInt8($0) }
        let chunks = BleMessageChunker.chunk(message, maxChunkSize: 10)

        XCTAssertEqual(chunks.count, 3)
        XCTAssertEqual(chunks[0][0], 0x01)
        XCTAssertEqual(chunks[1][0], 0x01)
        XCTAssertEqual(chunks[2][0], 0x00)
        // Total wire size (prefix + payload) must never exceed maxChunkSize -
        // NOT prefix + maxChunkSize, which real BLE hardware rejects.
        XCTAssertEqual(chunks[0].count, 10)
        XCTAssertEqual(chunks[1].count, 10)
        XCTAssertEqual(chunks[2].count, 8) // prefix + 7 remaining
    }

    /// Regression test for the off-by-one bug found and fixed in the Kotlin
    /// SDK first (see `BleMessageChunker.chunk`'s doc comment): an earlier
    /// version took `maxChunkSize` payload bytes and added the prefix on
    /// top, producing chunks one byte over the caller's limit - which broke
    /// real BLE notifications once the negotiated MTU exceeded 515, hitting
    /// Android's hard 512-byte attribute-value cap. Ported verbatim from
    /// `chunk_neverProducesAWireSizeLargerThanMaxChunkSize` (Kotlin).
    func testChunk_neverProducesAWireSizeLargerThanMaxChunkSize() {
        for maxChunkSize in [2, 3, 10, 20, 512] {
            for messageSize in [0, 1, maxChunkSize - 1, maxChunkSize, maxChunkSize + 1, maxChunkSize * 3 + 1] {
                if messageSize < 0 { continue }
                let message: [UInt8] = (0..<messageSize).map { UInt8($0 & 0xFF) }
                let chunks = BleMessageChunker.chunk(message, maxChunkSize: maxChunkSize)
                for c in chunks {
                    XCTAssertLessThanOrEqual(
                        c.count, maxChunkSize,
                        "chunk of size \(c.count) exceeds maxChunkSize \(maxChunkSize) (message=\(messageSize))"
                    )
                }
            }
        }
    }

    func testReassembler_reconstructsOriginalMessage() {
        let message: [UInt8] = (0..<517).map { UInt8($0 % 251) }
        let chunks = BleMessageChunker.chunk(message, maxChunkSize: 100)
        let reassembler = BleMessageChunker.Reassembler()

        var result: [UInt8]?
        for (index, chunk) in chunks.enumerated() {
            if let r = reassembler.feed(chunk) {
                XCTAssertEqual(index, chunks.count - 1, "only the last chunk should yield a result")
                result = r
            }
        }

        XCTAssertEqual(result, message)
    }

    func testReassembler_resetsAfterCompleteMessage_forNextMessage() {
        let reassembler = BleMessageChunker.Reassembler()
        let first: [UInt8] = Array("first".utf8)
        let second: [UInt8] = Array("second".utf8)

        for chunk in BleMessageChunker.chunk(first, maxChunkSize: 3) {
            _ = reassembler.feed(chunk)
        }
        var secondResult: [UInt8]?
        for chunk in BleMessageChunker.chunk(second, maxChunkSize: 3) {
            secondResult = reassembler.feed(chunk) ?? secondResult
        }

        XCTAssertEqual(secondResult, second)
    }

    /// Regression coverage for the Copilot-review fix ported from the
    /// Kotlin SDK (`BleMessageChunker.Reassembler`, commit `e7d8872`):
    /// `feed` must accept exactly the two valid prefix bytes, 0x00 (last)
    /// and 0x01 (more coming). The invalid-prefix case (anything else)
    /// traps via `precondition` rather than throwing - this repo's test
    /// suite has no existing convention for asserting on a precondition
    /// trap (no crash-testing harness elsewhere in `Tests/`), so that half
    /// of the fix is verified by code-review parity with Kotlin's
    /// `require(chunk[0] == 0x00 || chunk[0] == 0x01) { ... }` rather than
    /// by an executable test here; this test instead locks down the valid
    /// boundary so a future change can't narrow it by accident.
    func testReassembler_acceptsBothValidPrefixBytes() {
        let reassembler = BleMessageChunker.Reassembler()

        XCTAssertNil(reassembler.feed([0x01, 1, 2, 3]))
        XCTAssertEqual(reassembler.feed([0x00, 4, 5]), [1, 2, 3, 4, 5])
    }
}

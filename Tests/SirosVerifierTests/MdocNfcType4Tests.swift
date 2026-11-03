// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosVerifier

final class MdocNfcType4Tests: XCTestCase {
    func testSelectCommandsUseNDEFApplicationAndE104File() {
        let application = MdocNfcType4.selectNDEFTagApplication
        XCTAssertEqual(application.instructionClass, 0x00)
        XCTAssertEqual(application.instructionCode, 0xA4)
        XCTAssertEqual(application.p1Parameter, 0x04)
        XCTAssertEqual(application.p2Parameter, 0x00)
        XCTAssertEqual(application.data, [0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01])
        XCTAssertEqual(application.expectedResponseLength, -1)

        let file = MdocNfcType4.selectNDEFDataFile
        XCTAssertEqual(file.instructionClass, 0x00)
        XCTAssertEqual(file.instructionCode, 0xA4)
        XCTAssertEqual(file.p1Parameter, 0x00)
        XCTAssertEqual(file.p2Parameter, 0x0C)
        XCTAssertEqual(file.data, [0xE1, 0x04])
        XCTAssertEqual(file.expectedResponseLength, -1)
    }

    func testReadNLENIsReadBinaryOffsetZeroLengthTwo() {
        XCTAssertEqual(MdocNfcType4.readNLEN, MdocNfcType4.Command(
            instructionClass: 0x00,
            instructionCode: 0xB0,
            p1Parameter: 0x00,
            p2Parameter: 0x00,
            data: [],
            expectedResponseLength: 2
        ))
    }

    func testReadBinaryUsesBigEndianOffsetAndSupports256ByteLe() throws {
        let command = try MdocNfcType4.readBinary(offset: 0x1234, length: 256)
        XCTAssertEqual(command.instructionClass, 0x00)
        XCTAssertEqual(command.instructionCode, 0xB0)
        XCTAssertEqual(command.p1Parameter, 0x12)
        XCTAssertEqual(command.p2Parameter, 0x34)
        XCTAssertTrue(command.data.isEmpty)
        XCTAssertEqual(command.expectedResponseLength, 256)

        let boundary = try MdocNfcType4.readBinary(offset: Int(UInt16.max), length: 1)
        XCTAssertEqual(boundary.p1Parameter, 0xFF)
        XCTAssertEqual(boundary.p2Parameter, 0xFF)
    }

    func testReadBinaryRejectsOutOfRangeOffsetAndLength() {
        for offset in [-1, Int(UInt16.max) + 1] {
            XCTAssertThrowsError(try MdocNfcType4.readBinary(offset: offset, length: 1))
        }
        for length in [-1, 0, 257] {
            XCTAssertThrowsError(try MdocNfcType4.readBinary(offset: 0, length: length))
        }
    }

    func testOnlyStatus9000IsAccepted() throws {
        try MdocNfcType4.requireSuccess(sw1: 0x90, sw2: 0x00)
        XCTAssertThrowsError(try MdocNfcType4.requireSuccess(sw1: 0x6A, sw2: 0x82)) { error in
            XCTAssertEqual(
                error as? MdocNfcEngagementError,
                .apduStatus(sw1: 0x6A, sw2: 0x82)
            )
        }
        XCTAssertThrowsError(try MdocNfcType4.requireSuccess(sw1: 0x90, sw2: 0x01))
    }

    func testNLENIsExactlyTwoByteBigEndianAndBounded() throws {
        XCTAssertEqual(try MdocNfcType4.parseNLEN([0x00, 0x00]), 0)
        XCTAssertEqual(try MdocNfcType4.parseNLEN([0x01, 0x00]), 256)
        XCTAssertEqual(try MdocNfcType4.parseNLEN([0x12, 0x34]), 0x1234)
        XCTAssertEqual(try MdocNfcType4.parseNLEN([0xFF, 0xFF]), 65_535)

        let malformedResponses: [[UInt8]] = [[], [0x00], [0x00, 0x00, 0x00]]
        for response in malformedResponses {
            XCTAssertThrowsError(try MdocNfcType4.parseNLEN(response)) { error in
                XCTAssertTrue(error is MdocNfcEngagementError)
            }
        }
        XCTAssertThrowsError(try MdocNfcType4.validateNDEFLength(
            MdocNfcHandoverParser.maximumHandoverSelectSize + 1
        )) { error in
            guard case .malformed = error as? MdocNfcEngagementError else {
                return XCTFail("unexpected error: \(error)")
            }
        }
    }

    func testChunkPlanStartsAfterNLENAndCoversPayloadExactlyOnce() throws {
        let chunks = try MdocNfcType4.chunkPlan(ndefLength: 12, maximumChunkSize: 5)
        XCTAssertEqual(chunks, [
            MdocNfcType4.ReadChunk(offset: 2, length: 5),
            MdocNfcType4.ReadChunk(offset: 7, length: 5),
            MdocNfcType4.ReadChunk(offset: 12, length: 2),
        ])
        XCTAssertEqual(chunks.reduce(0) { $0 + $1.length }, 12)
        XCTAssertTrue(try MdocNfcType4.chunkPlan(ndefLength: 0).isEmpty)
    }

    func testDefaultChunkPlanIsBoundedThroughMaximumHandoverSize() throws {
        for length in [1, 255, 256, 257, 65_535, 65_536] {
            let chunks = try MdocNfcType4.chunkPlan(ndefLength: length)
            XCTAssertEqual(chunks.reduce(0) { $0 + $1.length }, length)
            XCTAssertEqual(chunks.first?.offset, 2)
            XCTAssertTrue(chunks.allSatisfy { (1...256).contains($0.length) })
            for (previous, next) in zip(chunks, chunks.dropFirst()) {
                XCTAssertEqual(next.offset, previous.offset + previous.length)
            }
            for chunk in chunks {
                let command = try MdocNfcType4.readBinary(offset: chunk.offset, length: chunk.length)
                XCTAssertEqual(command.expectedResponseLength, chunk.length)
            }
        }
    }

    func testChunkPlanRejectsOversizeAndInvalidChunkSizes() {
        XCTAssertThrowsError(try MdocNfcType4.chunkPlan(
            ndefLength: MdocNfcHandoverParser.maximumHandoverSelectSize + 1
        ))
        for size in [-1, 0, 257] {
            XCTAssertThrowsError(try MdocNfcType4.chunkPlan(ndefLength: 1, maximumChunkSize: size))
        }
    }

    func testTruncatedAndOverlongResponsesAreRejected() throws {
        try MdocNfcType4.requireResponseLength([0x01, 0x02], expectedLength: 2)
        let wrongLengthResponses: [[UInt8]] = [[0x01], [0x01, 0x02, 0x03]]
        for response in wrongLengthResponses {
            XCTAssertThrowsError(try MdocNfcType4.requireResponseLength(
                response,
                expectedLength: 2
            )) { error in
                guard case .malformed = error as? MdocNfcEngagementError else {
                    return XCTFail("unexpected error: \(error)")
                }
            }
        }
    }
}

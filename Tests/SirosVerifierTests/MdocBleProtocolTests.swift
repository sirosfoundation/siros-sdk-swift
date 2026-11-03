// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosVerifier

/// Pure framing/state tests. Real radio interoperability requires device testing.
final class MdocBleProtocolTests: XCTestCase {
    func testChunkingHonoursWireLimitAndReassemblyReturnsOnlyWholeMessages() throws {
        let first = (0..<517).map { UInt8($0 % 251) }
        let second: [UInt8] = [9, 8, 7]
        let reassembler = MdocBleReassembler()

        let chunks = MdocBleProtocol.chunk(first, maxChunkSize: 20)
        XCTAssertTrue(chunks.allSatisfy { $0.count <= 20 })
        XCTAssertEqual(chunks.first?.first, 0x01)
        XCTAssertEqual(chunks.last?.first, 0x00)
        var actual: [UInt8]?
        for (index, chunk) in chunks.enumerated() {
            let complete = try reassembler.feed(chunk)
            if index < chunks.count - 1 { XCTAssertNil(complete) }
            actual = complete ?? actual
        }
        XCTAssertEqual(actual, first)

        var secondActual: [UInt8]?
        for chunk in MdocBleProtocol.chunk(second, maxChunkSize: 2) {
            secondActual = try reassembler.feed(chunk) ?? secondActual
        }
        XCTAssertEqual(secondActual, second)
        XCTAssertEqual(MdocBleProtocol.chunk([], maxChunkSize: 20), [[0x00]])
    }

    func testReassemblerAcceptsExactlyTwoMiB() throws {
        let message = (0..<MdocBleProtocol.maximumMessageSize).map { UInt8($0 % 31) }
        let reassembler = MdocBleReassembler()
        var actual: [UInt8]?

        for chunk in MdocBleProtocol.chunk(message, maxChunkSize: 512) {
            actual = try reassembler.feed(chunk) ?? actual
        }

        XCTAssertEqual(actual, message)
    }

    func testOversizedChunkAbortsAndResetsReassembly() throws {
        let reassembler = MdocBleReassembler()
        let oversized = [UInt8(0x01)] + [UInt8](
            repeating: 0,
            count: MdocBleProtocol.maximumMessageSize + 1
        )

        XCTAssertThrowsError(try reassembler.feed(oversized)) { error in
            XCTAssertEqual(error as? MdocBleTransportError, .messageTooLarge)
        }
        XCTAssertEqual(try reassembler.feed([0x00, 4, 5]), [4, 5])
    }

    func testMalformedChunkAbortsPartialMessageAndResetsReassembly() throws {
        let reassembler = MdocBleReassembler()
        XCTAssertNil(try reassembler.feed([0x01, 9]))

        XCTAssertThrowsError(try reassembler.feed([]))
        XCTAssertEqual(try reassembler.feed([0x00, 4]), [4])
        XCTAssertThrowsError(try reassembler.feed([0x02, 1]))
        XCTAssertEqual(try reassembler.feed([0x00, 7]), [7])
    }

    func testClientWaitsForNotificationsAndStateStartWrite() {
        let handshake = MdocBleClientHandshake()
        XCTAssertFalse(handshake.ready)

        handshake.onNotifications(.state, enabled: true)
        handshake.onStateStartWritten()
        XCTAssertFalse(handshake.ready)

        handshake.onNotifications(.serverToClient, enabled: true)
        XCTAssertTrue(handshake.ready)
        handshake.onNotifications(.serverToClient, enabled: false)
        XCTAssertFalse(handshake.ready)
    }

    func testServerWaitsForSubscriptionEvenWhenStartArrivesFirst() throws {
        let handshake = MdocBleServerHandshake()
        XCTAssertEqual(try handshake.onState([0x01]), .start)
        XCTAssertTrue(handshake.started)
        XCTAssertFalse(handshake.ready)

        handshake.onServer2ClientNotifications(enabled: true)
        XCTAssertTrue(handshake.ready)
        handshake.onServer2ClientNotifications(enabled: false)
        XCTAssertFalse(handshake.ready)
    }

    func testStateParserRejectsMalformedAndUnknownValues() throws {
        XCTAssertEqual(try MdocBleState.parse([0x02]), .end)
        XCTAssertThrowsError(try MdocBleState.parse([]))
        XCTAssertThrowsError(try MdocBleState.parse([0x01, 0x00]))
        XCTAssertThrowsError(try MdocBleState.parse([0x7F]))
    }

    func testIdentMatchesIndependentRFC5869Vector() {
        let ident = MdocBleProtocol.computeIdent(eDeviceKeyBytes: (0..<88).map(UInt8.init))
        XCTAssertEqual(hex("0cd459a9fa6e6f91cba134e5e8c3c3ee"), ident)
    }

    func testMtuAndCoreBluetoothAttributeLimitsAreFlooredAndCapped() {
        XCTAssertEqual(20, MdocBleProtocol.maxChunkSize(negotiatedMtu: 1))
        XCTAssertEqual(20, MdocBleProtocol.maxChunkSize(negotiatedMtu: 23))
        XCTAssertEqual(512, MdocBleProtocol.maxChunkSize(negotiatedMtu: 517))
        XCTAssertEqual(100, MdocBleProtocol.maxChunkSize(negotiatedMtu: 103))
        XCTAssertEqual(20, MdocBleProtocol.maxChunkSize(attributeValueLength: 0))
        XCTAssertEqual(100, MdocBleProtocol.maxChunkSize(attributeValueLength: 100))
        XCTAssertEqual(512, MdocBleProtocol.maxChunkSize(attributeValueLength: 600))
    }

    private func hex(_ value: String) -> [UInt8] {
        stride(from: 0, to: value.count, by: 2).map { offset in
            let start = value.index(value.startIndex, offsetBy: offset)
            let end = value.index(start, offsetBy: 2)
            return UInt8(value[start..<end], radix: 16)!
        }
    }
}

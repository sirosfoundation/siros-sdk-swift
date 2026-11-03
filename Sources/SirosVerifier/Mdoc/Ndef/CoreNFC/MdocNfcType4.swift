// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Platform-independent NFC Forum Type 4 Tag command and response validation.
///
/// Kept free of CoreNFC imports so the wire-format behavior can be tested on
/// every SwiftPM host. `MdocNfcEngagementReader` performs these commands in
/// order on iOS and passes the resulting bytes directly to the NDEF parser.
enum MdocNfcType4 {
    static let ndefTagApplicationAID: [UInt8] = [0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01]
    static let ndefDataFileIdentifier: [UInt8] = [0xE1, 0x04]
    static let maximumReadBinaryChunkSize = 256

    struct Command: Equatable, Sendable {
        let instructionClass: UInt8
        let instructionCode: UInt8
        let p1Parameter: UInt8
        let p2Parameter: UInt8
        let data: [UInt8]
        let expectedResponseLength: Int
    }

    struct ReadChunk: Equatable, Sendable {
        /// Absolute offset in the NDEF data file (the NDEF message starts at 2).
        let offset: Int
        let length: Int
    }

    static var selectNDEFTagApplication: Command {
        Command(
            instructionClass: 0x00,
            instructionCode: 0xA4,
            p1Parameter: 0x04,
            p2Parameter: 0x00,
            data: ndefTagApplicationAID,
            expectedResponseLength: -1
        )
    }

    static var selectNDEFDataFile: Command {
        Command(
            instructionClass: 0x00,
            instructionCode: 0xA4,
            p1Parameter: 0x00,
            p2Parameter: 0x0C,
            data: ndefDataFileIdentifier,
            expectedResponseLength: -1
        )
    }

    static var readNLEN: Command {
        // READ BINARY at file offset zero; NLEN is exactly two bytes.
        Command(
            instructionClass: 0x00,
            instructionCode: 0xB0,
            p1Parameter: 0x00,
            p2Parameter: 0x00,
            data: [],
            expectedResponseLength: 2
        )
    }

    static func readBinary(offset: Int, length: Int) throws -> Command {
        guard (0...Int(UInt16.max)).contains(offset) else {
            throw MdocNfcEngagementError.malformed("READ BINARY offset is outside the Type 4 range")
        }
        guard (1...maximumReadBinaryChunkSize).contains(length) else {
            throw MdocNfcEngagementError.malformed("READ BINARY length must be between 1 and 256 bytes")
        }
        return Command(
            instructionClass: 0x00,
            instructionCode: 0xB0,
            p1Parameter: UInt8((offset >> 8) & 0xFF),
            p2Parameter: UInt8(offset & 0xFF),
            data: [],
            expectedResponseLength: length
        )
    }

    static func requireSuccess(sw1: UInt8, sw2: UInt8) throws {
        guard sw1 == 0x90, sw2 == 0x00 else {
            throw MdocNfcEngagementError.apduStatus(sw1: sw1, sw2: sw2)
        }
    }

    static func requireResponseLength(_ response: [UInt8], expectedLength: Int) throws {
        guard expectedLength >= 0, response.count == expectedLength else {
            throw MdocNfcEngagementError.malformed(
                "Type 4 response has \(response.count) bytes; expected exactly \(expectedLength)"
            )
        }
    }

    static func parseNLEN(_ response: [UInt8]) throws -> Int {
        try requireResponseLength(response, expectedLength: 2)
        let length = (Int(response[0]) << 8) | Int(response[1])
        try validateNDEFLength(length)
        return length
    }

    static func validateNDEFLength(_ length: Int) throws {
        guard length >= 0 else {
            throw MdocNfcEngagementError.malformed("NDEF message length is negative")
        }
        guard length <= MdocNfcHandoverParser.maximumHandoverSelectSize else {
            throw MdocNfcEngagementError.malformed(
                "NDEF message length \(length) exceeds the " +
                    "\(MdocNfcHandoverParser.maximumHandoverSelectSize)-byte limit"
            )
        }
    }

    /// Plans bounded READ BINARY commands covering every NDEF byte exactly once.
    static func chunkPlan(
        ndefLength: Int,
        maximumChunkSize: Int = maximumReadBinaryChunkSize
    ) throws -> [ReadChunk] {
        try validateNDEFLength(ndefLength)
        guard (1...maximumReadBinaryChunkSize).contains(maximumChunkSize) else {
            throw MdocNfcEngagementError.malformed("READ BINARY chunk size must be between 1 and 256 bytes")
        }

        var chunks: [ReadChunk] = []
        chunks.reserveCapacity((ndefLength + maximumChunkSize - 1) / maximumChunkSize)
        var consumed = 0
        while consumed < ndefLength {
            let length = min(maximumChunkSize, ndefLength - consumed)
            let offset = consumed + 2 // Skip the two-byte NLEN prefix.
            guard offset <= Int(UInt16.max) else {
                throw MdocNfcEngagementError.malformed("NDEF data exceeds the Type 4 offset range")
            }
            chunks.append(ReadChunk(offset: offset, length: length))
            consumed += length
        }
        return chunks
    }
}

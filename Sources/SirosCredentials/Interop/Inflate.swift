// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// DEFLATE decompression (RFC 1951), with optional zlib framing (RFC 1950).
///
/// Written out rather than linked because the alternatives are all
/// platform-specific: Apple's `Compression` framework has no Linux
/// counterpart, and a system zlib would put a C module dependency into a
/// package that otherwise builds anywhere Swift does. The only thing that
/// needs it is the Token Status List, whose payloads are a few kilobytes, so
/// a straightforward implementation is the right size of answer.
enum Inflate {

    /// Inflate `data`, accepting either a zlib-wrapped or a raw DEFLATE
    /// stream. Returns nil if the input is not either.
    ///
    /// Both are tried because the Token Status List draft specifies zlib but
    /// a few issuers emit raw DEFLATE, and a "corrupt list" error for a list
    /// that is merely framed differently would be wrong.
    static func inflate(_ data: Data) -> Data? {
        if let zlib = inflateZlib(data) { return zlib }
        return try? inflateRaw(data, from: 0)
    }

    private static func inflateZlib(_ data: Data) -> Data? {
        // RFC 1950: CMF/FLG, where the low nibble of CMF is the compression
        // method (8 = deflate) and (CMF<<8 | FLG) must be a multiple of 31.
        guard data.count > 2 else { return nil }
        let cmf = Int(data[data.startIndex])
        let flg = Int(data[data.startIndex + 1])
        guard cmf & 0x0F == 8, (cmf << 8 | flg) % 31 == 0, flg & 0x20 == 0 else { return nil }
        return try? inflateRaw(data, from: 2)
    }

    private struct Corrupt: Error {}

    private struct BitReader {
        let bytes: [UInt8]
        var position: Int
        var bitBuffer: UInt32 = 0
        var bitCount: Int = 0

        mutating func bits(_ count: Int) throws -> Int {
            while bitCount < count {
                guard position < bytes.count else { throw Corrupt() }
                bitBuffer |= UInt32(bytes[position]) << UInt32(bitCount)
                position += 1
                bitCount += 8
            }
            let value = Int(bitBuffer & ((1 << UInt32(count)) - 1))
            bitBuffer >>= UInt32(count)
            bitCount -= count
            return value
        }

        mutating func alignToByte() {
            bitBuffer = 0
            bitCount = 0
        }
    }

    /// A canonical Huffman decoding table, in the counts-and-symbols form RFC
    /// 1951 §3.2.2 describes.
    private struct Huffman {
        var counts: [Int]
        var symbols: [Int]

        init(lengths: [Int]) {
            var counts = [Int](repeating: 0, count: 16)
            for length in lengths where length > 0 { counts[length] += 1 }
            var offsets = [Int](repeating: 0, count: 16)
            for length in 1..<15 { offsets[length + 1] = offsets[length] + counts[length] }
            var symbols = [Int](repeating: 0, count: lengths.count)
            for (symbol, length) in lengths.enumerated() where length > 0 {
                symbols[offsets[length]] = symbol
                offsets[length] += 1
            }
            self.counts = counts
            self.symbols = symbols
        }

        func decode(_ reader: inout BitReader) throws -> Int {
            var code = 0
            var first = 0
            var index = 0
            for length in 1...15 {
                code |= try reader.bits(1)
                let count = counts[length]
                if code - first < count {
                    return symbols[index + (code - first)]
                }
                index += count
                first = (first + count) << 1
                code <<= 1
            }
            throw Corrupt()
        }
    }

    // RFC 1951 §3.2.5.
    private static let lengthBase = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
        35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258,
    ]
    private static let lengthExtra = [
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
        3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
    ]
    private static let distanceBase = [
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
        257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193,
        12289, 16385, 24577,
    ]
    private static let distanceExtra = [
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
        7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
    ]
    private static let codeLengthOrder = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]

    /// Hard cap on the output, so a malformed or hostile stream cannot be
    /// inflated into unbounded memory. A status list covering a million
    /// credentials at one bit each is 125 KB, so this is far above anything
    /// legitimate.
    private static let maxOutputBytes = 64 * 1024 * 1024

    private static func inflateRaw(_ data: Data, from offset: Int) throws -> Data {
        var reader = BitReader(bytes: [UInt8](data.dropFirst(offset)), position: 0)
        var output = [UInt8]()

        while true {
            let isFinal = try reader.bits(1) == 1
            let type = try reader.bits(2)
            switch type {
            case 0:
                reader.alignToByte()
                guard reader.position + 4 <= reader.bytes.count else { throw Corrupt() }
                let length = Int(reader.bytes[reader.position]) | Int(reader.bytes[reader.position + 1]) << 8
                let complement = Int(reader.bytes[reader.position + 2]) | Int(reader.bytes[reader.position + 3]) << 8
                guard length == (~complement & 0xFFFF) else { throw Corrupt() }
                reader.position += 4
                guard reader.position + length <= reader.bytes.count else { throw Corrupt() }
                guard output.count + length <= maxOutputBytes else { throw Corrupt() }
                output.append(contentsOf: reader.bytes[reader.position..<(reader.position + length)])
                reader.position += length
            case 1:
                try inflateBlock(&reader, &output, literals: fixedLiteralTable, distances: fixedDistanceTable)
            case 2:
                let (literals, distances) = try readDynamicTables(&reader)
                try inflateBlock(&reader, &output, literals: literals, distances: distances)
            default:
                throw Corrupt()
            }
            if isFinal { break }
        }
        return Data(output)
    }

    private static let fixedLiteralTable: Huffman = {
        var lengths = [Int](repeating: 8, count: 288)
        for symbol in 144..<256 { lengths[symbol] = 9 }
        for symbol in 256..<280 { lengths[symbol] = 7 }
        return Huffman(lengths: lengths)
    }()

    private static let fixedDistanceTable = Huffman(lengths: [Int](repeating: 5, count: 30))

    private static func readDynamicTables(_ reader: inout BitReader) throws -> (Huffman, Huffman) {
        let literalCount = try reader.bits(5) + 257
        let distanceCount = try reader.bits(5) + 1
        let codeLengthCount = try reader.bits(4) + 4

        var codeLengths = [Int](repeating: 0, count: 19)
        for index in 0..<codeLengthCount {
            codeLengths[codeLengthOrder[index]] = try reader.bits(3)
        }
        let codeLengthTable = Huffman(lengths: codeLengths)

        var lengths = [Int]()
        lengths.reserveCapacity(literalCount + distanceCount)
        while lengths.count < literalCount + distanceCount {
            let symbol = try codeLengthTable.decode(&reader)
            switch symbol {
            case 0..<16:
                lengths.append(symbol)
            case 16:
                guard let previous = lengths.last else { throw Corrupt() }
                let repeats = try reader.bits(2) + 3
                lengths.append(contentsOf: [Int](repeating: previous, count: repeats))
            case 17:
                let repeats = try reader.bits(3) + 3
                lengths.append(contentsOf: [Int](repeating: 0, count: repeats))
            case 18:
                let repeats = try reader.bits(7) + 11
                lengths.append(contentsOf: [Int](repeating: 0, count: repeats))
            default:
                throw Corrupt()
            }
        }
        guard lengths.count == literalCount + distanceCount else { throw Corrupt() }
        return (
            Huffman(lengths: Array(lengths[0..<literalCount])),
            Huffman(lengths: Array(lengths[literalCount...]))
        )
    }

    private static func inflateBlock(
        _ reader: inout BitReader,
        _ output: inout [UInt8],
        literals: Huffman,
        distances: Huffman
    ) throws {
        while true {
            let symbol = try literals.decode(&reader)
            if symbol < 256 {
                guard output.count < maxOutputBytes else { throw Corrupt() }
                output.append(UInt8(symbol))
                continue
            }
            if symbol == 256 { return }

            let lengthIndex = symbol - 257
            guard lengthIndex < lengthBase.count else { throw Corrupt() }
            let length = lengthBase[lengthIndex] + (try reader.bits(lengthExtra[lengthIndex]))

            let distanceSymbol = try distances.decode(&reader)
            guard distanceSymbol < distanceBase.count else { throw Corrupt() }
            let distance = distanceBase[distanceSymbol] + (try reader.bits(distanceExtra[distanceSymbol]))
            guard distance <= output.count else { throw Corrupt() }
            guard output.count + length <= maxOutputBytes else { throw Corrupt() }

            // Overlapping copies are legal and are how DEFLATE encodes runs,
            // so this has to copy byte by byte rather than by slice.
            var source = output.count - distance
            for _ in 0..<length {
                output.append(output[source])
                source += 1
            }
        }
    }
}

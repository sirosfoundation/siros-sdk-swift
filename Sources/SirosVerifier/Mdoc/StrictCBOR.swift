// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// A small, bounded, definite-length CBOR reader. Unlike a general CBOR map
/// decoder it retains every map entry (so duplicates cannot disappear) and the
/// original byte span of every item (so transcript inputs need no re-encoding).
enum StrictCBOR {
    static let maxDepth = 32

    struct Error: Swift.Error, CustomStringConvertible {
        let description: String
    }

    struct MapEntry {
        let key: Node
        let value: Node
    }

    indirect enum Kind {
        case unsigned(UInt64)
        case negative(UInt64)
        case byteString([UInt8])
        case text(String)
        case array([Node])
        case map([MapEntry])
        case tag(UInt64, Node)
        case simple(UInt8)
        case floatingPoint
    }

    struct Node {
        let kind: Kind
        let range: Range<Int>

        var unsigned: UInt64? {
            if case .unsigned(let value) = kind { return value }
            return nil
        }

        var bytes: [UInt8]? {
            if case .byteString(let value) = kind { return value }
            return nil
        }

        var text: String? {
            if case .text(let value) = kind { return value }
            return nil
        }

        var array: [Node]? {
            if case .array(let value) = kind { return value }
            return nil
        }

        var boolean: Bool? {
            guard case .simple(let value) = kind else { return nil }
            if value == 20 { return false }
            if value == 21 { return true }
            return nil
        }

        /// Integer map label represented as an Int. Negative CBOR integers use
        /// the encoded value n to represent -1-n.
        var integerLabel: Int? {
            switch kind {
            case .unsigned(let value):
                return value <= UInt64(Int.max) ? Int(value) : nil
            case .negative(let value):
                return value <= UInt64(Int.max) ? -1 - Int(value) : nil
            default:
                return nil
            }
        }
    }

    static func parse(_ bytes: [UInt8]) throws -> Node {
        var reader = Reader(bytes: bytes)
        let result = try reader.readValue(depth: 0)
        guard reader.position == bytes.count else {
            throw Error(description: "trailing CBOR at byte \(reader.position)")
        }
        return result
    }

    /// Convert a map with integer labels without losing duplicate detection.
    static func integerMap(_ node: Node) throws -> [Int: Node] {
        guard case .map(let entries) = node.kind else {
            throw Error(description: "expected a CBOR map at byte \(node.range.lowerBound)")
        }
        var result: [Int: Node] = [:]
        for entry in entries {
            guard let label = entry.key.integerLabel else {
                throw Error(description: "non-integer map label at byte \(entry.key.range.lowerBound)")
            }
            guard result.updateValue(entry.value, forKey: label) == nil else {
                throw Error(description: "duplicate map label \(label)")
            }
        }
        return result
    }

    private struct Reader {
        let bytes: [UInt8]
        var position = 0

        mutating func readValue(depth: Int) throws -> Node {
            guard depth <= StrictCBOR.maxDepth else { throw fail("CBOR nesting is too deep") }
            let start = position
            let initial = try readByte()
            let major = initial >> 5
            let additional = initial & 0x1F
            let kind: Kind

            switch major {
            case 0:
                kind = .unsigned(try readArgument(additional))
            case 1:
                kind = .negative(try readArgument(additional))
            case 2:
                kind = .byteString(try readByteString(additional))
            case 3:
                let stringBytes = try readByteString(additional)
                guard let text = String(bytes: stringBytes, encoding: .utf8) else {
                    throw fail("invalid UTF-8 in CBOR text string")
                }
                kind = .text(text)
            case 4:
                kind = .array(try readArray(additional, depth: depth))
            case 5:
                kind = .map(try readMap(additional, depth: depth))
            case 6:
                let tag = try readArgument(additional)
                kind = .tag(tag, try readValue(depth: depth + 1))
            case 7:
                kind = try readSimpleOrFloat(additional)
            default:
                throw fail("invalid CBOR major type")
            }
            return Node(kind: kind, range: start..<position)
        }

        mutating func readArray(_ additional: UInt8, depth: Int) throws -> [Node] {
            let count = try readLength(additional)
            var values: [Node] = []
            values.reserveCapacity(count)
            for _ in 0..<count {
                values.append(try readValue(depth: depth + 1))
            }
            return values
        }

        mutating func readMap(_ additional: UInt8, depth: Int) throws -> [MapEntry] {
            let count = try readLength(additional)
            var entries: [MapEntry] = []
            entries.reserveCapacity(count)
            for _ in 0..<count {
                let key = try readValue(depth: depth + 1)
                let value = try readValue(depth: depth + 1)
                entries.append(MapEntry(key: key, value: value))
            }
            return entries
        }

        mutating func readByteString(_ additional: UInt8) throws -> [UInt8] {
            try readBytes(count: readLength(additional))
        }

        /// Read a definite length/count. The input-size cap makes this bound
        /// useful even for arrays of one-byte items and prevents huge reserves.
        mutating func readLength(_ additional: UInt8) throws -> Int {
            let value = try readArgument(additional)
            guard value <= UInt64(Int.max) else { throw fail("CBOR length exceeds platform Int") }
            let count = Int(value)
            guard count <= bytes.count - position else { throw fail("CBOR length exceeds remaining input") }
            return count
        }

        mutating func readArgument(_ additional: UInt8) throws -> UInt64 {
            switch additional {
            case 0...23:
                return UInt64(additional)
            case 24:
                return UInt64(try readByte())
            case 25:
                return try readBigEndian(byteCount: 2)
            case 26:
                return try readBigEndian(byteCount: 4)
            case 27:
                return try readBigEndian(byteCount: 8)
            case 31:
                throw fail("indefinite-length CBOR is not supported")
            default:
                throw fail("reserved CBOR additional-information value")
            }
        }

        mutating func readSimpleOrFloat(_ additional: UInt8) throws -> Kind {
            switch additional {
            case 0...23:
                return .simple(additional)
            case 24:
                return .simple(try readByte())
            case 25:
                _ = try readBytes(count: 2)
                return .floatingPoint
            case 26:
                _ = try readBytes(count: 4)
                return .floatingPoint
            case 27:
                _ = try readBytes(count: 8)
                return .floatingPoint
            case 31:
                throw fail("unexpected CBOR break")
            default:
                throw fail("reserved CBOR simple/float encoding")
            }
        }

        mutating func readBigEndian(byteCount: Int) throws -> UInt64 {
            var result: UInt64 = 0
            for byte in try readBytes(count: byteCount) {
                result = (result << 8) | UInt64(byte)
            }
            return result
        }

        mutating func readBytes(count: Int) throws -> [UInt8] {
            guard count >= 0, count <= bytes.count - position else { throw fail("truncated CBOR input") }
            let end = position + count
            let result = Array(bytes[position..<end])
            position = end
            return result
        }

        mutating func readByte() throws -> UInt8 {
            guard position < bytes.count else { throw fail("unexpected end of CBOR") }
            let result = bytes[position]
            position += 1
            return result
        }

        func fail(_ message: String) -> Error {
            Error(description: "\(message) at byte \(position)")
        }
    }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// A JSON value with exact number kinds, used by the EC TS12 pipeline.
///
/// Parsed with `StrictJSON`, not `JSONSerialization`, because the pipeline
/// must (a) tell booleans from numbers and integers from reals reliably on
/// every platform, and (b) refuse documents a lenient parser would accept in
/// an ambiguous way (duplicate object keys, trailing content, runaway
/// nesting), since the user is asked to consent to what this parse says.
public enum JSONValue: Sendable, Equatable {
    case null
    case bool(Bool)
    case int(Int64)
    case double(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    public var stringValue: String? { if case .string(let s) = self { return s }; return nil }
    public var objectValue: [String: JSONValue]? { if case .object(let o) = self { return o }; return nil }
    public var arrayValue: [JSONValue]? { if case .array(let a) = self { return a }; return nil }
    public var boolValue: Bool? { if case .bool(let b) = self { return b }; return nil }

    public subscript(key: String) -> JSONValue? { objectValue?[key] }

    /// Numeric value of an `.int` or `.double`, `nil` otherwise.
    public var numberValue: Double? {
        switch self {
        case .int(let i): return Double(i)
        case .double(let d): return d
        default: return nil
        }
    }

    /// Equality in the JSON data model: `1` equals `1.0`.
    public func jsonEquals(_ other: JSONValue) -> Bool {
        switch (self, other) {
        case (.null, .null): return true
        case (.bool(let a), .bool(let b)): return a == b
        case (.string(let a), .string(let b)): return a == b
        case (.array(let a), .array(let b)):
            return a.count == b.count && zip(a, b).allSatisfy { $0.jsonEquals($1) }
        case (.object(let a), .object(let b)):
            return a.count == b.count && a.allSatisfy { k, v in b[k].map { v.jsonEquals($0) } ?? false }
        default:
            if let a = numberValue, let b = other.numberValue { return a == b }
            return false
        }
    }
}

/// Strict, bounded JSON parser (RFC 8259).
public enum StrictJSON {
    public struct ParseError: Error, Equatable, CustomStringConvertible {
        public let description: String
    }

    /// Maximum nesting depth accepted.
    public static let maxDepth = 32

    public static func parse(_ text: String) throws -> JSONValue {
        try parse(Data(text.utf8))
    }

    public static func parse(_ data: Data) throws -> JSONValue {
        var parser = Parser(bytes: [UInt8](data))
        parser.skipWhitespace()
        let value = try parser.parseValue(depth: 0)
        parser.skipWhitespace()
        guard parser.atEnd else { throw ParseError(description: "trailing content after JSON value") }
        return value
    }

    private struct Parser {
        let bytes: [UInt8]
        var pos = 0
        init(bytes: [UInt8]) { self.bytes = bytes }

        var atEnd: Bool { pos >= bytes.count }

        mutating func skipWhitespace() {
            while pos < bytes.count, [0x20, 0x09, 0x0A, 0x0D].contains(bytes[pos]) { pos += 1 }
        }

        func fail(_ message: String) -> ParseError { ParseError(description: "\(message) at byte \(pos)") }

        mutating func parseValue(depth: Int) throws -> JSONValue {
            guard depth <= StrictJSON.maxDepth else { throw fail("nesting too deep") }
            guard pos < bytes.count else { throw fail("unexpected end") }
            switch bytes[pos] {
            case UInt8(ascii: "{"): return try parseObject(depth: depth)
            case UInt8(ascii: "["): return try parseArray(depth: depth)
            case UInt8(ascii: "\""): return .string(try parseString())
            case UInt8(ascii: "t"): try expect("true"); return .bool(true)
            case UInt8(ascii: "f"): try expect("false"); return .bool(false)
            case UInt8(ascii: "n"): try expect("null"); return .null
            default: return try parseNumber()
            }
        }

        mutating func expect(_ word: String) throws {
            let w = Array(word.utf8)
            guard pos + w.count <= bytes.count, Array(bytes[pos..<pos + w.count]) == w else { throw fail("invalid literal") }
            pos += w.count
        }

        mutating func parseObject(depth: Int) throws -> JSONValue {
            pos += 1
            var result: [String: JSONValue] = [:]
            skipWhitespace()
            if pos < bytes.count, bytes[pos] == UInt8(ascii: "}") { pos += 1; return .object(result) }
            while true {
                skipWhitespace()
                guard pos < bytes.count, bytes[pos] == UInt8(ascii: "\"") else { throw fail("expected object key") }
                let key = try parseString()
                guard result[key] == nil else { throw fail("duplicate object key") }
                skipWhitespace()
                guard pos < bytes.count, bytes[pos] == UInt8(ascii: ":") else { throw fail("expected ':'") }
                pos += 1
                skipWhitespace()
                result[key] = try parseValue(depth: depth + 1)
                skipWhitespace()
                guard pos < bytes.count else { throw fail("unterminated object") }
                if bytes[pos] == UInt8(ascii: ",") { pos += 1; continue }
                if bytes[pos] == UInt8(ascii: "}") { pos += 1; return .object(result) }
                throw fail("expected ',' or '}'")
            }
        }

        mutating func parseArray(depth: Int) throws -> JSONValue {
            pos += 1
            var result: [JSONValue] = []
            skipWhitespace()
            if pos < bytes.count, bytes[pos] == UInt8(ascii: "]") { pos += 1; return .array(result) }
            while true {
                skipWhitespace()
                result.append(try parseValue(depth: depth + 1))
                skipWhitespace()
                guard pos < bytes.count else { throw fail("unterminated array") }
                if bytes[pos] == UInt8(ascii: ",") { pos += 1; continue }
                if bytes[pos] == UInt8(ascii: "]") { pos += 1; return .array(result) }
                throw fail("expected ',' or ']'")
            }
        }

        mutating func parseHex4() throws -> UInt32 {
            guard pos + 4 <= bytes.count else { throw fail("bad \\u escape") }
            var value: UInt32 = 0
            for _ in 0..<4 {
                guard let digit = Character(UnicodeScalar(bytes[pos])).hexDigitValue else { throw fail("bad \\u escape") }
                value = value * 16 + UInt32(digit)
                pos += 1
            }
            return value
        }

        mutating func parseString() throws -> String {
            pos += 1
            var out = [UInt8]()
            while true {
                guard pos < bytes.count else { throw fail("unterminated string") }
                let b = bytes[pos]
                if b == UInt8(ascii: "\"") { pos += 1; break }
                if b < 0x20 { throw fail("control character in string") }
                if b != UInt8(ascii: "\\") { out.append(b); pos += 1; continue }
                pos += 1
                guard pos < bytes.count else { throw fail("bad escape") }
                let e = bytes[pos]
                pos += 1
                switch e {
                case UInt8(ascii: "\""): out.append(0x22)
                case UInt8(ascii: "\\"): out.append(0x5C)
                case UInt8(ascii: "/"): out.append(0x2F)
                case UInt8(ascii: "b"): out.append(0x08)
                case UInt8(ascii: "f"): out.append(0x0C)
                case UInt8(ascii: "n"): out.append(0x0A)
                case UInt8(ascii: "r"): out.append(0x0D)
                case UInt8(ascii: "t"): out.append(0x09)
                case UInt8(ascii: "u"):
                    var code = try parseHex4()
                    if (0xD800...0xDBFF).contains(code) {
                        guard pos + 2 <= bytes.count, bytes[pos] == UInt8(ascii: "\\"), bytes[pos + 1] == UInt8(ascii: "u") else {
                            throw fail("lone surrogate")
                        }
                        pos += 2
                        let low = try parseHex4()
                        guard (0xDC00...0xDFFF).contains(low) else { throw fail("lone surrogate") }
                        code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)
                    } else if (0xDC00...0xDFFF).contains(code) {
                        throw fail("lone surrogate")
                    }
                    guard let scalar = UnicodeScalar(code) else { throw fail("bad \\u escape") }
                    out.append(contentsOf: Array(String(Character(scalar)).utf8))
                default: throw fail("bad escape")
                }
            }
            guard let s = String(bytes: out, encoding: .utf8) else { throw fail("invalid UTF-8 in string") }
            return s
        }

        mutating func parseNumber() throws -> JSONValue {
            let start = pos
            if pos < bytes.count, bytes[pos] == UInt8(ascii: "-") { pos += 1 }
            guard pos < bytes.count, bytes[pos] >= 0x30, bytes[pos] <= 0x39 else { throw fail("invalid value") }
            if bytes[pos] == 0x30 {
                pos += 1
                if pos < bytes.count, bytes[pos] >= 0x30, bytes[pos] <= 0x39 { throw fail("leading zero") }
            } else {
                while pos < bytes.count, bytes[pos] >= 0x30, bytes[pos] <= 0x39 { pos += 1 }
            }
            var isInt = true
            if pos < bytes.count, bytes[pos] == UInt8(ascii: ".") {
                isInt = false
                pos += 1
                let fracStart = pos
                while pos < bytes.count, bytes[pos] >= 0x30, bytes[pos] <= 0x39 { pos += 1 }
                guard pos > fracStart else { throw fail("bad fraction") }
            }
            if pos < bytes.count, bytes[pos] == UInt8(ascii: "e") || bytes[pos] == UInt8(ascii: "E") {
                isInt = false
                pos += 1
                if pos < bytes.count, bytes[pos] == UInt8(ascii: "+") || bytes[pos] == UInt8(ascii: "-") { pos += 1 }
                let expStart = pos
                while pos < bytes.count, bytes[pos] >= 0x30, bytes[pos] <= 0x39 { pos += 1 }
                guard pos > expStart else { throw fail("bad exponent") }
            }
            let text = String(decoding: bytes[start..<pos], as: UTF8.self)
            if isInt, let i = Int64(text) { return .int(i) }
            guard let d = Double(text), d.isFinite else { throw fail("number out of range") }
            return .double(d)
        }
    }
}

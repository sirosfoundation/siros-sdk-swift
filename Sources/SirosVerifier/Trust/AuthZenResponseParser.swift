// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Strict JSON parsing for the small security-critical part of AuthZEN.
/// JSONSerialization cannot be used here because duplicate object members must
/// be rejected instead of silently resolving to one of their values.
enum AuthZenResponseParser {
    private indirect enum Value {
        case null
        case bool(Bool)
        case number
        case string
        case array([Value])
        case object([String: Value])
    }

    private struct ParseError: Error, CustomStringConvertible {
        let description: String
    }

    static func decision(in data: Data) throws -> Bool {
        guard String(data: data, encoding: .utf8) != nil else {
            throw AuthZenPdpError.invalidResponse("response is not UTF-8")
        }
        do {
            var parser = Parser(bytes: [UInt8](data))
            parser.skipWhitespace()
            let value = try parser.parseValue(depth: 0)
            parser.skipWhitespace()
            guard parser.atEnd else { throw parser.fail("trailing content") }
            guard case .object(let object) = value else {
                throw AuthZenPdpError.invalidResponse("top-level JSON value is not an object")
            }
            guard let decision = object["decision"] else {
                throw AuthZenPdpError.invalidResponse("missing top-level decision")
            }
            guard case .bool(let result) = decision else {
                throw AuthZenPdpError.invalidResponse("top-level decision is not a boolean")
            }
            return result
        } catch let error as AuthZenPdpError {
            throw error
        } catch let error as ParseError {
            throw AuthZenPdpError.invalidResponse(error.description)
        } catch {
            throw AuthZenPdpError.invalidResponse("malformed JSON")
        }
    }

    private struct Parser {
        static let maxDepth = 64

        let bytes: [UInt8]
        var position = 0
        var atEnd: Bool { position >= bytes.count }

        mutating func skipWhitespace() {
            while position < bytes.count,
                  bytes[position] == 0x20 || bytes[position] == 0x09 ||
                    bytes[position] == 0x0A || bytes[position] == 0x0D {
                position += 1
            }
        }

        func fail(_ message: String) -> ParseError {
            ParseError(description: "\(message) at byte \(position)")
        }

        mutating func parseValue(depth: Int) throws -> Value {
            guard depth <= Self.maxDepth else { throw fail("JSON nesting is too deep") }
            guard position < bytes.count else { throw fail("unexpected end of JSON") }
            switch bytes[position] {
            case UInt8(ascii: "{"):
                return try parseObject(depth: depth)
            case UInt8(ascii: "["):
                return try parseArray(depth: depth)
            case UInt8(ascii: "\""):
                _ = try parseString()
                return .string
            case UInt8(ascii: "t"):
                try expect("true")
                return .bool(true)
            case UInt8(ascii: "f"):
                try expect("false")
                return .bool(false)
            case UInt8(ascii: "n"):
                try expect("null")
                return .null
            default:
                try parseNumber()
                return .number
            }
        }

        mutating func expect(_ literal: String) throws {
            let expected = Array(literal.utf8)
            guard position + expected.count <= bytes.count,
                  Array(bytes[position..<(position + expected.count)]) == expected else {
                throw fail("invalid JSON literal")
            }
            position += expected.count
        }

        mutating func parseObject(depth: Int) throws -> Value {
            position += 1
            var object: [String: Value] = [:]
            skipWhitespace()
            if consume(UInt8(ascii: "}")) { return .object(object) }
            while true {
                skipWhitespace()
                guard position < bytes.count, bytes[position] == UInt8(ascii: "\"") else {
                    throw fail("expected an object member name")
                }
                let key = try parseString()
                guard object[key] == nil else { throw fail("duplicate object member \(key)") }
                skipWhitespace()
                guard consume(UInt8(ascii: ":")) else { throw fail("expected ':'") }
                skipWhitespace()
                object[key] = try parseValue(depth: depth + 1)
                skipWhitespace()
                if consume(UInt8(ascii: ",")) { continue }
                if consume(UInt8(ascii: "}")) { return .object(object) }
                throw fail("expected ',' or '}'")
            }
        }

        mutating func parseArray(depth: Int) throws -> Value {
            position += 1
            var array: [Value] = []
            skipWhitespace()
            if consume(UInt8(ascii: "]")) { return .array(array) }
            while true {
                skipWhitespace()
                array.append(try parseValue(depth: depth + 1))
                skipWhitespace()
                if consume(UInt8(ascii: ",")) { continue }
                if consume(UInt8(ascii: "]")) { return .array(array) }
                throw fail("expected ',' or ']'")
            }
        }

        mutating func consume(_ byte: UInt8) -> Bool {
            guard position < bytes.count, bytes[position] == byte else { return false }
            position += 1
            return true
        }

        mutating func parseString() throws -> String {
            position += 1
            var output: [UInt8] = []
            while true {
                guard position < bytes.count else { throw fail("unterminated JSON string") }
                let byte = bytes[position]
                if byte == UInt8(ascii: "\"") {
                    position += 1
                    break
                }
                guard byte >= 0x20 else { throw fail("control character in JSON string") }
                position += 1
                if byte != UInt8(ascii: "\\") {
                    output.append(byte)
                    continue
                }
                guard position < bytes.count else { throw fail("unterminated JSON escape") }
                let escaped = bytes[position]
                position += 1
                if let simple = Self.simpleEscapes[escaped] {
                    output.append(simple)
                } else if escaped == UInt8(ascii: "u") {
                    output.append(contentsOf: try parseUnicodeEscape())
                } else {
                    throw fail("invalid JSON escape")
                }
            }
            guard let result = String(bytes: output, encoding: .utf8) else {
                throw fail("invalid UTF-8 in JSON string")
            }
            return result
        }

        mutating func parseUnicodeEscape() throws -> [UInt8] {
            var scalar = try parseHex4()
            if (0xD800...0xDBFF).contains(scalar) {
                guard position + 2 <= bytes.count,
                      bytes[position] == UInt8(ascii: "\\"),
                      bytes[position + 1] == UInt8(ascii: "u") else {
                    throw fail("unpaired high surrogate")
                }
                position += 2
                let low = try parseHex4()
                guard (0xDC00...0xDFFF).contains(low) else { throw fail("invalid surrogate pair") }
                scalar = 0x10000 + ((scalar - 0xD800) << 10) + (low - 0xDC00)
            } else if (0xDC00...0xDFFF).contains(scalar) {
                throw fail("unpaired low surrogate")
            }
            guard let unicodeScalar = UnicodeScalar(scalar) else { throw fail("invalid Unicode escape") }
            return Array(String(Character(unicodeScalar)).utf8)
        }

        mutating func parseHex4() throws -> UInt32 {
            guard position + 4 <= bytes.count else { throw fail("short Unicode escape") }
            var result: UInt32 = 0
            for _ in 0..<4 {
                guard let digit = Character(UnicodeScalar(bytes[position])).hexDigitValue else {
                    throw fail("invalid Unicode escape")
                }
                result = result * 16 + UInt32(digit)
                position += 1
            }
            return result
        }

        mutating func parseNumber() throws {
            let start = position
            _ = consume(UInt8(ascii: "-"))
            guard position < bytes.count, isDigit(bytes[position]) else { throw fail("invalid JSON value") }
            if bytes[position] == UInt8(ascii: "0") {
                position += 1
                guard position >= bytes.count || !isDigit(bytes[position]) else {
                    throw fail("leading zero in JSON number")
                }
            } else {
                while position < bytes.count, isDigit(bytes[position]) { position += 1 }
            }
            if consume(UInt8(ascii: ".")) {
                let fraction = position
                while position < bytes.count, isDigit(bytes[position]) { position += 1 }
                guard position > fraction else { throw fail("empty JSON number fraction") }
            }
            if position < bytes.count, bytes[position] == UInt8(ascii: "e") || bytes[position] == UInt8(ascii: "E") {
                position += 1
                if position < bytes.count, bytes[position] == UInt8(ascii: "+") || bytes[position] == UInt8(ascii: "-") {
                    position += 1
                }
                let exponent = position
                while position < bytes.count, isDigit(bytes[position]) { position += 1 }
                guard position > exponent else { throw fail("empty JSON number exponent") }
            }
            guard position > start else { throw fail("invalid JSON number") }
        }

        private func isDigit(_ byte: UInt8) -> Bool {
            byte >= UInt8(ascii: "0") && byte <= UInt8(ascii: "9")
        }

        private static let simpleEscapes: [UInt8: UInt8] = [
            UInt8(ascii: "\""): 0x22,
            UInt8(ascii: "\\"): 0x5C,
            UInt8(ascii: "/"): 0x2F,
            UInt8(ascii: "b"): 0x08,
            UInt8(ascii: "f"): 0x0C,
            UInt8(ascii: "n"): 0x0A,
            UInt8(ascii: "r"): 0x0D,
            UInt8(ascii: "t"): 0x09,
        ]
    }
}

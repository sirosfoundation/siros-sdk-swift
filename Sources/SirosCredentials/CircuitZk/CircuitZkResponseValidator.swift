// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Why a `circuit_zk` response was refused. The `code` is the stable identifier shared with the
/// conformance vectors (siros-dc-matcher `circuit_zk_response`); the first rule broken is reported.
public enum CircuitZkResponseError: Error, Equatable, Sendable {
    case responseNotParseable
    case duplicateMember
    case queryIdMissing
    case presentationsNotArray
    case presentationsEmpty
    case presentationsMultipleNotAllowed
    case presentationNotObject
    case presentationErrorMember
    case presentationUnknownMember
    case presentationMemberMissing
    case presentationMemberWrongType
    case circuitIdNotOffered
    case proofSystemNotOffered
    case proofEmpty
    case proofNotBase64url
    case x5chainNotArray, x5chainEmpty, x5chainTooMany
    case x5chainElementNotString, x5chainElementEmpty, x5chainElementNotBase64, x5chainElementTooLarge
    case duplicateHandle
    case resultHandleUnexpected
    case resultHandleMissing
    case resultNotObject
    case resultFunctionUnknown
    case resultUnknownMember
    case resultMemberMissing
    case resultMemberWrongType
    case resultNotSatisfied
    case pseudonymNotBase64url
    case pseudonymWrongLength

    /// The stable reason code.
    public var code: String {
        switch self {
        case .responseNotParseable: return "response_not_parseable"
        case .duplicateMember: return "duplicate_member"
        case .queryIdMissing: return "query_id_missing"
        case .presentationsNotArray: return "presentations_not_array"
        case .presentationsEmpty: return "presentations_empty"
        case .presentationsMultipleNotAllowed: return "presentations_multiple_not_allowed"
        case .presentationNotObject: return "presentation_not_object"
        case .presentationErrorMember: return "presentation_error_member"
        case .presentationUnknownMember: return "presentation_unknown_member"
        case .presentationMemberMissing: return "presentation_member_missing"
        case .presentationMemberWrongType: return "presentation_member_wrong_type"
        case .circuitIdNotOffered: return "circuit_id_not_offered"
        case .proofSystemNotOffered: return "proof_system_not_offered"
        case .proofEmpty: return "proof_empty"
        case .proofNotBase64url: return "proof_not_base64url"
        case .x5chainNotArray: return "x5chain_not_array"
        case .x5chainEmpty: return "x5chain_empty"
        case .x5chainTooMany: return "x5chain_too_many"
        case .x5chainElementNotString: return "x5chain_element_not_string"
        case .x5chainElementEmpty: return "x5chain_element_empty"
        case .x5chainElementNotBase64: return "x5chain_element_not_base64"
        case .x5chainElementTooLarge: return "x5chain_element_too_large"
        case .duplicateHandle: return "duplicate_handle"
        case .resultHandleUnexpected: return "result_handle_unexpected"
        case .resultHandleMissing: return "result_handle_missing"
        case .resultNotObject: return "result_not_object"
        case .resultFunctionUnknown: return "result_function_unknown"
        case .resultUnknownMember: return "result_unknown_member"
        case .resultMemberMissing: return "result_member_missing"
        case .resultMemberWrongType: return "result_member_wrong_type"
        case .resultNotSatisfied: return "result_not_satisfied"
        case .pseudonymNotBase64url: return "pseudonym_not_base64url"
        case .pseudonymWrongLength: return "pseudonym_wrong_length"
        }
    }
}

/// What the response is checked against: the request's credential query id, whether it allows several
/// presentations, the offered circuit ids and proof systems (nil = the request stated none, so nothing was
/// offered), and the `return` handle of every `req` item with the function that answers it.
public struct CircuitZkResponseExpectation: Sendable, Equatable {
    public struct Item: Sendable, Equatable {
        public let handle: String
        public let functionId: String

        public init(handle: String, functionId: String) {
            self.handle = handle
            self.functionId = functionId
        }
    }

    public let queryId: String
    public let multiple: Bool
    public let circuitIds: [String]?
    public let proofSystems: [String]?
    public let items: [Item]

    public init(queryId: String, multiple: Bool, circuitIds: [String]?, proofSystems: [String]?, items: [Item]) {
        self.queryId = queryId
        self.multiple = multiple
        self.circuitIds = circuitIds
        self.proofSystems = proofSystems
        self.items = items
    }
}

/// Checks the SHAPE of a `circuit_zk` entry in a `vp_token` and its binding to the request
/// (docs/circuit_zk_response.md of siros-dc-matcher; the shared vectors are
/// `tests/vectors/circuit_zk_response/`, copied verbatim). It does not verify or decode the proof. A JSON
/// `null` is a value of the wrong type wherever it appears; duplicate members are judged on the raw text.
/// A wallet runs it on the response it built before sending it.
public enum CircuitZkResponseValidator {
    /// Result functions this validator knows (each has a result shape).
    public static let pseudonymFunction = "pseudonym-v1-sha256"
    public static let ageFunction = "age_check"
    public static let pseudonymBytes = 32

    private static let memberNames = ["circuit_id", "proof_system", "proof", "x5chain", "results"]

    public static func validate(_ expectation: CircuitZkResponseExpectation, vpToken: String) throws {
        guard case .object(let token)? = RawJSON.parse(vpToken) else { throw CircuitZkResponseError.responseNotParseable }
        let unique = try uniqueMembers(token)
        guard let entry = unique[expectation.queryId] else { throw CircuitZkResponseError.queryIdMissing }
        guard case .array(let presentations) = entry else { throw CircuitZkResponseError.presentationsNotArray }
        guard !presentations.isEmpty else { throw CircuitZkResponseError.presentationsEmpty }
        if presentations.count > 1, !expectation.multiple { throw CircuitZkResponseError.presentationsMultipleNotAllowed }
        for presentation in presentations { try check(presentation, expectation) }
    }

    private static func uniqueMembers(_ pairs: [(String, RawJSON)]) throws -> [String: RawJSON] {
        var out: [String: RawJSON] = [:]
        for (key, value) in pairs {
            guard out[key] == nil else { throw CircuitZkResponseError.duplicateMember }
            out[key] = value
        }
        return out
    }

    private static func check(_ presentation: RawJSON, _ expectation: CircuitZkResponseExpectation) throws {
        guard case .object(let pairs) = presentation else { throw CircuitZkResponseError.presentationNotObject }
        let members = try uniqueMembers(pairs)
        if members["error"] != nil || members["error_description"] != nil { throw CircuitZkResponseError.presentationErrorMember }
        if members.keys.contains(where: { !memberNames.contains($0) }) { throw CircuitZkResponseError.presentationUnknownMember }
        // Presence of every member first, then types, then the offer and the proof.
        for member in memberNames where members[member] == nil { throw CircuitZkResponseError.presentationMemberMissing }
        func string(_ member: String) throws -> String {
            guard case .string(let text)? = members[member] else { throw CircuitZkResponseError.presentationMemberWrongType }
            return text
        }
        let circuitId = try string("circuit_id")
        let proofSystem = try string("proof_system")
        let proof = try string("proof")
        guard case .array(let chain)? = members["x5chain"] else { throw CircuitZkResponseError.x5chainNotArray }
        guard case .object(let results)? = members["results"] else { throw CircuitZkResponseError.presentationMemberWrongType }
        // Fail closed: a request that stated no list offered nothing to match.
        guard expectation.circuitIds?.contains(circuitId) == true else { throw CircuitZkResponseError.circuitIdNotOffered }
        guard expectation.proofSystems?.contains(proofSystem) == true else { throw CircuitZkResponseError.proofSystemNotOffered }
        guard !proof.isEmpty else { throw CircuitZkResponseError.proofEmpty }
        guard Base64Strict.isUnpaddedBase64url(proof) else { throw CircuitZkResponseError.proofNotBase64url }
        try checkChain(chain)
        try checkResults(results, expectation)
    }

    /// Encoding and limits only. The certificates are not parsed.
    private static func checkChain(_ chain: [RawJSON]) throws {
        guard !chain.isEmpty else { throw CircuitZkResponseError.x5chainEmpty }
        guard chain.count <= CircuitZkX5Chain.maxCertificates else { throw CircuitZkResponseError.x5chainTooMany }
        for element in chain {
            guard case .string(let text) = element else { throw CircuitZkResponseError.x5chainElementNotString }
            guard !text.isEmpty else { throw CircuitZkResponseError.x5chainElementEmpty }
            guard let length = Base64Strict.paddedStandardDecodedLength(text) else { throw CircuitZkResponseError.x5chainElementNotBase64 }
            guard length <= CircuitZkX5Chain.maxCertificateBytes else { throw CircuitZkResponseError.x5chainElementTooLarge }
        }
    }

    private static func checkResults(_ pairs: [(String, RawJSON)], _ expectation: CircuitZkResponseExpectation) throws {
        var seen = Set<String>()
        for (handle, _) in pairs where !seen.insert(handle).inserted { throw CircuitZkResponseError.duplicateHandle }
        let wanted = Set(expectation.items.map(\.handle))
        if pairs.contains(where: { !wanted.contains($0.0) }) { throw CircuitZkResponseError.resultHandleUnexpected }
        // Every handle is present before any value is judged.
        for item in expectation.items where !seen.contains(item.handle) { throw CircuitZkResponseError.resultHandleMissing }
        for item in expectation.items {
            guard let value = pairs.first(where: { $0.0 == item.handle })?.1 else { throw CircuitZkResponseError.resultHandleMissing }
            guard case .object(let valuePairs) = value else { throw CircuitZkResponseError.resultNotObject }
            let members = try uniqueMembers(valuePairs)
            switch item.functionId {
            case pseudonymFunction: try checkPseudonym(members)
            case ageFunction: try checkAge(members)
            default: throw CircuitZkResponseError.resultFunctionUnknown
            }
        }
    }

    private static func sole(_ members: [String: RawJSON], _ name: String) throws -> RawJSON {
        if members.keys.contains(where: { $0 != name }) { throw CircuitZkResponseError.resultUnknownMember }
        guard let value = members[name] else { throw CircuitZkResponseError.resultMemberMissing }
        return value
    }

    private static func checkPseudonym(_ members: [String: RawJSON]) throws {
        guard case .string(let text) = try sole(members, "pseudonym") else { throw CircuitZkResponseError.resultMemberWrongType }
        guard let length = Base64Strict.unpaddedBase64urlDecodedLength(text) else { throw CircuitZkResponseError.pseudonymNotBase64url }
        guard length == pseudonymBytes else { throw CircuitZkResponseError.pseudonymWrongLength }
    }

    private static func checkAge(_ members: [String: RawJSON]) throws {
        switch try sole(members, "satisfied") {
        case .bool(true): return
        case .bool(false): throw CircuitZkResponseError.resultNotSatisfied
        default: throw CircuitZkResponseError.resultMemberWrongType
        }
    }
}

/// Strict base64 forms, without decoding more than needed.
enum Base64Strict {
    private static func value(_ c: UInt8, url: Bool) -> UInt8? {
        switch c {
        case 0x41...0x5A: return c - 0x41
        case 0x61...0x7A: return c - 0x61 + 26
        case 0x30...0x39: return c - 0x30 + 52
        case 0x2B where !url: return 62
        case 0x2F where !url: return 63
        case 0x2D where url: return 62
        case 0x5F where url: return 63
        default: return nil
        }
    }

    /// Decoded length of strict PADDED standard base64 (RFC 4648 section 4), or nil: wrong alphabet,
    /// whitespace, missing or misplaced padding, or non-canonical trailing bits.
    static func paddedStandardDecodedLength(_ text: String) -> Int? {
        let bytes = Array(text.utf8)
        guard !bytes.isEmpty, bytes.count % 4 == 0 else { return nil }
        let padding = bytes.reversed().prefix(while: { $0 == 0x3D }).count
        guard padding <= 2 else { return nil }
        let values = bytes.dropLast(padding).map { value($0, url: false) }
        guard values.allSatisfy({ $0 != nil }), let last = values.last.flatMap({ $0 }) else { return nil }
        let canonical = padding == 1 ? last & 0x03 == 0 : padding == 2 ? last & 0x0F == 0 : true
        return canonical ? bytes.count / 4 * 3 - padding : nil
    }

    /// Decoded length of strict UNPADDED base64url, or nil. The empty string is length 0.
    static func unpaddedBase64urlDecodedLength(_ text: String) -> Int? {
        let bytes = Array(text.utf8)
        guard bytes.count % 4 != 1 else { return nil }
        let values = bytes.map { value($0, url: true) }
        guard values.allSatisfy({ $0 != nil }) else { return nil }
        if let last = values.last.flatMap({ $0 }) {
            // Trailing bits of the last character must be zero (canonical encoding).
            switch bytes.count % 4 {
            case 2: guard last & 0x0F == 0 else { return nil }
            case 3: guard last & 0x03 == 0 else { return nil }
            default: break
            }
        }
        return bytes.count / 4 * 3 + (bytes.count % 4 == 0 ? 0 : bytes.count % 4 - 1)
    }

    static func isUnpaddedBase64url(_ text: String) -> Bool { unpaddedBase64urlDecodedLength(text) != nil }
}

/// JSON that KEEPS duplicate object members (a parsed dictionary would silently keep one). Numbers are
/// kept only as "a number"; nothing here needs their value.
indirect enum RawJSON {
    case object([(String, RawJSON)])
    case array([RawJSON])
    case string(String)
    case number
    case bool(Bool)
    case null

    /// Strict RFC 8259 parse of the whole text, or nil.
    static func parse(_ text: String) -> RawJSON? {
        var parser = Parser(bytes: Array(text.utf8))
        guard let value = parser.value(depth: 0) else { return nil }
        parser.skipSpace()
        return parser.index == parser.bytes.count ? value : nil
    }

    private struct Parser {
        let bytes: [UInt8]
        var index = 0
        static let maxDepth = 64

        mutating func skipSpace() {
            while index < bytes.count, [0x20, 0x09, 0x0A, 0x0D].contains(bytes[index]) { index += 1 }
        }

        mutating func value(depth: Int) -> RawJSON? {
            guard depth < Self.maxDepth else { return nil }
            skipSpace()
            guard index < bytes.count else { return nil }
            switch bytes[index] {
            case UInt8(ascii: "{"): return object(depth: depth)
            case UInt8(ascii: "["): return array(depth: depth)
            case UInt8(ascii: "\""): return string().map(RawJSON.string)
            case UInt8(ascii: "t"): return literal("true", .bool(true))
            case UInt8(ascii: "f"): return literal("false", .bool(false))
            case UInt8(ascii: "n"): return literal("null", .null)
            default: return number()
            }
        }

        mutating func literal(_ word: String, _ result: RawJSON) -> RawJSON? {
            let wordBytes = Array(word.utf8)
            guard index + wordBytes.count <= bytes.count, Array(bytes[index..<index + wordBytes.count]) == wordBytes else { return nil }
            index += wordBytes.count
            return result
        }

        /// Consumes one or more digits; false when there is none.
        mutating func digits(_ range: ClosedRange<UInt8> = 0x30...0x39) -> Bool {
            let start = index
            while index < bytes.count, range.contains(bytes[index]) { index += 1 }
            return index > start
        }

        mutating func accept(_ candidates: UInt8...) -> Bool {
            guard index < bytes.count, candidates.contains(bytes[index]) else { return false }
            index += 1
            return true
        }

        mutating func number() -> RawJSON? {
            let start = index
            _ = accept(UInt8(ascii: "-"))
            guard index < bytes.count else { return nil }
            if bytes[index] == UInt8(ascii: "0") {
                index += 1
            } else if digits(0x31...0x39) {
                _ = digits()
            } else {
                return nil
            }
            if accept(UInt8(ascii: ".")), !digits() { return nil }
            if accept(UInt8(ascii: "e"), UInt8(ascii: "E")) {
                _ = accept(UInt8(ascii: "+"), UInt8(ascii: "-"))
                guard digits() else { return nil }
            }
            return index > start ? .number : nil
        }

        mutating func string() -> String? {
            guard bytes[index] == UInt8(ascii: "\"") else { return nil }
            index += 1
            var out: [UInt8] = []
            while index < bytes.count {
                let c = bytes[index]
                index += 1
                if c == UInt8(ascii: "\"") { return String(bytes: out, encoding: .utf8) }
                if c < 0x20 { return nil }
                if c == UInt8(ascii: "\\") {
                    guard let escaped = escape() else { return nil }
                    out.append(contentsOf: escaped)
                } else {
                    out.append(c)
                }
            }
            return nil
        }

        /// The bytes of the escape sequence after a backslash.
        mutating func escape() -> [UInt8]? {
            guard index < bytes.count else { return nil }
            let e = bytes[index]
            index += 1
            let simple: [UInt8: UInt8] = [
                UInt8(ascii: "\""): 0x22, UInt8(ascii: "\\"): 0x5C, UInt8(ascii: "/"): 0x2F, UInt8(ascii: "b"): 0x08,
                UInt8(ascii: "f"): 0x0C, UInt8(ascii: "n"): 0x0A, UInt8(ascii: "r"): 0x0D, UInt8(ascii: "t"): 0x09,
            ]
            if let byte = simple[e] { return [byte] }
            guard e == UInt8(ascii: "u"), let scalar = unicodeEscape() else { return nil }
            return Array(String(Character(scalar)).utf8)
        }

        /// The scalar of a `\uXXXX` escape (the `\u` is consumed), joining a surrogate pair.
        mutating func unicodeEscape() -> Unicode.Scalar? {
            guard var unit = hex4() else { return nil }
            if (0xDC00..<0xE000).contains(unit) { return nil }
            if (0xD800..<0xDC00).contains(unit) {
                guard index + 1 < bytes.count, bytes[index] == UInt8(ascii: "\\"), bytes[index + 1] == UInt8(ascii: "u") else { return nil }
                index += 2
                guard let low = hex4(), (0xDC00..<0xE000).contains(low) else { return nil }
                unit = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)
            }
            return Unicode.Scalar(unit)
        }

        mutating func hex4() -> UInt32? {
            guard index + 4 <= bytes.count else { return nil }
            var value: UInt32 = 0
            for _ in 0..<4 {
                let c = bytes[index]
                index += 1
                let digit: UInt32
                switch c {
                case 0x30...0x39: digit = UInt32(c - 0x30)
                case 0x41...0x46: digit = UInt32(c - 0x41 + 10)
                case 0x61...0x66: digit = UInt32(c - 0x61 + 10)
                default: return nil
                }
                value = value << 4 | digit
            }
            return value
        }

        mutating func array(depth: Int) -> RawJSON? {
            index += 1
            var out: [RawJSON] = []
            skipSpace()
            if index < bytes.count, bytes[index] == UInt8(ascii: "]") { index += 1; return .array(out) }
            while true {
                guard let item = value(depth: depth + 1) else { return nil }
                out.append(item)
                skipSpace()
                guard index < bytes.count else { return nil }
                if bytes[index] == UInt8(ascii: ",") { index += 1; continue }
                if bytes[index] == UInt8(ascii: "]") { index += 1; return .array(out) }
                return nil
            }
        }

        mutating func object(depth: Int) -> RawJSON? {
            index += 1
            var out: [(String, RawJSON)] = []
            skipSpace()
            if index < bytes.count, bytes[index] == UInt8(ascii: "}") { index += 1; return .object(out) }
            while true {
                skipSpace()
                guard index < bytes.count, let key = string() else { return nil }
                skipSpace()
                guard index < bytes.count, bytes[index] == UInt8(ascii: ":") else { return nil }
                index += 1
                guard let item = value(depth: depth + 1) else { return nil }
                out.append((key, item))
                skipSpace()
                guard index < bytes.count else { return nil }
                if bytes[index] == UInt8(ascii: ",") { index += 1; continue }
                if bytes[index] == UInt8(ascii: "}") { index += 1; return .object(out) }
                return nil
            }
        }
    }
}

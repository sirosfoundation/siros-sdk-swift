// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// A deliberately small JSON Schema (draft 2020-12) validator for EC TS12
/// transaction-data payloads.
///
/// It implements the keywords the TS12 schemas use and fails CLOSED on
/// anything else: a schema using a keyword this validator does not implement
/// is reported as `.unsupported`, never silently treated as satisfied, because
/// a skipped constraint would let a payload through that the attestation
/// provider meant to forbid.
///
/// `format` is an annotation, as 2020-12 specifies by default, and is not
/// asserted. References are resolved only through the supplied resolver
/// (local `#/...` pointers and the built-in schema registry); network
/// references are never followed from here.
public struct JSONSchemaValidator: Sendable {
    public enum Outcome: Equatable, Sendable {
        case valid
        /// The payload violates the schema; `path` locates the violation.
        case invalid(path: String, reason: String)
        /// The schema itself uses something this validator cannot evaluate.
        case unsupported(String)
    }

    /// Resolves a non-local `$ref` (for example the file name the TS12
    /// e-mandate schema uses for the payment schema). `nil` = unresolvable.
    public typealias RefResolver = @Sendable (String) -> JSONValue?

    private static let annotationKeywords: Set<String> = [
        "$schema", "$id", "$comment", "title", "description", "examples", "default",
        "format", "$defs", "definitions", "deprecated", "readOnly", "writeOnly",
    ]
    private static let maxDepth = 64

    private let resolveRef: RefResolver

    public init(resolveRef: @escaping RefResolver = { _ in nil }) {
        self.resolveRef = resolveRef
    }

    /// Schema evaluations allowed for one `validate` call. A recursive schema
    /// whose branches reference each other can otherwise do exponential work
    /// well inside the depth limit.
    static let evaluationBudget = 20_000

    private final class Budget {
        var remaining = JSONSchemaValidator.evaluationBudget
    }

    public func validate(_ instance: JSONValue, against schema: JSONValue) -> Outcome {
        validate(instance, schema, root: schema, path: "", depth: 0, budget: Budget())
    }

    private func validate(_ instance: JSONValue, _ schema: JSONValue, root: JSONValue, path: String, depth: Int, budget: Budget) -> Outcome {
        budget.remaining -= 1
        guard budget.remaining >= 0 else { return .unsupported("schema evaluation budget exceeded") }
        guard depth <= Self.maxDepth else { return .unsupported("schema nesting or reference depth exceeded") }
        switch schema {
        case .bool(let allowed):
            return allowed ? .valid : .invalid(path: path, reason: "schema is false")
        case .object(let keywords):
            return validateObjectSchema(instance, keywords, root: root, path: path, depth: depth, budget: budget)
        default:
            return .unsupported("a schema must be an object or boolean")
        }
    }

    private func validateObjectSchema(
        _ instance: JSONValue, _ kw: [String: JSONValue], root: JSONValue, path: String, depth: Int, budget: Budget
    ) -> Outcome {
        let known: Set<String> = [
            "type", "properties", "required", "additionalProperties", "items", "minItems", "maxItems",
            "enum", "const", "minLength", "maxLength", "pattern", "minimum", "maximum",
            "exclusiveMinimum", "exclusiveMaximum", "$ref", "allOf", "anyOf", "oneOf", "not",
        ]
        for key in kw.keys where !known.contains(key) && !Self.annotationKeywords.contains(key) {
            return .unsupported("unsupported schema keyword '\(key)'")
        }
        var result: Outcome = .valid
        func check(_ outcome: Outcome) -> Bool {
            if outcome != .valid { result = outcome; return false }
            return true
        }

        if let ref = kw["$ref"] {
            guard let target = resolve(ref, root: root) else { return .unsupported("unresolvable $ref") }
            guard check(validate(instance, target.schema, root: target.root, path: path, depth: depth + 1, budget: budget)) else { return result }
        }
        if let type = kw["type"] {
            guard check(checkType(instance, type, path: path)) else { return result }
        }
        if let e = kw["enum"] {
            guard let options = e.arrayValue else { return .unsupported("enum must be an array") }
            if !options.contains(where: { $0.jsonEquals(instance) }) {
                return .invalid(path: path, reason: "not one of the allowed values")
            }
        }
        if let c = kw["const"], !c.jsonEquals(instance) {
            return .invalid(path: path, reason: "does not equal the required constant")
        }
        guard check(checkString(instance, kw, path: path)) else { return result }
        guard check(checkNumber(instance, kw, path: path)) else { return result }
        guard check(checkObject(instance, kw, root: root, path: path, depth: depth, budget: budget)) else { return result }
        guard check(checkArray(instance, kw, root: root, path: path, depth: depth, budget: budget)) else { return result }
        guard check(checkCombinators(instance, kw, root: root, path: path, depth: depth, budget: budget)) else { return result }
        return .valid
    }

    private func resolve(_ ref: JSONValue, root: JSONValue) -> (schema: JSONValue, root: JSONValue)? {
        guard let r = ref.stringValue else { return nil }
        if r == "#" { return (root, root) }
        if r.hasPrefix("#/") {
            var node = root
            for raw in r.dropFirst(2).split(separator: "/", omittingEmptySubsequences: false) {
                let token = String(raw).replacingOccurrences(of: "~1", with: "/").replacingOccurrences(of: "~0", with: "~")
                guard let next = node[token] else { return nil }
                node = next
            }
            return (node, root)
        }
        // Only a bare file name reaches the resolver: anything with a scheme, a
        // host (`//host/...`) or a path never does, so no reference can name a
        // network location from here.
        guard r.range(of: "^[A-Za-z0-9._-]+$", options: .regularExpression) != nil,
              let external = resolveRef(r) else { return nil }
        return (external, external)
    }

    private func checkType(_ instance: JSONValue, _ type: JSONValue, path: String) -> Outcome {
        let names: [String]
        if let s = type.stringValue { names = [s] }
        else if let a = type.arrayValue, a.allSatisfy({ $0.stringValue != nil }) { names = a.compactMap(\.stringValue) }
        else { return .unsupported("type must be a string or array of strings") }
        let known: Set<String> = ["null", "boolean", "object", "array", "number", "integer", "string"]
        guard names.allSatisfy(known.contains) else { return .unsupported("unknown type name") }
        if names.contains(where: { matches(instance, $0) }) { return .valid }
        return .invalid(path: path, reason: "expected type \(names.joined(separator: " or "))")
    }

    private func matches(_ v: JSONValue, _ name: String) -> Bool {
        switch (name, v) {
        case ("null", .null), ("boolean", .bool), ("object", .object), ("array", .array), ("string", .string): return true
        case ("number", _): return v.isNumber
        case ("integer", _): return v.isIntegral
        default: return false
        }
    }

    private func checkString(_ instance: JSONValue, _ kw: [String: JSONValue], path: String) -> Outcome {
        guard case .string(let s) = instance else { return .valid }
        let length = s.unicodeScalars.count
        if let m = kw["minLength"] {
            guard case .int(let n) = m else { return .unsupported("minLength must be an integer") }
            if Int64(length) < n { return .invalid(path: path, reason: "shorter than minLength") }
        }
        if let m = kw["maxLength"] {
            guard case .int(let n) = m else { return .unsupported("maxLength must be an integer") }
            if Int64(length) > n { return .invalid(path: path, reason: "longer than maxLength") }
        }
        if let p = kw["pattern"] {
            guard let pattern = p.stringValue, RegexSafety.isSafe(pattern),
                  let regex = try? NSRegularExpression(pattern: pattern) else {
                return .unsupported("pattern is not a usable, bounded regular expression")
            }
            // A bounded input too: matching cost grows with the string.
            guard s.utf8.count <= RegexSafety.maxInputBytes else { return .invalid(path: path, reason: "too long to match a pattern") }
            let range = NSRange(s.startIndex..., in: s)
            if regex.firstMatch(in: s, range: range) == nil { return .invalid(path: path, reason: "does not match pattern") }
        }
        return .valid
    }

    private func checkNumber(_ instance: JSONValue, _ kw: [String: JSONValue], path: String) -> Outcome {
        guard instance.isNumber else { return .valid }
        let violations: [(String, (ComparisonResult) -> Bool)] = [
            ("minimum", { $0 == .orderedAscending }), ("maximum", { $0 == .orderedDescending }),
            ("exclusiveMinimum", { $0 != .orderedDescending }), ("exclusiveMaximum", { $0 != .orderedAscending }),
        ]
        for (key, violated) in violations {
            guard let limit = kw[key] else { continue }
            guard limit.isNumber else { return .unsupported("\(key) must be a number") }
            // Not comparable exactly: fail closed rather than let it through.
            guard let order = JSONValue.compareNumbers(instance, limit) else { return .invalid(path: path, reason: "cannot be compared with \(key)") }
            if violated(order) { return .invalid(path: path, reason: "violates \(key)") }
        }
        return .valid
    }

    private func checkObject(_ instance: JSONValue, _ kw: [String: JSONValue], root: JSONValue, path: String, depth: Int, budget: Budget) -> Outcome {
        guard case .object(let members) = instance else { return .valid }
        if let req = kw["required"] {
            guard let names = req.arrayValue, names.allSatisfy({ $0.stringValue != nil }) else {
                return .unsupported("required must be an array of strings")
            }
            for name in names.compactMap(\.stringValue) where members[name] == nil {
                return .invalid(path: path, reason: "missing required member '\(name)'")
            }
        }
        var properties: [String: JSONValue] = [:]
        if let p = kw["properties"] {
            guard let obj = p.objectValue else { return .unsupported("properties must be an object") }
            properties = obj
        }
        for (name, sub) in properties {
            guard let value = members[name] else { continue }
            let outcome = validate(value, sub, root: root, path: path + "." + name, depth: depth + 1, budget: budget)
            if outcome != .valid { return outcome }
        }
        if let ap = kw["additionalProperties"] {
            for (name, value) in members where properties[name] == nil {
                switch ap {
                case .bool(false): return .invalid(path: path + "." + name, reason: "additional member not allowed")
                case .bool(true): continue
                default:
                    let outcome = validate(value, ap, root: root, path: path + "." + name, depth: depth + 1, budget: budget)
                    if outcome != .valid { return outcome }
                }
            }
        }
        return .valid
    }

    private func checkArray(_ instance: JSONValue, _ kw: [String: JSONValue], root: JSONValue, path: String, depth: Int, budget: Budget) -> Outcome {
        guard case .array(let items) = instance else { return .valid }
        if let m = kw["minItems"] {
            guard case .int(let n) = m else { return .unsupported("minItems must be an integer") }
            if Int64(items.count) < n { return .invalid(path: path, reason: "fewer than minItems") }
        }
        if let m = kw["maxItems"] {
            guard case .int(let n) = m else { return .unsupported("maxItems must be an integer") }
            if Int64(items.count) > n { return .invalid(path: path, reason: "more than maxItems") }
        }
        if let itemSchema = kw["items"] {
            for (index, item) in items.enumerated() {
                let outcome = validate(item, itemSchema, root: root, path: path + "[\(index)]", depth: depth + 1, budget: budget)
                if outcome != .valid { return outcome }
            }
        }
        return .valid
    }

    private func checkCombinators(_ instance: JSONValue, _ kw: [String: JSONValue], root: JSONValue, path: String, depth: Int, budget: Budget) -> Outcome {
        func subschemas(_ key: String) -> [JSONValue]? {
            guard let v = kw[key] else { return [] }
            return v.arrayValue
        }
        guard let all = subschemas("allOf"), let any = subschemas("anyOf"), let one = subschemas("oneOf") else {
            return .unsupported("allOf/anyOf/oneOf must be arrays")
        }
        for sub in all {
            let outcome = validate(instance, sub, root: root, path: path, depth: depth + 1, budget: budget)
            if outcome != .valid { return outcome }
        }
        if kw["anyOf"] != nil {
            var firstUnsupported: Outcome?
            var matched = false
            for sub in any {
                let outcome = validate(instance, sub, root: root, path: path, depth: depth + 1, budget: budget)
                if outcome == .valid { matched = true; break }
                if case .unsupported = outcome, firstUnsupported == nil { firstUnsupported = outcome }
            }
            if !matched { return firstUnsupported ?? .invalid(path: path, reason: "matches none of anyOf") }
        }
        if kw["oneOf"] != nil {
            var count = 0
            for sub in one {
                let outcome = validate(instance, sub, root: root, path: path, depth: depth + 1, budget: budget)
                if case .unsupported = outcome { return outcome }
                if outcome == .valid { count += 1 }
            }
            if count != 1 { return .invalid(path: path, reason: "does not match exactly one of oneOf") }
        }
        if let not = kw["not"] {
            let outcome = validate(instance, not, root: root, path: path, depth: depth + 1, budget: budget)
            if case .unsupported = outcome { return outcome }
            if outcome == .valid { return .invalid(path: path, reason: "matches a schema it must not match") }
        }
        return .valid
    }
}

/// A conservative gate on schema `pattern`s, which come from an issuer-controlled
/// document and run on the wallet. `NSRegularExpression` has no time limit, so
/// patterns that can backtrack catastrophically are refused rather than run:
/// a quantified group whose body itself contains a quantifier or an
/// alternation (`(a+)+`, `(a|aa)*`), back-references, lookaround, and
/// over-long patterns. Plain classes, anchors and bounded repeats pass.
enum RegexSafety {
    static let maxPatternLength = 256
    static let maxInputBytes = 4096

    static func isSafe(_ pattern: String) -> Bool {
        guard pattern.utf8.count <= maxPatternLength else { return false }
        let chars = Array(pattern)
        // Back-references and lookaround are refused outright.
        if pattern.contains("(?=") || pattern.contains("(?!") || pattern.contains("(?<=") || pattern.contains("(?<!") { return false }
        var i = 0
        var stack: [Int] = []          // start indices of open groups
        var escaped = false
        var inClass = false
        func isQuantifier(at index: Int) -> Bool {
            guard index < chars.count else { return false }
            switch chars[index] {
            case "+", "*": return true
            case "{":
                // {n,} or {n,m} with m > 1 repeats; {n} / {0,1} is bounded and harmless.
                guard let close = chars[index...].firstIndex(of: "}") else { return false }
                let body = String(chars[(index + 1)..<close])
                if body.contains(",") {
                    let upper = body.split(separator: ",", omittingEmptySubsequences: false).last.map(String.init) ?? ""
                    return upper.isEmpty || (Int(upper) ?? 2) > 1
                }
                return (Int(body) ?? 2) > 1
            default: return false
            }
        }
        while i < chars.count {
            let c = chars[i]
            if escaped {
                if c.isNumber && c != "0" { return false }   // back-reference
                escaped = false
            } else if c == "\\" {
                escaped = true
            } else if inClass {
                if c == "]" { inClass = false }
            } else if c == "[" {
                inClass = true
            } else if c == "(" {
                stack.append(i)
            } else if c == ")" {
                guard let start = stack.popLast() else { return false }
                if isQuantifier(at: i + 1) {
                    let body = chars[(start + 1)..<i]
                    var bodyEscaped = false
                    var bodyInClass = false
                    for (offset, b) in body.enumerated() {
                        let position = start + 1 + offset
                        if bodyEscaped { bodyEscaped = false; continue }
                        if b == "\\" { bodyEscaped = true; continue }
                        if bodyInClass { if b == "]" { bodyInClass = false }; continue }
                        if b == "[" { bodyInClass = true; continue }
                        if b == "|" || b == "(" || isQuantifier(at: position) { return false }
                    }
                }
            }
            i += 1
        }
        return stack.isEmpty
    }
}

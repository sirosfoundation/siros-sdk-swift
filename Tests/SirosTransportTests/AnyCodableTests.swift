// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosTransport

final class AnyCodableTests: XCTestCase {
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    func testStringRoundTrip() throws {
        let value: AnyCodable = "hello"
        let data = try encoder.encode(value)
        let decoded = try decoder.decode(AnyCodable.self, from: data)
        XCTAssertEqual(decoded, .string("hello"))
        XCTAssertEqual(decoded.stringValue, "hello")
    }

    func testIntRoundTrip() throws {
        let value: AnyCodable = 42
        let data = try encoder.encode(value)
        let decoded = try decoder.decode(AnyCodable.self, from: data)
        XCTAssertEqual(decoded, .int(42))
        XCTAssertEqual(decoded.intValue, 42)
    }

    func testBoolRoundTrip() throws {
        let value: AnyCodable = true
        let data = try encoder.encode(value)
        let decoded = try decoder.decode(AnyCodable.self, from: data)
        XCTAssertEqual(decoded, .bool(true))
        XCTAssertEqual(decoded.boolValue, true)
    }

    func testNullRoundTrip() throws {
        let value: AnyCodable = nil
        let data = try encoder.encode(value)
        let decoded = try decoder.decode(AnyCodable.self, from: data)
        XCTAssertEqual(decoded, .null_)
    }

    func testObjectRoundTrip() throws {
        let value: AnyCodable = ["key": "value", "num": 42]
        let data = try encoder.encode(value)
        let decoded = try decoder.decode(AnyCodable.self, from: data)
        XCTAssertEqual(decoded.objectValue?["key"]?.stringValue, "value")
        XCTAssertEqual(decoded.objectValue?["num"]?.intValue, 42)
    }

    func testArrayRoundTrip() throws {
        let value: AnyCodable = ["a", "b", "c"]
        let data = try encoder.encode(value)
        let decoded = try decoder.decode(AnyCodable.self, from: data)
        XCTAssertEqual(decoded.arrayValue?.count, 3)
    }

    func testNestedJsonDecoding() throws {
        let json = """
        {"wmp":{"version":"0.1","session_id":"ses-123"},"ttl":3600,"auth":{"type":"bearer","token":"tok"}}
        """
        let decoded = try decoder.decode([String: AnyCodable].self, from: json.data(using: .utf8)!)
        XCTAssertEqual(decoded["ttl"]?.intValue, 3600)
        XCTAssertEqual(decoded["wmp"]?.objectValue?["version"]?.stringValue, "0.1")
        XCTAssertEqual(decoded["auth"]?.objectValue?["token"]?.stringValue, "tok")
    }
}

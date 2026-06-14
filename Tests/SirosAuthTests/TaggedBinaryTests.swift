// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosAuth

final class TaggedBinaryTests: XCTestCase {

    func testDecodeUnwrapsTaggedBinaryRecursively() {
        let input: [String: Any] = [
            "outer": ["$b64u": "YWJj"],
            "arr": [
                ["$b64u": "ZGVm"],
                ["nested": ["$b64u": "Z2hp"]],
            ],
            "plain": "hello",
        ]
        let decoded = TaggedBinary.decode(input)
        XCTAssertEqual(decoded["outer"] as? String, "YWJj")
        XCTAssertEqual(decoded["plain"] as? String, "hello")

        let arr = decoded["arr"] as? [Any]
        XCTAssertNotNil(arr)
        XCTAssertEqual(arr?[0] as? String, "ZGVm")
        if let nested = arr?[1] as? [String: Any] {
            XCTAssertEqual(nested["nested"] as? String, "Z2hp")
        } else {
            XCTFail("Expected nested dict")
        }
    }

    func testDecodePassesThroughNonTaggedObjects() {
        let input: [String: Any] = [
            "key1": "value1",
            "key2": 42,
            "key3": ["a", "b"],
        ]
        let decoded = TaggedBinary.decode(input)
        XCTAssertEqual(decoded["key1"] as? String, "value1")
        XCTAssertEqual(decoded["key2"] as? Int, 42)
    }

    func testExtractBase64UrlFromPlainString() {
        let result = TaggedBinary.extractBase64Url("dGVzdA")
        XCTAssertEqual(result, "dGVzdA")
    }

    func testExtractBase64UrlFromTaggedObject() {
        let tagged: [String: Any] = ["$b64u": "dGVzdA"]
        let result = TaggedBinary.extractBase64Url(tagged)
        XCTAssertEqual(result, "dGVzdA")
    }

    func testExtractBase64UrlReturnsNilForInvalid() {
        let result = TaggedBinary.extractBase64Url(42)
        XCTAssertNil(result)
    }
}

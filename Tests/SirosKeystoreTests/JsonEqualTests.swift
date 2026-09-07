// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import XCTest

/// `ContainerTestSupport.jsonEqual` is what the container round-trip tests
/// trust to say "byte-for-byte the same"; if it is too lenient, those tests
/// prove nothing. The case that matters is the one `JSONSerialization`
/// makes easy to get wrong: it hands back both numbers and booleans as
/// `NSNumber`, whose `==` says `true == 1`.
final class JsonEqualTests: XCTestCase {

    private func parse(_ json: String) throws -> Any {
        try JSONSerialization.jsonObject(with: Data(json.utf8), options: [.fragmentsAllowed])
    }

    func testABooleanIsNotEqualToTheNumberItWouldCoerceTo() throws {
        XCTAssertFalse(ContainerTestSupport.jsonEqual(try parse("true"), try parse("1")))
        XCTAssertFalse(ContainerTestSupport.jsonEqual(try parse("1"), try parse("true")))
        XCTAssertFalse(ContainerTestSupport.jsonEqual(try parse("false"), try parse("0")))
        XCTAssertFalse(ContainerTestSupport.jsonEqual(try parse("0"), try parse("false")))
    }

    func testEqualBooleansAndEqualNumbersStillCompareEqual() throws {
        XCTAssertTrue(ContainerTestSupport.jsonEqual(try parse("true"), try parse("true")))
        XCTAssertTrue(ContainerTestSupport.jsonEqual(try parse("false"), try parse("false")))
        XCTAssertTrue(ContainerTestSupport.jsonEqual(try parse("1"), try parse("1")))
        XCTAssertTrue(ContainerTestSupport.jsonEqual(try parse("1.5"), try parse("1.5")))
        XCTAssertFalse(ContainerTestSupport.jsonEqual(try parse("1"), try parse("2")))
        XCTAssertFalse(ContainerTestSupport.jsonEqual(try parse("true"), try parse("false")))
    }

    /// The same distinction has to hold when the values are nested, since
    /// that is where the round-trip tests meet them.
    func testTheDistinctionHoldsInsideObjectsAndArrays() throws {
        let withBoolean = try parse(#"{"flag": true, "list": [1, false, null, "x"]}"#)
        let sameShape = try parse(#"{"flag": true, "list": [1, false, null, "x"]}"#)
        let retyped = try parse(#"{"flag": 1, "list": [1, false, null, "x"]}"#)
        let retypedInList = try parse(#"{"flag": true, "list": [1, 0, null, "x"]}"#)

        XCTAssertTrue(ContainerTestSupport.jsonEqual(withBoolean, sameShape))
        XCTAssertFalse(ContainerTestSupport.jsonEqual(withBoolean, retyped))
        XCTAssertFalse(ContainerTestSupport.jsonEqual(withBoolean, retypedInList))
    }

    func testTheOtherLeafTypesBehave() throws {
        XCTAssertTrue(ContainerTestSupport.jsonEqual(nil, nil))
        XCTAssertFalse(ContainerTestSupport.jsonEqual(nil, try parse("null")))
        XCTAssertTrue(ContainerTestSupport.jsonEqual(try parse("null"), try parse("null")))
        XCTAssertTrue(ContainerTestSupport.jsonEqual(try parse(#""a""#), try parse(#""a""#)))
        XCTAssertFalse(ContainerTestSupport.jsonEqual(try parse(#""1""#), try parse("1")))
        XCTAssertFalse(ContainerTestSupport.jsonEqual(try parse(#"{"a": 1}"#), try parse(#"{"a": 1, "b": 2}"#)))
        XCTAssertFalse(ContainerTestSupport.jsonEqual(try parse("[1, 2]"), try parse("[2, 1]")))
    }
}

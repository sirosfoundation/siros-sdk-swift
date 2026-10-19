// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosTransport

final class SseEventParserTests: XCTestCase {

    private func events(_ text: String) -> [SseEvent] {
        var splitter = SseLineSplitter()
        var parser = SseEventParser()
        var out: [SseEvent] = []
        for byte in Array(text.utf8) {
            if let line = splitter.feed(byte: byte), let event = parser.feed(line: line) { out.append(event) }
        }
        return out
    }

    func testBlankLinesAreKeptSoEventsDispatch() {
        let out = events("id: 7\ndata: {\"a\":1}\n\ndata: x\ndata: y\n\n")
        XCTAssertEqual(out, [SseEvent(id: "7", event: nil, data: "{\"a\":1}"), SseEvent(id: nil, event: nil, data: "x\ny")])
    }

    func testCRLFAndLoneCRTerminators() {
        XCTAssertEqual(events("id:1\r\ndata:a\r\n\r\n").map(\.data), ["a"])
        XCTAssertEqual(events("data:a\r\r").map(\.data), ["a"])
    }

    func testCommentsAndUnknownFieldsAreIgnoredAndOneLeadingSpaceIsStripped() {
        let out = events(": keep-alive\nretry: 100\nfoo: bar\nevent: wmp\ndata:  two spaces\n\n")
        XCTAssertEqual(out, [SseEvent(id: nil, event: "wmp", data: " two spaces")])
    }

    func testAnEventWithoutDataIsNotDispatchedButItsIdIsRemembered() {
        var parser = SseEventParser()
        XCTAssertNil(parser.feed(line: "id: 9"))
        XCTAssertNil(parser.feed(line: ""))
        XCTAssertEqual(parser.lastEventId, "9")
    }

    func testLastEventIdPersistsAcrossEventsWithoutAnId() {
        var parser = SseEventParser()
        _ = parser.feed(line: "id: 3"); _ = parser.feed(line: "data: a"); _ = parser.feed(line: "")
        _ = parser.feed(line: "data: b")
        let second = parser.feed(line: "")
        XCTAssertNil(second?.id)
        XCTAssertEqual(parser.lastEventId, "3", "an event without an id does not reset the stream's last id")
    }

    func testAnIdWithNulIsIgnored() {
        var parser = SseEventParser()
        _ = parser.feed(line: "id: a\u{0}b")
        XCTAssertNil(parser.lastEventId)
    }

    func testReplayFilterDropsAReplayedIdAndNeverEventsWithoutOne() {
        var filter = SseReplayFilter()
        let a = SseEvent(id: "1", event: nil, data: "x")
        XCTAssertTrue(filter.admit(a))
        XCTAssertFalse(filter.admit(a), "the same id replayed after a resume is dropped")
        let anonymous = SseEvent(id: nil, event: nil, data: "x")
        XCTAssertTrue(filter.admit(anonymous))
        XCTAssertTrue(filter.admit(anonymous))
    }

    func testReplayFilterForgetsTheOldestPastItsCapacity() {
        var filter = SseReplayFilter(capacity: 2)
        for id in ["1", "2", "3"] { XCTAssertTrue(filter.admit(SseEvent(id: id, event: nil, data: "d"))) }
        XCTAssertTrue(filter.admit(SseEvent(id: "1", event: nil, data: "d")), "1 fell out of the window")
        XCTAssertFalse(filter.admit(SseEvent(id: "3", event: nil, data: "d")))
    }

    func testTheEventDoesNotPrintItsData() {
        let event = SseEvent(id: "1", event: nil, data: "SECRET-SEED")
        var dumped = ""
        dump(event, to: &dumped)
        for text in ["\(event)", String(reflecting: event), dumped] { XCTAssertFalse(text.contains("SECRET-SEED"), text) }
    }
}

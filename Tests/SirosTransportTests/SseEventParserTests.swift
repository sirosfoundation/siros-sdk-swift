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
        _ = parser.feed(line: "data: x")
        let event = parser.feed(line: "")   // the blank line commits the block: only then could an accepted id show
        XCTAssertNil(parser.lastEventId)
        XCTAssertNil(event?.id)
        XCTAssertEqual(event?.data, "x")
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

    // Copilot review.
    func testAnUnfinishedBlockDoesNotAdvanceTheResumeCursor() {
        var parser = SseEventParser()
        _ = parser.feed(line: "id: 7"); _ = parser.feed(line: "data: a"); _ = parser.feed(line: "")
        _ = parser.feed(line: "id: 8")           // the connection drops before the blank line
        XCTAssertEqual(parser.lastEventId, "7", "event 8 was never delivered; a resume must ask for what follows 7")
        _ = parser.feed(line: "")                // an id-only block commits
        XCTAssertEqual(parser.lastEventId, "8")
    }

    func testAnEmptyIdResetsTheCursorAndIsNeverADedupeKey() {
        var parser = SseEventParser()
        _ = parser.feed(line: "id: 5"); _ = parser.feed(line: "")
        _ = parser.feed(line: "id:"); _ = parser.feed(line: "")
        XCTAssertNil(parser.lastEventId, "an empty id resets the cursor")
        var filter = SseReplayFilter()
        var admitted: [String] = []
        for payload in ["one", "two"] {
            _ = parser.feed(line: "id:"); _ = parser.feed(line: "data: \(payload)")
            if let event = parser.feed(line: ""), filter.admit(event) { admitted.append(event.data) }
        }
        XCTAssertEqual(admitted, ["one", "two"], "two different payloads with empty ids are both delivered")
    }

    func testOneLeadingByteOrderMarkIsIgnoredAtTheStartOfTheResponseOnly() {
        var dataFirst = SseEventParser()
        XCTAssertNil(dataFirst.feed(line: "\u{FEFF}data: a"))
        XCTAssertEqual(dataFirst.feed(line: "")?.data, "a")
        var idFirst = SseEventParser()
        _ = idFirst.feed(line: "\u{FEFF}id: 4"); _ = idFirst.feed(line: "data: b")
        XCTAssertEqual(idFirst.feed(line: "")?.id, "4")
        // later BOMs are preserved: that line is an unknown field and is ignored
        var later = SseEventParser()
        _ = later.feed(line: "data: c"); _ = later.feed(line: "\u{FEFF}data: d")
        XCTAssertEqual(later.feed(line: "")?.data, "c")
        // each response expects its own BOM
        var next = SseEventParser()
        _ = next.feed(line: "data: x"); _ = next.feed(line: "")
        next.beginResponse()
        _ = next.feed(line: "\u{FEFF}data: y")
        XCTAssertEqual(next.feed(line: "")?.data, "y")
    }

    func testADisconnectMidEventDoesNotLeakIntoTheNextResponse() {
        var parser = SseEventParser()
        _ = parser.feed(line: "id: 1"); _ = parser.feed(line: "data: {\"a\":1}")   // the response ends here
        parser.beginResponse()
        _ = parser.feed(line: "data: {\"b\":2}")
        let event = parser.feed(line: "")
        XCTAssertEqual(event?.data, "{\"b\":2}")
        XCTAssertNil(event?.id, "the unfinished block's id is discarded with it")
        XCTAssertNil(parser.lastEventId)
        // the committed cursor survives a new response
        var committed = SseEventParser()
        _ = committed.feed(line: "id: 9"); _ = committed.feed(line: "data: z"); _ = committed.feed(line: "")
        committed.beginResponse()
        XCTAssertEqual(committed.lastEventId, "9")
    }

    func testTheEventDoesNotPrintItsData() {
        let event = SseEvent(id: "1", event: nil, data: "SECRET-SEED")
        var dumped = ""
        dump(event, to: &dumped)
        for text in ["\(event)", String(reflecting: event), dumped] { XCTAssertFalse(text.contains("SECRET-SEED"), text) }
    }
}

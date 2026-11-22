// Copyright 2026 SIROS Foundation. BSD-2-Clause License.

import XCTest
@testable import SirosWallet

/// The message store contract (issue #77): every implementation — the
/// `InMemoryWmpMessageStore`, the app's own persistence, the eventual
/// privatedata library's — answers this shape. The cursors persist (a
/// restart resumes the read's place, not the top).
///
/// Kotlin parity: `WmpMessageStoreTest` (the same six cases).
final class WmpMessageStoreTests: XCTestCase {

    private func message(_ text: String, id: String? = nil) -> WmpGroupMessage {
        WmpGroupMessage(
            backend: "engine",
            sessionId: "ses-1",
            from: "ses-peer",
            text: text,
            messageId: id
        )
    }

    private func stores() -> [InMemoryWmpMessageStore] {
        [InMemoryWmpMessageStore()]
    }

    func testAppendAndLoadNewestFirst() {
        for store in stores() {
            store.append(message("first", id: "m1"))
            store.append(message("second", id: "m2"))
            let loaded = store.load(backend: "engine", sessionId: "ses-1", limit: 50)
            XCTAssertEqual(loaded.first?.text, "second", "newest first")
            XCTAssertEqual(loaded.count, 2, "holds both")
        }
    }

    func testAppendIsIdempotentById() {
        for store in stores() {
            store.append(message("hello", id: "m1"))
            store.append(message("hello", id: "m1"))
            XCTAssertEqual(store.load(backend: "engine", sessionId: "ses-1", limit: 50).count, 1, "deduped")
        }
    }

    func testCursorsRoundTrip() {
        for store in stores() {
            XCTAssertNil(store.cursor(backend: "engine", sessionId: "ses-1"), "empty cursor")
            store.setCursor(backend: "engine", sessionId: "ses-1", since: "m42")
            XCTAssertEqual(store.cursor(backend: "engine", sessionId: "ses-1"), "m42", "the cursor")
        }
    }

    func testPruneKeepsTheNewest() {
        for store in stores() {
            for i in 1...60 {
                store.append(message("m\(i)", id: "id\(i)"))
            }
            store.prune(keep: 50)
            let loaded = store.load(backend: "engine", sessionId: "ses-1", limit: 100)
            XCTAssertEqual(loaded.count, 50, "pruned to 50")
            XCTAssertEqual(loaded.first?.text, "m60", "kept the newest")
        }
    }

    func testClearDropsEverything() {
        for store in stores() {
            store.append(message("gone", id: "m1"))
            store.setCursor(backend: "engine", sessionId: "ses-1", since: "m1")
            store.clear()
            XCTAssertTrue(store.load(backend: "engine", sessionId: "ses-1", limit: 50).isEmpty, "empty")
            XCTAssertNil(store.cursor(backend: "engine", sessionId: "ses-1"), "no cursor")
        }
    }

    func testTheSessionsAreSeparate() {
        for store in stores() {
            store.append(message("engine-one", id: "m1"))
            let other = WmpGroupMessage(
                backend: "engine",
                sessionId: "ses-2",
                from: nil,
                text: "other-session",
                messageId: "m2"
            )
            store.append(other)
            let one = store.load(backend: "engine", sessionId: "ses-1", limit: 50)
            XCTAssertEqual(one.count, 1, "per-session boxes")
            XCTAssertEqual(one.first?.text, "engine-one")
        }
    }
}
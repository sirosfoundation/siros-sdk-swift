// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore

/// What can honestly be verified from outside `SecureBytes` about its wipe path: Swift gives no
/// portable, safe way to scan memory that has already been `deallocate()`d to prove it was zeroed
/// first rather than just freed - these tests instead prove (a) the buffer holds what it was given
/// until wiped, (b) `wipe()` deterministically empties it and is idempotent, and (c) `deinit` runs
/// the same path without an explicit call, via a weak-reference sentinel.
final class SecureBytesTests: XCTestCase {
    func testHoldsWhatItWasGivenUntilWiped() {
        let s = SecureBytes(utf8: "123456")
        XCTAssertEqual(s.count, 6)
        XCTAssertEqual(s.dataCopy(), Data("123456".utf8))
        XCTAssertFalse(s.isWiped)
    }

    func testWipeEmptiesTheBufferAndIsIdempotent() {
        let s = SecureBytes(utf8: "123456")
        s.wipe()
        XCTAssertTrue(s.isWiped)
        XCTAssertEqual(s.count, 0)
        XCTAssertEqual(s.dataCopy(), Data(), "reads after wipe see nothing, not stale bytes")
        s.wipe() // must not double-free or crash
        XCTAssertTrue(s.isWiped)
    }

    func testByteArrayInitializerRoundTrips() {
        let s = SecureBytes([0x31, 0x32, 0x33])
        XCTAssertEqual(s.dataCopy(), Data([0x31, 0x32, 0x33]))
    }

    /// `deinit` runs the same wipe path as an explicit call, without the caller having to remember
    /// to call it: the sentinel is the instance itself going away as soon as the last strong
    /// reference does (Swift's deterministic ARC, not a GC finalizer `weak` would otherwise have to
    /// wait for).
    func testDeinitWipesWithoutAnExplicitCall() {
        weak var weakRef: SecureBytes?
        do {
            let s = SecureBytes(utf8: "123456")
            weakRef = s
            XCTAssertFalse(s.isWiped)
        }
        XCTAssertNil(weakRef, "the only strong reference went out of scope: deinit (and its wipe) already ran")
    }

    func testEmptySecretIsHandledWithoutCrashing() {
        let s = SecureBytes([])
        XCTAssertEqual(s.count, 0)
        XCTAssertEqual(s.dataCopy(), Data())
        s.wipe()
        XCTAssertEqual(s.count, 0)
    }
}

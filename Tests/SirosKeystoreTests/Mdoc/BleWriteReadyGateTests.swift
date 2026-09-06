// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore

/// Exercises the write-readiness hand-off `BleCentralClient` uses to pace
/// `.withoutResponse` GATT writes. Pure Swift concurrency - no CoreBluetooth
/// - so it runs on every platform, including Linux CI. Covers the three
/// hazards the gate exists to close (lost wake-up, unsynchronised
/// hand-off, re-entry) plus the timeout/abort bounds that mirror the Kotlin
/// SDK's `WRITE_ACK_TIMEOUT_MS` semantics.
final class BleWriteReadyGateTests: XCTestCase {

    private static let longTimeoutMs: UInt64 = 5_000

    func testReturnsReadyImmediatelyWhenAlreadyReady() async {
        let gate = BleWriteReadyGate()
        let outcome = await gate.wait(timeoutMs: Self.longTimeoutMs) { true }
        XCTAssertEqual(outcome, .ready)
    }

    func testResumesWithReadyWhenSignalled() async {
        let gate = BleWriteReadyGate()
        let waiter = Task { await gate.wait(timeoutMs: Self.longTimeoutMs) { false } }
        try? await Task.sleep(nanoseconds: 50_000_000)
        gate.signalReady()
        let outcome = await waiter.value
        XCTAssertEqual(outcome, .ready)
    }

    func testTimesOutWhenNeverSignalled() async {
        let gate = BleWriteReadyGate()
        let started = Date()
        let outcome = await gate.wait(timeoutMs: 100) { false }
        XCTAssertEqual(outcome, .timedOut)
        XCTAssertGreaterThanOrEqual(Date().timeIntervalSince(started), 0.09)
    }

    /// The lost-wake-up window: readiness flips true between the unlocked
    /// pre-check and the continuation being stored - i.e. the
    /// `peripheralIsReady` callback fired and found nobody to resume. The
    /// gate must observe that on its post-registration re-check instead of
    /// waiting (and here, timing out) for a signal that has already gone by.
    func testReadinessFlippingDuringRegistrationIsNotMissed() async {
        let gate = BleWriteReadyGate()
        var checks = 0
        let started = Date()
        let outcome = await gate.wait(timeoutMs: 200) {
            checks += 1
            return checks >= 2
        }
        XCTAssertEqual(outcome, .ready)
        XCTAssertEqual(checks, 2, "expected exactly one pre-check and one post-registration re-check")
        XCTAssertLessThan(Date().timeIntervalSince(started), 0.15, "must not have waited for the timeout")
    }

    func testAbortResumesCurrentWaiterAndFailsLaterWaitsImmediately() async {
        let gate = BleWriteReadyGate()
        let waiter = Task { await gate.wait(timeoutMs: Self.longTimeoutMs) { false } }
        try? await Task.sleep(nanoseconds: 50_000_000)
        gate.abort()
        let first = await waiter.value
        XCTAssertEqual(first, .aborted)

        // Latched: the connection is gone, so even a peripheral that claims
        // to be ready must not be written to, and nobody waits out a timeout.
        let started = Date()
        let second = await gate.wait(timeoutMs: Self.longTimeoutMs) { true }
        XCTAssertEqual(second, .aborted)
        XCTAssertLessThan(Date().timeIntervalSince(started), 0.5)
    }

    /// A second concurrent waiter must never overwrite (leak) the first's
    /// un-resumed continuation; it is refused, and the first still gets its
    /// signal.
    func testSecondConcurrentWaiterIsRefusedNotLeaked() async {
        let gate = BleWriteReadyGate()
        let first = Task { await gate.wait(timeoutMs: Self.longTimeoutMs) { false } }
        try? await Task.sleep(nanoseconds: 50_000_000)
        let second = await gate.wait(timeoutMs: Self.longTimeoutMs) { false }
        XCTAssertEqual(second, .contended)
        gate.signalReady()
        let firstOutcome = await first.value
        XCTAssertEqual(firstOutcome, .ready)
    }

    /// A timeout armed for an earlier wait that was resolved by a signal
    /// must not fire against a later, unrelated wait - the earlier timer is
    /// cancelled on resume and, belt-and-braces, generation-checked.
    func testStaleTimeoutDoesNotHitLaterWaiter() async {
        let gate = BleWriteReadyGate()
        let first = Task { await gate.wait(timeoutMs: 100) { false } }
        try? await Task.sleep(nanoseconds: 20_000_000)
        gate.signalReady()
        let firstOutcome = await first.value
        XCTAssertEqual(firstOutcome, .ready)

        let second = Task { await gate.wait(timeoutMs: Self.longTimeoutMs) { false } }
        // Well past the first wait's 100 ms deadline.
        try? await Task.sleep(nanoseconds: 300_000_000)
        gate.signalReady()
        let secondOutcome = await second.value
        XCTAssertEqual(secondOutcome, .ready, "first wait's expired timer must not have resumed the second waiter with .timedOut")
    }

    func testSignalWithNoWaiterIsANoOp() async {
        let gate = BleWriteReadyGate()
        gate.signalReady()
        gate.signalReady()
        // A stray early signal must not be "banked": a later not-ready wait
        // still has to observe real readiness (here: time out).
        let outcome = await gate.wait(timeoutMs: 100) { false }
        XCTAssertEqual(outcome, .timedOut)
    }
}

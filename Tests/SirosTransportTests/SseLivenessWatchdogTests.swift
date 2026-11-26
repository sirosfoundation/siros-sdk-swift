// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosTransport

/// #306: the SSE keep-alive — no line for four missed heartbeats (~60 s at
/// the engine's ~15 s cadence; milliseconds here) marks the transport
/// FAILED, which the session's reconnect answers (the collector side is
/// proven in `WmpSessionTests`). The HTTP+SSE transport that drives the
/// clock is Apple-only (URLSession async bytes); the clock itself is the
/// cross-platform twin of the Kotlin binding's SSE read timeout
/// (siros-sdk-kotlin#447) and is tested here directly.
final class SseLivenessWatchdogTests: XCTestCase {

    /// A stream that receives no line within the limit fires ONCE — the
    /// half-open socket case: the kernel still calls the connection
    /// established, no byte flows, no error ever surfaces.
    func testAnIdleStreamFiresOnceAfterTheIdleLimit() async {
        let counter = Count()
        let watchdog = SseLivenessWatchdog(checkInterval: 0.05, idleLimit: 0.2)
        watchdog.onIdle = { Task { await counter.bump() } }
        watchdog.arm()
        XCTAssertTrue(watchdog.isArmed)

        try? await waitFor(within: 2) { await counter.value > 0 }
        let fired = await counter.value
        XCTAssertEqual(fired, 1, "a silent stream trips the watchdog once")
        XCTAssertFalse(watchdog.isArmed, "the watchdog retires itself when it fires: the reconnect's fresh reader re-arms it")

        // It fires ONCE, not per check interval: a few more intervals pass
        // without another fire.
        try? await Task.sleep(nanoseconds: 300_000_000)
        let still = await counter.value
        XCTAssertEqual(still, 1)
    }

    /// A line arriving — heartbeat or data — keeps the stream alive: the
    /// clock never trips while lines flow, whatever their spacing.
    func testALineKeepsTheStreamAlive() async {
        let counter = Count()
        let watchdog = SseLivenessWatchdog(checkInterval: 0.05, idleLimit: 0.2)
        watchdog.onIdle = { Task { await counter.bump() } }
        watchdog.arm()

        // Ten check intervals' worth of heartbeats, each comfortably within
        // the limit: never fires.
        for _ in 0..<10 {
            try? await Task.sleep(nanoseconds: 100_000_000)
            watchdog.noteActivity()
        }
        let fired = await counter.value
        XCTAssertEqual(fired, 0, "a stream with lines never trips the watchdog")
        XCTAssertTrue(watchdog.isArmed, "the clock keeps running for a live stream")
        watchdog.stop()
    }

    /// A stopped clock never fires: each reader stops the clock as it ends,
    /// so a dead reader's silence cannot fail a stopped transport.
    func testAStoppedWatchdogNeverFires() async {
        let counter = Count()
        let watchdog = SseLivenessWatchdog(checkInterval: 0.05, idleLimit: 0.2)
        watchdog.onIdle = { Task { await counter.bump() } }
        watchdog.arm()
        watchdog.stop()
        XCTAssertFalse(watchdog.isArmed)

        try? await Task.sleep(nanoseconds: 400_000_000)
        let fired = await counter.value
        XCTAssertEqual(fired, 0)
    }

    /// A re-armed clock starts over: the stale tick of the previous arming
    /// must not fire on the new reader's silence before ITS limit passes.
    func testARestartedReaderRearmsTheClock() async {
        let counter = Count()
        let watchdog = SseLivenessWatchdog(checkInterval: 0.05, idleLimit: 0.2)
        watchdog.onIdle = { Task { await counter.bump() } }
        watchdog.arm()

        // Half the limit passes, then the reader is replaced: the fresh
        // arming's clock starts from NOW.
        try? await Task.sleep(nanoseconds: 100_000_000)
        watchdog.stop()
        watchdog.arm()
        try? await Task.sleep(nanoseconds: 100_000_000)
        var fired = await counter.value
        XCTAssertEqual(fired, 0, "the fresh arming restarted the clock: the old arming's age does not count")

        // No lines follow: the fresh reader's own limit trips it.
        try? await waitFor(within: 2) { await counter.value > 0 }
        fired = await counter.value
        XCTAssertEqual(fired, 1)
    }

    /// Arming a clock that is already running only freshens it: the running
    /// tick must keep its arming and still be able to fire — bumping its
    /// arming out from under it would strand a tick that ticks forever but
    /// can never fire.
    func testArmingARunningClockOnlyFreshensIt() async {
        let counter = Count()
        // The margins: each stretch sleeps half the idle limit, so a
        // loaded CI runner can oversleep a sleep by 300ms before the
        // freshened clock legitimately trips. The v0.19.0 release run
        // flaked on this test's 80ms margin (0.12s sleeps against a 0.2s
        // limit); 0.3s against 0.6s keeps the guarantee pinned without the
        // flake window.
        let watchdog = SseLivenessWatchdog(checkInterval: 0.05, idleLimit: 0.6)
        watchdog.onIdle = { Task { await counter.bump() } }
        watchdog.arm()

        // More than the limit elapses in TOTAL, but each stretch stays
        // within it: the clock is freshened by the re-arm and never trips.
        for _ in 0..<3 {
            try? await Task.sleep(nanoseconds: 300_000_000)
            watchdog.arm()
        }
        var fired = await counter.value
        XCTAssertEqual(fired, 0, "the freshened clock does not count the stretches before the re-arms")

        // The running tick can still fire once the stream goes silent.
        try? await waitFor(within: 3) { await counter.value > 0 }
        fired = await counter.value
        XCTAssertEqual(fired, 1)
    }

    // MARK: - Helpers

    private actor Count {
        private var n = 0
        func bump() { n += 1 }
        var value: Int { n }
    }

    /// Polls `condition` until it holds or `seconds` pass. True when it held.
    private func waitFor(
        within seconds: Double = 1,
        _ condition: @escaping () async -> Bool
    ) async throws -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if await condition() { return true }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        return await condition()
    }
}

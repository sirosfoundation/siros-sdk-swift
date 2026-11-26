// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// The SSE stream's keep-alive (#306 — the Swift twin of the Kotlin binding's
/// SSE liveness deadline, siros-sdk-kotlin#447).
///
/// The engine heartbeats its event streams every ~15 s (`:` comment lines,
/// wmp-transport.md §4.3.4), so a line arriving — heartbeat or data — is
/// proof the stream is alive. NO line for four missed heartbeats (60 s) is a
/// half-open socket: the kernel still calls the connection established, the
/// read blocks forever, and no error ever surfaces. Found on-device: the
/// stream died silently overnight and every later `wmp.flow.start`
/// orphaned — the engine's asks still went to a socket nobody read.
///
/// `URLSession` has no per-read timeout to set the way the Kotlin binding
/// sets OkHttp's `readTimeout`, so the Swift twin is an application-level
/// clock: the transport notes the time of every line received
/// (``noteActivity()``), a periodic check (``checkInterval``, 30 s) compares
/// it against the idle limit (``idleLimit``, 60 s), and ``onIdle`` fires when
/// the limit passed. The transport then marks itself FAILED and the session's
/// existing reconnect replays from `Last-Event-ID`.
///
/// Pure and cross-platform (like `SseEventParser` and `SseReaderGate`): the
/// HTTP+SSE transport that drives it is Apple-only, the clock itself is
/// testable everywhere.
public final class SseLivenessWatchdog: @unchecked Sendable {
    /// How often the idle clock is checked. ~30 s in production.
    public let checkInterval: TimeInterval
    /// How long without a line makes the stream dead: 60 s = four missed
    /// heartbeats at the engine's ~15 s cadence.
    public let idleLimit: TimeInterval

    private let lock = NSLock()
    private var lastActivity = Date()
    /// Bumped by every arm/stop and by a fire: a tick of an arming that has
    /// since been stopped or superseded must not fire.
    private var epoch = 0
    private var loop: Task<Void, Never>?

    /// Fires ONCE when no line arrived within ``idleLimit`` — the transport
    /// marks itself FAILED, and the reconnect that follows re-arms the
    /// watchdog with its fresh reader. Called off this class's lock.
    public var onIdle: (@Sendable () -> Void)?

    public init(checkInterval: TimeInterval = 30, idleLimit: TimeInterval = 60) {
        self.checkInterval = max(checkInterval, 0.001)
        self.idleLimit = max(idleLimit, 0.001)
    }

    /// The clock starts (or re-starts): each reader arms it when it begins,
    /// so a connect that never delivers a byte is the same death as a stream
    /// that goes silent. Arming while the clock already runs only freshens
    /// it — the running tick keeps its arming and can still fire.
    public func arm() {
        lock.lock()
        lastActivity = Date()
        if loop == nil {
            epoch += 1
            // The epoch is captured under the same lock that creates the
            // loop, so the tick sees the arming it belongs to.
            let armed = epoch
            loop = Task { [weak self] in
                guard let self else { return }
                await self.tick(armed: armed)
            }
        }
        lock.unlock()
    }

    /// The clock stops: each reader stops it as it ends, so a dead reader's
    /// silence never marks a stopped transport FAILED. Idempotent.
    public func stop() {
        lock.lock()
        epoch += 1
        loop?.cancel()
        loop = nil
        lock.unlock()
    }

    /// Whether the clock is running (armed).
    public var isArmed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return loop != nil
    }

    /// The time of the last ``noteActivity()`` (or of the last ``arm()``).
    public var lastActivityAt: Date {
        lock.lock()
        defer { lock.unlock() }
        return lastActivity
    }

    /// A line arrived — heartbeat or data, both prove the stream is alive.
    public func noteActivity() {
        lock.lock()
        lastActivity = Date()
        lock.unlock()
    }

    /// The periodic check: one inspection per ``checkInterval``, fire once.
    /// The lock lives in the sync helpers (``inspect(armed:)`` /
    /// ``noteActivity()``): `NSLock` in an async context is a concurrency
    /// violation.
    private func tick(armed myEpoch: Int) async {
        while true {
            do {
                try await Task.sleep(nanoseconds: UInt64(checkInterval * 1_000_000_000))
            } catch {
                return   // stopped
            }
            if inspect(armed: myEpoch) {
                // Off the lock: the transport's onIdle takes its own locks.
                onIdle?()
                return
            }
        }
    }

    /// One idle inspection, under the clock's lock: true when THIS tick's
    /// arming is still current and the idle limit passed — the tick retires
    /// itself (fires once), and the reconnect's fresh reader re-arms. False
    /// keeps the clock ticking; a stop() or re-arm since the arming
    /// invalidates the epoch and the old tick must not fail its successor.
    private func inspect(armed myEpoch: Int) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard epoch == myEpoch,
              Date().timeIntervalSince(lastActivity) >= idleLimit else { return false }
        epoch += 1
        loop = nil
        return true
    }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

#if os(iOS)

import Foundation
#if canImport(os)
import os
#endif

/// At most one loaded prover in the process at a time, released when the
/// host says so.
///
/// A decompressed Longfellow circuit is ~110 MB and a Vega prover key
/// ~140-160 MB, held as native memory outside Swift's own allocator (owned
/// by the Rust side, freed via the generated bindings' `deinit`). Before
/// this actor existed, each proof system kept its own cache of every prover
/// it had ever loaded for the life of the process - two proof systems and
/// two attribute counts could pin half a gigabyte, and the matching Kotlin
/// SDK already hit a real out-of-memory crash on a real device from exactly
/// this (see `ZkProverResidency.kt`'s own doc comment). This is the Swift
/// port of that same fix: one slot, keyed by whatever the proof system
/// needs to tell provers apart, reloaded on a miss, the old one simply
/// dropped (ARC + the generated binding's `deinit` frees the Rust-side
/// object - these generated UniFFI object types have no explicit
/// `close()`/`AutoCloseable` the way the Kotlin bindings do, so there is
/// nothing to call here beyond releasing the reference).
///
/// **Close to Kotlin's version, for the same underlying reason, not a
/// simpler one**: Kotlin's `ZkProverResidency` needs a manual mutex plus a
/// `releaseWhenIdle` flag so `release()` can be non-blocking and still defer
/// correctly while a proof is in flight. A bare Swift `actor` looks like it
/// buys the same property for free (every call to an actor-isolated method
/// queues on the actor's own serial executor) - but that queuing only
/// applies BETWEEN calls, not within one: `use`'s own `await`s (on `load`/
/// `block`) are suspension points another queued call can run during,
/// which is exactly reentrant enough to let two callers both think they
/// hold "the" resident prover at once. `withGate` below is this type's own
/// explicit mutex, for the same reason Kotlin's exists - see its doc
/// comment for the concrete race this closes.
///
/// One residency is shared by every proof system a host constructs
/// (`LongfellowZkProofSystem` and `VegaProofSystem` both take one in their
/// initializers) - the bound really is one prover process-wide, not one per
/// system. Proving is serialized on it as a consequence: two concurrent
/// proofs would otherwise each need a resident prover, and a wallet never
/// has two presentations in flight at once anyway.
public actor ZkProverResidency {

    private var resident: (key: String, prover: AnyObject)?

    // Actor isolation alone does NOT make `use`'s critical section
    // non-reentrant across its `await`s: while `load()` or `block()` is
    // suspended, another `use()`/`release()` call queued on this same actor
    // can run in the interleaving gap, mutate/clear `resident`, and start
    // loading a second large native prover - the first call's local
    // `prover`/`loaded` reference keeps ITS prover alive via ARC regardless
    // of what `resident` now points to, defeating the one-resident bound
    // this type exists to enforce and letting two FFI calls run at once.
    // `isBusy`/`waiters` is an explicit, reentrancy-proof async gate around
    // the whole load+block (or release) body - acquired in `withGate`,
    // released in `withGate`'s `defer`, so at most one `use`/`release` body
    // is ever actually running regardless of how many suspension points it
    // contains. This is the Swift-actor equivalent of what Kotlin's
    // `ZkProverResidency` uses its manual mutex for.
    private var isBusy = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    public init() {}

    /// The key of the prover currently loaded, or `nil`. For diagnostics and tests.
    public var residentKey: String? { resident?.key }

    /// Runs `block` with the prover for `key`, loading it with `load` if it
    /// is not the one resident (dropping whatever was, letting ARC free it).
    /// Serialized against every other `use`/`release` call via `withGate` -
    /// see this type's own doc comment above for why that gate, not just
    /// actor isolation, is what actually makes this non-reentrant.
    public func use<T: AnyObject, R>(
        key: String,
        load: () async throws -> T,
        block: (T) async throws -> R
    ) async throws -> R {
        try await withGate {
            let prover: T
            if let current = self.resident, current.key == key, let typed = current.prover as? T {
                prover = typed
            } else {
                if let current = self.resident {
                    #if canImport(os)
                    logger.info("Releasing resident ZK prover '\(current.key, privacy: .public)' to load '\(key, privacy: .public)'")
                    #endif
                    self.resident = nil
                }
                let loaded = try await load()
                self.resident = (key, loaded)
                prover = loaded
            }
            return try await block(prover)
        }
    }

    /// Drops the resident prover - a no-op with nothing resident. Waits its
    /// turn behind any `use(...)` currently in its critical section (via the
    /// same `withGate` every call goes through), then applies - see this
    /// type's doc comment for why an explicit gate, not just actor
    /// isolation, is required for that to hold. A caller on a synchronous
    /// callback (e.g. an app-lifecycle "entered background" notification)
    /// should wrap this in a detached `Task` rather than block waiting for it.
    public func release() async {
        await withGate {
            if let current = self.resident {
                #if canImport(os)
                logger.info("Releasing resident ZK prover '\(current.key, privacy: .public)'")
                #endif
                self.resident = nil
            }
        }
    }

    /// Runs `body` with exclusive access to this actor's critical section:
    /// at most one `withGate` body is ever actually executing, even though
    /// `body` itself may suspend (at `load`/`block`) and let other calls
    /// queue on the actor in the meantime. A queued caller is resumed only
    /// when the current holder's `body` finishes, via an explicit
    /// continuation handoff rather than relying on actor re-entrancy ordering.
    private func withGate<R>(_ body: () async throws -> R) async rethrows -> R {
        if isBusy {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                waiters.append(continuation)
            }
            // Resumed only by `releaseGate()`, which hands ownership of the
            // gate directly to us - `isBusy` is already (still) true.
        } else {
            isBusy = true
        }
        defer { releaseGate() }
        return try await body()
    }

    private func releaseGate() {
        if waiters.isEmpty {
            isBusy = false
        } else {
            // Ownership transfers directly to the next waiter - `isBusy`
            // stays true the whole handoff, so no third call can slip in
            // between this release and that waiter resuming.
            waiters.removeFirst().resume()
        }
    }
}

#if canImport(os)
private let logger = Logger(subsystem: "org.siros.sdk", category: "ZkProverResidency")
#endif

#endif // os(iOS)

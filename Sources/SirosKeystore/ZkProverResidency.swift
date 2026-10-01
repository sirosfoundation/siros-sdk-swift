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
/// **Simpler than Kotlin's version by construction, not by omission**:
/// Kotlin's `ZkProverResidency` needs a manual mutex plus a
/// `releaseWhenIdle` flag specifically so `release()` can be non-blocking
/// and still defer correctly while a proof is in flight (JVM has no
/// built-in "queue this behind whatever's running" primitive cheap enough
/// to use from a UI-thread lifecycle callback). A Swift `actor` already
/// provides exactly that: every call to an actor-isolated method is queued
/// on the actor's own serial executor, so a `release()` call made while
/// `use(...)` is still running simply waits its turn and applies once
/// `use` returns - no flag, no `tryLock`, no risk of the two racing.
///
/// One residency is shared by every proof system a host constructs
/// (`LongfellowZkProofSystem` and `VegaProofSystem` both take one in their
/// initializers) - the bound really is one prover process-wide, not one per
/// system. Proving is serialized on it as a consequence: two concurrent
/// proofs would otherwise each need a resident prover, and a wallet never
/// has two presentations in flight at once anyway.
public actor ZkProverResidency {

    private var resident: (key: String, prover: AnyObject)?

    public init() {}

    /// The key of the prover currently loaded, or `nil`. For diagnostics and tests.
    public var residentKey: String? { resident?.key }

    /// Runs `block` with the prover for `key`, loading it with `load` if it
    /// is not the one resident (dropping whatever was, letting ARC free it).
    /// Holds the residency for the duration via actor isolation, so `load`
    /// and `block` never overlap with another caller's.
    public func use<T: AnyObject, R>(
        key: String,
        load: () async throws -> T,
        block: (T) async throws -> R
    ) async throws -> R {
        let prover: T
        if let current = resident, current.key == key, let typed = current.prover as? T {
            prover = typed
        } else {
            if let current = resident {
                #if canImport(os)
                logger.info("Releasing resident ZK prover '\(current.key, privacy: .public)' to load '\(key, privacy: .public)'")
                #endif
                resident = nil
            }
            let loaded = try await load()
            resident = (key, loaded)
            prover = loaded
        }
        return try await block(prover)
    }

    /// Drops the resident prover - a no-op with nothing resident. Safe to
    /// call from any context at any time: as an `async` actor method, a
    /// call made while `use(...)` is still running is simply queued behind
    /// it by the actor's own serial executor, applying once `use` returns -
    /// see this type's doc comment for why that's enough on its own, unlike
    /// Kotlin's equivalent, which needs its own mutex/flag to get the same
    /// property. A caller on a synchronous callback (e.g. an app-lifecycle
    /// "entered background" notification) should wrap this in a detached
    /// `Task` rather than block waiting for it.
    public func release() {
        if let current = resident {
            #if canImport(os)
            logger.info("Releasing resident ZK prover '\(current.key, privacy: .public)'")
            #endif
            resident = nil
        }
    }
}

#if canImport(os)
private let logger = Logger(subsystem: "org.siros.sdk", category: "ZkProverResidency")
#endif

#endif // os(iOS)

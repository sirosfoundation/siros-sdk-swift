// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosKeystore

extension SirosWallet {
    /// Drops the resident native ZK prover (a decompressed circuit or
    /// prover key, 100-160 MB of native memory held outside Swift's own
    /// allocator - see `ZkProverResidency`'s doc comment) if one is
    /// currently loaded. Mirrors the matching Kotlin SDK's
    /// `ZkMdocPresentation.releaseProvers()`: call it when the host app
    /// loses the foreground (e.g. from `UIApplicationDelegate
    /// .applicationDidEnterBackground`) so this 100+ MB isn't pinned while
    /// backgrounded - nothing else in this wallet's own lifecycle reaches
    /// `ZkProverResidency.release()` otherwise. Also called automatically
    /// from `endSessionLocally()`, so a logout (or a lifecycle-blocked
    /// teardown) doesn't leave the previous account's resident prover
    /// loaded either. A no-op on non-iOS platforms (no resident prover
    /// exists there) and whenever nothing is currently loaded. Safe to call
    /// from any context at any time - see `ZkProverResidency.release()`'s
    /// own doc comment for why.
    public func releaseZkProvers() {
        #if os(iOS)
        let residency = zkProverResidency
        Task { await residency.release() }
        #endif
    }
}

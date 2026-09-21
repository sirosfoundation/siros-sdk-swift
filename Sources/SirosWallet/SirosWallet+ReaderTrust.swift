// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

extension SirosWallet {
    /// Evaluates a proximity reader's authenticated identity for trust - the
    /// `evaluateReaderTrust` dependency `MdocProximitySession` expects, for
    /// wiring into `BlePeripheralServer`/`BleCentralClient`. Only ever called
    /// with an x5chain whose `readerAuth` COSE_Sign1 signature has ALREADY
    /// verified locally (see `MdocCose.verify1`) - this method is purely the
    /// trust decision, mirroring `evaluateTrustDirect`'s request shape with a
    /// `"mdoc-reader-auth"` action name against go-trust's `mdocrical`
    /// registry. Ported from the Kotlin SDK's `SirosWallet.evaluateReaderTrust`.
    ///
    /// Which path runs is `WalletConfig.readerTrustEvaluationMode`. The
    /// default, `.remoteWithLocalFallback`, prefers the remote AuthZEN call:
    /// it is the only path that honors RICAL's temporary and dynamic trust
    /// roots, since go-trust's own registry cache and refresh handle
    /// freshness and the wallet just asks fresh each time. It drops to local
    /// X.509 validation against `WalletConfig.readerTrustRootCertificatesPem`
    /// only when go-trust could not be REACHED - a backend that refuses the
    /// caller fails closed instead. `.remoteOnly` never drops, and
    /// `.localOnly` never asks.
    ///
    /// - Parameter x5chain: the reader's DER-encoded certificate chain, leaf first.
    public func evaluateReaderTrust(_ x5chain: [[UInt8]]) async -> TrustResult {
        guard !x5chain.isEmpty else {
            return TrustResult(trusted: false, reason: "readerAuth has no certificate chain")
        }
        return await evaluateMdocTrust(
            mode: config.readerTrustEvaluationMode,
            framework: "mdocrical",
            entityLabel: "reader",
            registryName: "RICAL",
            remote: { try await self.evaluateReaderTrustRemote(x5chain) },
            local: { self.evaluateReaderTrustLocally(x5chain) }
        )
    }

    private func evaluateReaderTrustRemote(_ x5chain: [[UInt8]]) async throws -> TrustResult {
        try await evaluateMdocTrustRemote(x5chain: x5chain, actionName: "mdoc-reader-auth", defaultFramework: "mdocrical")
    }

    /// Plain X.509 path validation against
    /// `WalletConfig.readerTrustRootCertificatesPem` - no RICAL CBOR
    /// parsing, no `trustConstraints` enforcement, since this path exists
    /// purely as an offline/unreachable-backend fallback for the stable,
    /// known-in-advance official root(s), not a full reimplementation of
    /// go-trust's `mdocrical` registry.
    private func evaluateReaderTrustLocally(_ x5chain: [[UInt8]]) -> TrustResult {
        evaluateMdocTrustLocally(
            x5chain: x5chain,
            rootCertificatesPem: config.readerTrustRootCertificatesPem,
            frameworkLabel: "local-rical-root",
            entityLabel: "reader",
            registryName: "RICAL"
        )
    }
}

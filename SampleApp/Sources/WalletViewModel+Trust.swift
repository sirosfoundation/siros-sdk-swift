// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosWallet

/// The wallet's trust configuration as one value (2026-11-16): the RICAL /
/// VICAL roots and evaluation modes, resolved from the ViewModel's
/// persisted settings. Split out of WalletViewModel.swift to keep that file
/// under SwiftLint's 1500-line limit.
///
/// The deprecated `preferLocalReaderTrustEvaluation` boolean stays honored:
/// with the reader mode at its default, `true` maps to `.localOnly`. The
/// mode is the full statement, so the mode wins where both are non-default;
/// the issuer side passes directly.
struct WalletTrustConfig {
    var readerRootPem: [String]
    var preferLocal: Bool
    var issuerRootPem: [String]
    var readerMode: MdocTrustEvaluationMode?
    var issuerMode: MdocTrustEvaluationMode?
}

extension WalletViewModel {
    /// The trust block, resolved from the persisted settings.
    var trustConfig: WalletTrustConfig {
        WalletTrustConfig(
            readerRootPem: readerTrustRootCertificatePem.isEmpty ? [] : [readerTrustRootCertificatePem],
            preferLocal: preferLocalReaderTrustEvaluation,
            issuerRootPem: issuerTrustRootCertificatePem.isEmpty ? [] : [issuerTrustRootCertificatePem],
            readerMode: readerTrustEvaluationMode != .remoteWithLocalFallback
                ? readerTrustEvaluationMode
                : (preferLocalReaderTrustEvaluation ? .localOnly : nil),
            issuerMode: issuerTrustEvaluationMode != .remoteWithLocalFallback
                ? issuerTrustEvaluationMode
                : nil
        )
    }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
import SirosWallet

/// Credential status: DIIP's Validity and Revocation Algorithm, which the SDK
/// runs (see `SirosWallet.refreshCredentialStatuses`). The `@Published`
/// `credentialStatuses` stays in `WalletViewModel.swift`, since Swift
/// extensions cannot add stored properties; only the behaviour lives here,
/// mirroring the SDK's own `SirosWallet+*.swift` split.
extension WalletViewModel {

    /// The DIIP release this wallet's wire behaviour follows - see
    /// `WalletConfig.diipProfile`.
    var diipProfile: DiipProfile { wallet?.diipProfile ?? .latest }

    /// Re-run DIIP's Validity and Revocation Algorithm over every held
    /// credential. Only the unusable ones are kept, so a card reads the map by
    /// id and finds nothing for a credential that is fine.
    func refreshCredentialStatuses() {
        guard let wallet else { return }
        // Evaluating a credential's status parses it (CBOR, for an mdoc) and
        // can fetch and verify the issuer's status list, so the work runs off
        // the main actor; only the result is published back to the UI.
        Task.detached(priority: .utility) { [weak self] in
            let statuses = await wallet.refreshCredentialStatuses()
            let unusable = statuses.filter { $0.value != .valid }
            await MainActor.run { [weak self] in
                self?.credentialStatuses = unusable
            }
        }
    }
}

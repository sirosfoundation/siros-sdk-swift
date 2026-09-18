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
    ///
    /// A state emission that did not change the credential set does no work:
    /// `.ready`/`.flowActive` arrive on every engine progress update during a
    /// long issuance or presentation, and each evaluation re-parses every
    /// credential and may fetch a status list. Any refresh still in flight is
    /// cancelled, so overlapping evaluations cannot race to publish and the
    /// newest credential set wins rather than whichever finishes last.
    func refreshCredentialStatuses(for credentials: [StoredCredential], force: Bool = false) {
        guard let wallet else { return }
        let ids = credentials.map(\.id).sorted()
        guard force || ids != statusesEvaluatedFor else { return }
        statusesEvaluatedFor = ids

        // Evaluating a credential's status parses it (CBOR, for an mdoc) and
        // can fetch and verify the issuer's status list, so the work runs off
        // the main actor; only the result is published back to the UI.
        credentialStatusTask?.cancel()
        credentialStatusTask = Task.detached(priority: .utility) { [weak self] in
            let statuses = await wallet.refreshCredentialStatuses()
            guard !Task.isCancelled else { return }
            let unusable = statuses.filter { $0.value != .valid }
            await MainActor.run { [weak self] in
                self?.credentialStatuses = unusable
            }
        }
    }

    /// Forget what was evaluated, so the next credential set is re-evaluated
    /// even if it happens to hold the same ids.
    func resetCredentialStatuses() {
        credentialStatusTask?.cancel()
        statusesEvaluatedFor = nil
        credentialStatuses = [:]
    }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials

#if DEBUG
extension WalletViewModel {
    /// Seeds a plain fixture credential set and jumps straight past login to
    /// the credentials tab, bypassing the wallet session entirely - the
    /// credential card stack (`CredentialStack`, `CredentialsView`) is a pure
    /// view over `credentials`/`walletState`, so exercising its
    /// tap/long-press/drag interactions (manually via
    /// `SIMCTL_CHILD_SIROS_SAMPLE_APP_FIXTURE_CREDENTIALS=1 xcrun simctl
    /// launch <udid> <bundle-id>`, or from
    /// `CredentialStackInteractionUITests`) needs no real backend, wallet
    /// session or key material. Mirrors the Kotlin sample app's
    /// `CredentialStackInteractionTest`, which renders `CredentialStack`
    /// directly over a fixture `CredentialWithInstances` list with no wallet
    /// session either.
    ///
    /// Called unconditionally from `init` (the call site stays a one-liner
    /// there); this method and everything it touches is compiled out of
    /// release builds by the surrounding `#if DEBUG`, so it costs nothing
    /// there rather than needing a second guard at the call site too.
    func applyFixtureCredentialsIfRequested() {
        guard ProcessInfo.processInfo.environment["SIROS_SAMPLE_APP_FIXTURE_CREDENTIALS"] != nil else {
            return
        }
        walletState = .ready
        credentials = Self.fixtureCredentials
    }

    /// Three plain credentials (batch ids 1, 2, 3) with distinct `issuedAt`
    /// values so `CredentialUtils.groupForDisplay`'s issuedAt-descending sort
    /// yields them in that same order - batch id 3 ("Charlie") ends up
    /// last/frontmost, matching the Kotlin sample app's
    /// `CredentialStackInteractionTest` fixture exactly. See
    /// `applyFixtureCredentialsIfRequested()` above.
    static let fixtureCredentials: [StoredCredential] = [
        StoredCredential(
            id: 1, format: "dc+sd-jwt", raw: "",
            metadata: CredentialMetadata(name: "Alpha", backgroundColor: "#224488", textColor: "#FFFFFF"),
            issuedAt: 3_000, batchId: 1, instanceId: 0
        ),
        StoredCredential(
            id: 2, format: "dc+sd-jwt", raw: "",
            metadata: CredentialMetadata(name: "Bravo", backgroundColor: "#227744", textColor: "#FFFFFF"),
            issuedAt: 2_000, batchId: 2, instanceId: 0
        ),
        StoredCredential(
            id: 3, format: "dc+sd-jwt", raw: "",
            metadata: CredentialMetadata(name: "Charlie", backgroundColor: "#884422", textColor: "#FFFFFF"),
            issuedAt: 1_000, batchId: 3, instanceId: 0
        ),
    ]
}
#endif

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials

/// Observable wallet state. Apps observe `SirosWallet.state` to drive their UI.
public enum WalletState: Sendable, Equatable {
    /// Not authenticated. `cachedAccounts` are loginable accounts for the picker.
    case disconnected(cachedAccounts: [CachedAccount] = [])

    /// Authentication / keystore unlock in progress.
    case connecting

    /// Authenticated, keystore unlocked, ready.
    case ready(userId: String, displayName: String?, credentials: [StoredCredential], cachedAccounts: [CachedAccount] = [])

    /// Session resumed but keystore still locked (requires PRF).
    case keystoreLocked(userId: String, displayName: String?)

    /// An issuance or presentation flow is in progress.
    case flowActive(userId: String, displayName: String?, flowId: String, flowType: String, status: String, credentials: [StoredCredential])

    /// The backend refuses this installation because of its wallet instance's
    /// lifecycle (SID-AUTH-06): the instance is suspended, or the wallet has
    /// been deactivated and its data erased. Terminal for this session - it is
    /// not an error to retry or dismiss, but a condition that only someone
    /// else (another device, the provider) can lift.
    ///
    /// Entered from `login()`, `unlockKeystore()`, `resumeSession()` and from
    /// the SDK's own re-login after a token cut-off, whenever the
    /// authorization server answers `403` with `WALLET_SUSPENDED` /
    /// `WALLET_REVOKED`.
    ///
    /// **Neither reason forgets anything local**, and `cachedAccounts` still
    /// lists this account. `.revoked` is *not* proof the wallet was erased:
    /// the backend answers with it for the login gate of a single revoked
    /// instance as well, and only deactivates the wallet when the last
    /// non-revoked instance is revoked - the user's other devices keep working
    /// either way. Only `message`, which is written for the user, tells the
    /// two apart, so the SDK shows it rather than guessing.
    ///
    /// What an app should offer: for `.suspended`, a retry - a later `login()`
    /// succeeds once the instance is reactivated from another device. For
    /// `.revoked`, a fresh enrollment, which is the way forward in both the
    /// per-instance and the deactivated case. `SirosWallet.deactivateWallet`
    /// is the only thing that forgets the cached account.
    case lifecycleBlocked(
        reason: SirosError.WalletLifecycleRefusal,
        message: String?,
        cachedAccounts: [CachedAccount] = []
    )

    /// An error occurred.
    case error(message: String)
}

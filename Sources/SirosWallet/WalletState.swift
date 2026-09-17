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
    /// On `.revoked` the cached account for this tenant has already been
    /// forgotten (its server-side data is gone and its passkey can never log
    /// in again), so `cachedAccounts` no longer lists it and the app should
    /// offer a fresh enrollment. On `.suspended` nothing local is lost and a
    /// later `login()` succeeds once the instance is reactivated.
    case lifecycleBlocked(
        reason: SirosError.WalletLifecycleRefusal,
        message: String?,
        cachedAccounts: [CachedAccount] = []
    )

    /// An error occurred.
    case error(message: String)
}

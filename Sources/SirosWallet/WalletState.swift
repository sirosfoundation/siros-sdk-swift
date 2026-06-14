// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials

/// Observable wallet state. Apps observe `SirosWallet.state` to drive their UI.
public enum WalletState: Sendable, Equatable {
    /// Not authenticated.
    case disconnected

    /// Authentication / keystore unlock in progress.
    case connecting

    /// Authenticated, keystore unlocked, ready.
    case ready(userId: String, displayName: String?, credentials: [StoredCredential])

    /// Session resumed but keystore still locked (requires PRF).
    case keystoreLocked(userId: String, displayName: String?)

    /// An issuance or presentation flow is in progress.
    case flowActive(userId: String, displayName: String?, flowId: String, flowType: String, status: String, credentials: [StoredCredential])

    /// An error occurred.
    case error(message: String)
}

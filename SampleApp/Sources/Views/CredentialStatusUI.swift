// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosCredentials

/// How a ``CredentialStatus`` is shown.
///
/// Only the presentation lives here - which words and which colour. Whether a
/// credential *has* a status is the SDK's answer (see
/// `SirosWallet.refreshCredentialStatuses`), because establishing it means
/// reading a validity window and fetching the issuer's Token Status List.
extension CredentialStatus {

    /// The one-word ribbon label.
    var ribbonLabel: String {
        switch self {
        case .valid: return ""
        case .expired: return L10n.string("credentials.statusExpired")
        case .notYetValid: return L10n.string("credentials.statusNotYetValid")
        case .revoked: return L10n.string("credentials.statusRevoked")
        case .suspended: return L10n.string("credentials.statusSuspended")
        }
    }

    /// The sentence shown on the detail screen, rather than the one-word
    /// ribbon.
    var detailMessage: String {
        switch self {
        case .valid: return ""
        case .expired: return L10n.string("credentials.statusExpiredDetail")
        case .notYetValid: return L10n.string("credentials.statusNotYetValidDetail")
        case .revoked: return L10n.string("credentials.statusRevokedDetail")
        case .suspended: return L10n.string("credentials.statusSuspendedDetail")
        }
    }

    /// Error colouring for the permanent outcomes, warning colouring for the
    /// ones that may resolve on their own - a suspended credential can be
    /// reinstated by its issuer, and one that is not yet valid simply becomes
    /// valid.
    var ribbonColor: Color {
        switch self {
        case .expired, .revoked: return SirosTheme.error
        case .notYetValid, .suspended: return SirosTheme.warning
        case .valid: return SirosTheme.success
        }
    }
}

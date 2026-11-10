// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// The screens the bottom bar and the menu lead to. The raw values are
/// `WalletViewModel.selectedTab`'s: 0, 1 and 2 are the three tabs it has
/// always named, and the menu's destinations follow on.
enum WalletDestination: Int {
    case credentials = 0
    case home = 1
    case settings = 2
    case menu = 3
    case share = 4
    case about = 5
}

/// Where a row of the menu leads.
enum MenuItem: String, CaseIterable {
    case manageCredentials
    case shareInPerson
    case history
    case addCredentials
    case settings
    case about
    case verify
    case logout
}

/// Navigation among the designed screens. The destination is
/// `selectedTab` (stored on the view model so it survives a round trip
/// through a stacked screen); the `show*` flags stack History, Add
/// Credentials, Scan Photo ID and the scanner over whichever destination is
/// current.
extension WalletViewModel {

    var destination: WalletDestination {
        get { WalletDestination(rawValue: selectedTab) ?? .home }
        set { selectedTab = newValue.rawValue }
    }

    /// Closes every screen stacked over the current destination.
    func closeOverlays() {
        closeActivate()
        closeIDVPreparation()
        closeAddCredential()
        closeHistory()
    }

    /// Goes to `destination`, leaving any stacked screen.
    func go(_ destination: WalletDestination) {
        closeOverlays()
        self.destination = destination
    }

    /// The menu row of the screen now showing; nil on Home and on the menu.
    var currentMenuItem: MenuItem? {
        if showHistory { return .history }
        if showAddCredential || showIDVPreparation { return .addCredentials }
        switch destination {
        case .credentials: return .manageCredentials
        case .share: return .shareInPerson
        case .settings: return .settings
        case .about: return .about
        case .home, .menu: return nil
        }
    }

    /// Opens the menu, remembering the screen it was opened from.
    func openMenu() {
        let current = currentMenuItem
        if current != nil || destination != .menu { menuOrigin = current }
        go(.menu)
    }

    /// The bottom bar's Scan QR: the wallet's one QR scanner, from anywhere.
    func scanQr() {
        closeOverlays()
        openActivate()
    }

    /// Opens Manage credentials, on the "Needs attention" filter or on All.
    func openManageCredentials(needsAttentionOnly: Bool) {
        self.needsAttentionOnly = needsAttentionOnly
        go(.credentials)
    }
}

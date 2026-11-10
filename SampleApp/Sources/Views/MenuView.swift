// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI

/// The wallet's menu: every destination in one list, Logout set apart below
/// a rule, and the attribution line at the foot. The row of the screen the
/// menu was opened from is highlighted.
///
/// "Verify a credential" opens the sample app's mdoc reader. It is this
/// app's own addition to the designed list, which describes the holder side
/// only.
struct MenuView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @EnvironmentObject var verifierViewModel: VerifierViewModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                row(.manageCredentials, "wallet.pass", L10n.string("home.manageCredentials"))
                row(.shareInPerson, "person.2", L10n.string("home.shareInPerson"))
                row(.history, "clock.arrow.circlepath", L10n.string("menu.history"))
                row(.addCredentials, "plus.circle", L10n.string("credentials.addTitle"))
                row(.settings, "gearshape", L10n.string("nav.settings"))
                row(.about, "info.circle", L10n.string("menu.about"))
                row(.verify, "checkmark.shield", L10n.string("menu.verify"))
                rule.padding(.vertical, 20)
                row(.logout, "rectangle.portrait.and.arrow.right", L10n.string("menu.logout"))
                rule.padding(.top, 40)
                Text(L10n.string("menu.poweredBy"))
                    .font(.body.weight(.medium))
                    .foregroundColor(SirosTheme.ink)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 20)
            }
            .padding(.horizontal, SirosTheme.screenMargin)
            .padding(.top, 20)
        }
        .background(SirosTheme.screenBackground)
    }

    private var rule: some View {
        Rectangle().fill(SirosTheme.hairline).frame(height: 1)
    }

    private func row(_ item: MenuItem, _ systemImage: String, _ label: String) -> some View {
        Button(action: { select(item) }) {
            HStack(spacing: 10) {
                Image(systemName: systemImage)
                    .font(.system(size: 20))
                    .frame(width: 24)
                Text(label)
                    .font(.body.weight(.medium))
                Spacer()
            }
            .foregroundColor(SirosTheme.ink)
            .padding(.horizontal, 12)
            .padding(.vertical, 14)
            .background(
                RoundedRectangle(cornerRadius: SirosTheme.cardCorner)
                    .fill(viewModel.menuOrigin == item ? SirosTheme.menuHighlight : Color.clear)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        // "home-verify-nearby-mdoc" is the reader's long-standing hook.
        .accessibilityIdentifier(item == .verify ? "home-verify-nearby-mdoc" : "menu-\(item.rawValue)")
    }

    private func select(_ item: MenuItem) {
        switch item {
        case .manageCredentials: viewModel.openManageCredentials(needsAttentionOnly: false)
        case .shareInPerson: viewModel.go(.share)
        case .history: viewModel.openHistory()
        case .addCredentials: viewModel.openAddCredential()
        case .settings: viewModel.go(.settings)
        case .about: viewModel.go(.about)
        case .verify: verifierViewModel.open()
        case .logout: viewModel.disconnect()
        }
    }
}

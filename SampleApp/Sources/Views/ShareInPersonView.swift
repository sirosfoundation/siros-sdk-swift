// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI

/// Share In-Person: the ways to hand a credential to a device in front of
/// the user. Show QR code presents the wallet's ISO 18013-5 device
/// engagement; Scan QR code reads the other party's code with the wallet's
/// one QR scanner. iOS offers these two: the engagement's NFC handover is
/// the part of ISO 18013-5 this platform does not provide, so there is no
/// "tap" option here.
struct ShareInPersonView: View {
    @EnvironmentObject var viewModel: WalletViewModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                ScreenTitle(text: L10n.string("share.title"))
                Text(L10n.string("share.intro"))
                    .font(.body.weight(.medium))
                    .foregroundColor(SirosTheme.ink)
                    .padding(.bottom, 4)
                ActionCard(
                    title: L10n.string("share.showQrTitle"),
                    subtitle: L10n.string("share.showQrSubtitle"),
                    systemImage: "qrcode",
                    tileLeading: true,
                    identifier: "share-show-qr"
                ) {
                    viewModel.openActivate(mode: .proximity)
                }
                ActionCard(
                    title: L10n.string("share.scanQrTitle"),
                    subtitle: L10n.string("share.scanQrSubtitle"),
                    systemImage: "camera",
                    tileLeading: true,
                    identifier: "share-scan-qr"
                ) {
                    viewModel.openActivate()
                }
            }
            .padding(.horizontal, SirosTheme.screenMargin)
            .padding(.vertical, 12)
        }
        .background(SirosTheme.screenBackground)
    }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI

/// About: what this app is and which build of it is running.
struct AboutView: View {
    private var version: String {
        let info = Bundle.main.infoDictionary
        let short = info?["CFBundleShortVersionString"] as? String ?? "-"
        let build = info?["CFBundleVersion"] as? String ?? "-"
        return "\(short) (\(build))"
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                ScreenTitle(text: L10n.string("menu.about"))
                Text(L10n.string("about.text"))
                    .font(.body)
                    .foregroundColor(SirosTheme.ink)
                VStack(spacing: 12) {
                    row(L10n.string("about.version"), version)
                    Rectangle().fill(SirosTheme.hairline).frame(height: 1)
                    row(L10n.string("about.license"), "BSD 2-Clause")
                }
                .walletCard()
                Text(L10n.string("menu.poweredBy"))
                    .font(.subheadline)
                    .foregroundColor(SirosTheme.secondaryText)
            }
            .padding(.horizontal, SirosTheme.screenMargin)
            .padding(.vertical, 12)
        }
        .background(SirosTheme.screenBackground)
    }

    private func row(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label).foregroundColor(SirosTheme.secondaryText)
            Spacer()
            Text(value).foregroundColor(SirosTheme.ink)
        }
        .font(.body)
    }
}

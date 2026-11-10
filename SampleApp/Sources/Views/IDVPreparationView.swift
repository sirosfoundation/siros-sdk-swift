// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI

/// Scan Photo ID: what the scan will ask of the user (three steps), what to
/// have ready, why a face scan is part of it, and the consent to biometric
/// processing that enables Start Scan. Chrome-free - `ContentView` frames it.
struct IDVPreparationView: View {
    let onStartScan: () -> Void
    let onDismiss: () -> Void

    @State private var consentGiven = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                ScreenTitle(text: L10n.string("idv.navTitle"), onBack: onDismiss)

                VStack(alignment: .leading, spacing: 20) {
                    StepRow(number: 1, icon: "face.smiling", description: L10n.string("idv.stepFaceScanDescription"))
                    StepRow(number: 2, icon: "viewfinder", description: L10n.string("idv.stepDocumentScanDescription"))
                    StepRow(number: 3, icon: "wave.3.right", description: L10n.string("idv.stepNfcDescription"))
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .walletCard()

                VStack(alignment: .leading, spacing: 12) {
                    Text(L10n.string("idv.beforeYouStart"))
                        .font(.body.weight(.semibold))
                        .foregroundColor(SirosTheme.ink)
                    HStack(alignment: .top, spacing: 8) {
                        Prerequisite(icon: "person.text.rectangle", label: L10n.string("idv.prereqDocument"))
                        Prerequisite(icon: "sun.max", label: L10n.string("idv.prereqLighting"))
                        Prerequisite(icon: "chart.bar", label: L10n.string("idv.prereqConnection"))
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .walletCard(fill: SirosTheme.altSurface)

                HStack(alignment: .center, spacing: 16) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(L10n.string("idv.whyFaceScanTitle"))
                            .font(.body.weight(.semibold))
                        Text(L10n.string("idv.whyFaceScanDescription"))
                            .font(.subheadline)
                    }
                    .foregroundColor(SirosTheme.ink)
                    Spacer(minLength: 0)
                    ZStack {
                        RoundedRectangle(cornerRadius: 4).fill(SirosTheme.altSurface)
                        Image(systemName: "checkmark.shield")
                            .font(.system(size: 34))
                            .foregroundColor(SirosTheme.brandOnPage)
                    }
                    .frame(width: 64, height: 64)
                }
                .walletCard()

                Toggle(isOn: $consentGiven) {
                    Text(L10n.string("idv.consentText"))
                        .font(.callout)
                        .foregroundColor(SirosTheme.ink)
                }
                .toggleStyle(.switch)
                .tint(SirosTheme.brand)
                .accessibilityIdentifier("idv-consent")

                Button(action: onStartScan) {
                    Text(L10n.string("idv.startScanButton"))
                        .font(.body.weight(.semibold))
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity, minHeight: 48)
                        .background(
                            RoundedRectangle(cornerRadius: SirosTheme.cardCorner)
                                .fill(SirosTheme.brand.opacity(consentGiven ? 1 : 0.4))
                        )
                }
                .buttonStyle(.plain)
                .disabled(!consentGiven)
                .accessibilityIdentifier("idv-start")
            }
            .padding(.horizontal, SirosTheme.screenMargin)
            .padding(.vertical, 8)
        }
        .background(SirosTheme.screenBackground)
    }
}

private struct StepRow: View {
    let number: Int
    let icon: String
    let description: String

    var body: some View {
        HStack(alignment: .top, spacing: 20) {
            SoftIconTile(systemImage: icon)
            VStack(alignment: .leading, spacing: 2) {
                Text(L10n.string("idv.stepNumber", number))
                    .font(.body.weight(.semibold))
                Text(description)
                    .font(.body)
            }
            .foregroundColor(SirosTheme.ink)
        }
    }
}

private struct Prerequisite: View {
    let icon: String
    let label: String

    var body: some View {
        VStack(spacing: 10) {
            SoftIconTile(systemImage: icon, size: 54, circular: true)
            Text(label)
                .font(.subheadline.weight(.medium))
                .foregroundColor(SirosTheme.ink)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
    }
}

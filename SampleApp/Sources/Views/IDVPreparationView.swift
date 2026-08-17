// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI

/// IDV preparation screen matching the wallet-frontend's ScanPhysicalID.tsx UX.
///
/// Shows three steps (face scan → document scan → NFC read), prerequisites,
/// privacy explanation, consent checkbox, and "Start Scan" CTA.
struct IDVPreparationView: View {
    let onStartScan: () -> Void
    let onDismiss: () -> Void

    @State private var consentGiven = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    // Steps
                    Text(L10n.string("idv.howItWorks"))
                        .font(.headline)

                    StepRow(number: 1, icon: "faceid", title: L10n.string("idv.stepFaceScanTitle"),
                            description: L10n.string("idv.stepFaceScanDescription"))
                    StepRow(number: 2, icon: "doc.viewfinder", title: L10n.string("idv.stepDocumentScanTitle"),
                            description: L10n.string("idv.stepDocumentScanDescription"))
                    StepRow(number: 3, icon: "wave.3.right", title: L10n.string("idv.stepNfcTitle"),
                            description: L10n.string("idv.stepNfcDescription"))

                    Divider()

                    // Prerequisites
                    Text(L10n.string("idv.beforeYouStart"))
                        .font(.subheadline)
                        .fontWeight(.semibold)

                    VStack(alignment: .leading, spacing: 6) {
                        Label(L10n.string("idv.prereqDocument"), systemImage: "checkmark.circle")
                        Label(L10n.string("idv.prereqLighting"), systemImage: "checkmark.circle")
                        Label(L10n.string("idv.prereqConnection"), systemImage: "checkmark.circle")
                    }
                    .font(.callout)
                    .foregroundColor(.secondary)

                    Divider()

                    // Privacy explanation
                    Text(L10n.string("idv.whyFaceScanTitle"))
                        .font(.subheadline)
                        .fontWeight(.semibold)

                    Text(L10n.string("idv.whyFaceScanDescription"))
                        .font(.caption)
                        .foregroundColor(.secondary)

                    // Consent
                    Toggle(isOn: $consentGiven) {
                        Text(L10n.string("idv.consentText"))
                            .font(.callout)
                    }
                    .toggleStyle(.switch)

                    // Start Scan
                    Button(action: onStartScan) {
                        Text(L10n.string("idv.startScanButton"))
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(!consentGiven)
                }
                .padding(.horizontal, 24)
                .padding(.vertical, 16)
            }
            .navigationTitle(L10n.string("idv.navTitle"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(L10n.string("common.cancel"), action: onDismiss)
                }
            }
        }
    }
}

private struct StepRow: View {
    let number: Int
    let icon: String
    let title: String
    let description: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            ZStack {
                Circle()
                    .fill(Color.accentColor.opacity(0.15))
                    .frame(width: 36, height: 36)
                Text("\(number)")
                    .font(.callout)
                    .fontWeight(.bold)
                    .foregroundColor(.accentColor)
            }

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Image(systemName: icon)
                        .font(.callout)
                    Text(title)
                        .font(.callout)
                        .fontWeight(.medium)
                }
                Text(description)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
        }
    }
}

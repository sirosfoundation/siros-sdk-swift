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
                    Text("How it works")
                        .font(.headline)

                    StepRow(number: 1, icon: "faceid", title: "Face scan",
                            description: "Scan your face to show you are a real, live human")
                    StepRow(number: 2, icon: "doc.viewfinder", title: "Document scan",
                            description: "Scan the photo page of your passport or ID card")
                    StepRow(number: 3, icon: "wave.3.right", title: "NFC chip read",
                            description: "Place your phone on your document to read the NFC chip")

                    Divider()

                    // Prerequisites
                    Text("Before you start")
                        .font(.subheadline)
                        .fontWeight(.semibold)

                    VStack(alignment: .leading, spacing: 6) {
                        Label("Have your passport or ID card ready", systemImage: "checkmark.circle")
                        Label("Ensure good lighting conditions", systemImage: "checkmark.circle")
                        Label("Ensure a stable internet connection", systemImage: "checkmark.circle")
                    }
                    .font(.callout)
                    .foregroundColor(.secondary)

                    Divider()

                    // Privacy explanation
                    Text("Why a face scan?")
                        .font(.subheadline)
                        .fontWeight(.semibold)

                    Text("A 3D face scan verifies you are a real, live person. Your biometric data is encrypted during capture and processed only for identity verification. It is not stored after the session.")
                        .font(.caption)
                        .foregroundColor(.secondary)

                    // Consent
                    Toggle(isOn: $consentGiven) {
                        Text("I consent to biometric processing for identity verification.")
                            .font(.callout)
                    }
                    .toggleStyle(.switch)

                    // Start Scan
                    Button(action: onStartScan) {
                        Text("Start Scan")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                    .disabled(!consentGiven)
                }
                .padding(.horizontal, 24)
                .padding(.vertical, 16)
            }
            .navigationTitle("Scan Physical ID")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: onDismiss)
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

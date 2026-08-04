// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import UIKit
import SirosKeystore

/// ISO 18013-5 §8.2 device engagement, shown as a QR code (§8.2.2.3) AND a
/// real "mdoc peripheral server mode" BLE GATT server (`BlePeripheralServer`)
/// that a real mdoc reader can connect to, decrypt a request from, and
/// receive a signed `DeviceResponse` back from - this is a genuinely
/// completable proximity presentation, not just an engagement demo, PROVIDED
/// a stored credential's docType matches what the reader asks for.
///
/// Ported from the Kotlin sample app's `ProximityEngagementScreen.kt`.
/// Unlike that screen, there is no NFC static handover here: iOS doesn't
/// allow third-party apps to emulate an NFC Type 4 Tag / act as an HCE host
/// the way Android's `HostApduService` does (that capability is restricted
/// to specific system frameworks, not general app code) - QR and BLE
/// peripheral server mode are this screen's only two engagement/retrieval
/// mechanisms.
///
/// "mdoc central client mode" (this device scanning for and connecting to a
/// reader's own GATT server) is not implemented - see `BlePeripheralServer`'s
/// doc comment.
struct ProximityEngagementScreen: View {
    @EnvironmentObject var viewModel: WalletViewModel

    @State private var engagement: DeviceEngagement.Engagement?
    @State private var qrImage: UIImage?
    @State private var statusLines: [String] = ["Starting..."]
    @State private var server: BlePeripheralServer?
    @State private var setupError: String?

    var body: some View {
        NavigationStack {
            Group {
                if let setupError {
                    errorView(setupError)
                } else if let qrImage {
                    engagementView(qrImage)
                } else {
                    ProgressView()
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
            .navigationTitle("Proximity Engagement")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Close") { viewModel.closeProximityEngagement() }
                }
            }
        }
        .onAppear(perform: setUpIfNeeded)
        .onDisappear {
            server?.stop()
        }
    }

    @ViewBuilder
    private func engagementView(_ qrImage: UIImage) -> some View {
        ScrollView {
            VStack(spacing: 16) {
                Text("Scan with an ISO 18013-5 mdoc reader")
                    .font(.title3.weight(.medium))
                    .multilineTextAlignment(.center)

                Image(uiImage: qrImage)
                    .resizable()
                    .interpolation(.none)
                    .scaledToFit()
                    .frame(maxWidth: 280, maxHeight: 280)
                    .padding(.vertical, 8)

                Divider()

                Text(
                    "BLE peripheral server mode is advertising - a real reader can connect " +
                    "and complete a presentation if a stored credential matches its requested " +
                    "docType. NFC static handover is not available on iOS."
                )
                .font(.body)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)

                Divider()

                VStack(alignment: .leading, spacing: 4) {
                    ForEach(Array(statusLines.suffix(6).enumerated()), id: \.offset) { pair in
                        Text(pair.element)
                            .font(.footnote)
                            .foregroundColor(.secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding(24)
        }
    }

    private func errorView(_ message: String) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 40))
                .foregroundColor(.orange)
            Text("Could not start proximity engagement")
                .font(.headline)
            Text(message)
                .font(.footnote)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func setUpIfNeeded() {
        guard engagement == nil else { return }
        do {
            let engagement = try DeviceEngagement.create(
                supportsCentralClientMode: true,
                supportsPeripheralServerMode: true
            )
            self.engagement = engagement
            self.qrImage = QrCodeGenerator.generate(engagement.mdocUri)

            let bleServer = BlePeripheralServer(
                engagement: engagement,
                getCredentials: { [viewModel] in await viewModel.getCredentialsForProximity() },
                signPresentation: { [viewModel] credentialId, disclosedClaims, sessionTranscriptBytes in
                    try await viewModel.signMdocPresentationForProximity(
                        credentialId: credentialId,
                        disclosedClaims: disclosedClaims,
                        sessionTranscriptBytes: sessionTranscriptBytes
                    )
                },
                onLog: { line in statusLines.append(line) },
                onComplete: { success in
                    statusLines.append(success ? "Presentation complete" : "Presentation did not complete")
                }
            )
            server = bleServer
            bleServer.start()
        } catch {
            setupError = error.localizedDescription
        }
    }
}

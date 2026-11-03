// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI

/// Standalone reader UI. It shares only the camera representable with the
/// wallet app; it does not embed holder `QRScannerContent` or ActivateView.
struct MdocVerifierView: View {
    @EnvironmentObject var viewModel: VerifierViewModel
    @State private var showScanner = false
    @State private var simulatorQR = ""

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    Label("No account or sign-in is required.", systemImage: "person.crop.circle.badge.checkmark")
                        .font(.subheadline)
                        .foregroundColor(SirosTheme.onSurfaceVariant)

                    configuration

                    Button(action: { showScanner = true }) {
                        Label("Scan mdoc engagement QR", systemImage: "qrcode.viewfinder")
                            .frame(maxWidth: .infinity)
                            .frame(height: 48)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(SirosTheme.brand)
                    .disabled(viewModel.isRunning)
                    .accessibilityIdentifier("verifier-scan")

                    Button(action: { viewModel.startNfc() }) {
                        Label("Tap wallet (NFC)", systemImage: "wave.3.right")
                            .frame(maxWidth: .infinity)
                            .frame(height: 48)
                    }
                    .buttonStyle(.bordered)
                    .tint(SirosTheme.brand)
                    .disabled(viewModel.isRunning)
                    .accessibilityIdentifier("verifier-nfc")

                    Text("Requests one mDL document with given_name and family_name. Intent to retain is false for both. NFC reads static handover only; SessionData continues over Bluetooth.")
                        .font(.caption)
                        .foregroundColor(SirosTheme.onSurfaceVariant)

                    content
                }
                .padding(24)
            }
            .background(SirosTheme.background)
            .navigationTitle("Verify nearby mdoc")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(viewModel.isRunning ? "Cancel" : "Back") {
                        Task { await viewModel.close() }
                    }
                    .accessibilityIdentifier("verifier-back-cancel")
                }
            }
            .sheet(isPresented: $showScanner) {
                scannerSheet
            }
        }
        .onDisappear {
            // Covers navigation away without using the toolbar. `close()` also
            // cancels first, so repeated cancellation is harmless.
            Task { await viewModel.cancel() }
        }
    }

    private var configuration: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("go-trust (AuthZEN)")
                .font(.headline)
            TextField("Complete evaluation URL", text: $viewModel.evaluationEndpoint)
                .textFieldStyle(.roundedBorder)
                .keyboardType(.URL)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
                .disabled(viewModel.isRunning)
                .accessibilityIdentifier("verifier-endpoint")
            TextField("Tenant", text: $viewModel.tenantId)
                .textFieldStyle(.roundedBorder)
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
                .disabled(viewModel.isRunning)
                .accessibilityIdentifier("verifier-tenant")
            Text("The complete /v1/evaluate URL is used as entered. No token or wallet credentials are sent.")
                .font(.caption)
                .foregroundColor(SirosTheme.onSurfaceVariant)
        }
    }

    @ViewBuilder
    private var content: some View {
        if let progress = viewModel.phase.progressMessage {
            HStack(spacing: 12) {
                ProgressView()
                Text(progress)
                    .foregroundColor(SirosTheme.onSurfaceVariant)
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            Button("Cancel verification", role: .cancel) {
                Task { await viewModel.cancel() }
            }
            .buttonStyle(.bordered)
        }

        switch viewModel.phase {
        case .verified:
            VStack(alignment: .leading, spacing: 12) {
                Label("Verified and permitted", systemImage: "checkmark.seal.fill")
                    .font(.headline)
                    .foregroundColor(.green)
                if viewModel.claims.isEmpty {
                    Text("The response was verified and permitted, but contained no requested claims.")
                        .foregroundColor(SirosTheme.onSurfaceVariant)
                } else {
                    ForEach(viewModel.claims) { claim in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(claim.identifier)
                                .font(.caption)
                                .foregroundColor(SirosTheme.onSurfaceVariant)
                            Text(claim.value)
                                .font(.body.weight(.medium))
                            Text(claim.namespace)
                                .font(.caption2)
                                .foregroundColor(SirosTheme.onSurfaceVariant)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(12)
                        .background(
                            RoundedRectangle(cornerRadius: 10)
                                .fill(SirosTheme.surfaceVariant)
                        )
                    }
                }
            }
        case .denied(let message):
            outcome(icon: "hand.raised.fill", title: "Denied by go-trust", message: message, color: .orange)
        case .sessionOver(let status):
            outcome(
                icon: "xmark.circle.fill",
                title: status == 20 ? "Session ended" : "Session ended by wallet",
                message: "The wallet ended the session (status \(status)). No claims were shown.",
                color: .orange
            )
        case .failed(let message):
            outcome(icon: "exclamationmark.triangle.fill", title: "Could not verify", message: message, color: SirosTheme.error)
        case .cancelled:
            Text("Verification cancelled. No claims were shown.")
                .foregroundColor(SirosTheme.onSurfaceVariant)
        default:
            EmptyView()
        }
    }

    private func outcome(icon: String, title: String, message: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: icon)
                .font(.headline)
                .foregroundColor(color)
            Text(message)
                .foregroundColor(SirosTheme.onSurfaceVariant)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(SirosTheme.surfaceVariant)
        )
    }

    private var scannerSheet: some View {
        NavigationStack {
            Group {
                #if targetEnvironment(simulator)
                VStack(spacing: 16) {
                    Image(systemName: "camera.fill")
                        .font(.system(size: 48))
                        .foregroundColor(.secondary)
                    Text("Camera scanning is unavailable in Simulator. Paste the other device's mdoc: engagement URI instead.")
                        .multilineTextAlignment(.center)
                        .foregroundColor(SirosTheme.onSurfaceVariant)
                    TextField("mdoc:…", text: $simulatorQR, axis: .vertical)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .lineLimit(3...6)
                    Button("Verify pasted engagement") {
                        start(qrCode: simulatorQR)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(simulatorQR.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
                .padding(24)
                #else
                CameraQRScanner { qrCode in
                    start(qrCode: qrCode)
                }
                .ignoresSafeArea()
                #endif
            }
            .navigationTitle("Scan mdoc QR")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { showScanner = false }
                }
            }
        }
    }

    private func start(qrCode: String) {
        let qrCode = qrCode.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !qrCode.isEmpty else { return }
        showScanner = false
        viewModel.start(qrCode: qrCode)
    }
}

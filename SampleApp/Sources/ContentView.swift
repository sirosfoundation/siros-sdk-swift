// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosWallet

struct ContentView: View {
    @EnvironmentObject var viewModel: WalletViewModel

    var body: some View {
        Group {
            switch viewModel.walletState {
            case .disconnected, .connecting:
                LoginView()
            case .ready:
                if let flowType = viewModel.flowStarting {
                    FlowStartingView(flowType: flowType)
                } else if viewModel.pendingPresentation != nil {
                    PresentationConsentView()
                } else if let credential = viewModel.selectedCredential {
                    CredentialDetailView(credential: credential)
                } else if viewModel.showHistory {
                    PresentationHistoryView()
                } else if viewModel.showQrScanner {
                    QRScannerView()
                } else if viewModel.showProximityEngagement {
                    ProximityEngagementScreen()
                } else if viewModel.showAddCredential {
                    AddCredentialView()
                } else if viewModel.showWscaDeveloper {
                    WscaDeveloperView()
                } else {
                    MainTabView()
                }
            case .flowActive(let flowType, let status):
                FlowActiveView(flowType: flowType, status: status)
            case .error(let message):
                ErrorView(message: message)
            }
        }
        .alert("Error", isPresented: $viewModel.showError) {
            Button("OK") { viewModel.clearError() }
        } message: {
            Text(viewModel.errorMessage ?? "")
        }
        .alert("Info", isPresented: $viewModel.showInfo) {
            Button("OK") { viewModel.clearInfo() }
        } message: {
            Text(viewModel.infoMessage ?? "")
        }
        // Attached at this top level (not inside a specific screen) since a
        // `RequestWscdChoice` prompt can fire during credential issuance
        // regardless of which screen happens to be showing underneath -
        // mirrors how the error/info alerts above are handled globally.
        .sheet(item: $viewModel.pendingWscdChoice, onDismiss: {
            // Covers the sheet being dismissed WITHOUT the user tapping a
            // plugin or Cancel (e.g. swiping it away) - see
            // `WalletViewModel.dismissWscdChoice`'s doc comment, mirroring
            // `ProximityEngagementScreen`'s identical `onDismiss` handling.
            viewModel.dismissWscdChoice()
        }) { choice in
            WscdChoiceSheet(choice: choice)
        }
        // Same top-level rationale as `pendingWscdChoice` above - a FIDO2
        // ClientPin prompt (see `SampleAppAuthProvider.requestPin`) can fire
        // during any signing operation regardless of which screen is
        // showing underneath.
        .sheet(item: $viewModel.pendingFido2PinEntry, onDismiss: {
            viewModel.dismissFido2PinEntry()
        }) { pending in
            Fido2PinEntryView(pending: pending)
        }
    }
}

// MARK: - Flow Starting View

/// Interstitial shown the instant a QR-scanned (or pasted/deep-linked)
/// offer/request URI is handed off to the SDK's issuance/presentation start
/// call, and cleared the moment the engine's first real flow-progress state
/// arrives (see `WalletViewModel.flowStarting`). Covers the network-bound gap
/// (VCTM fetch, issuer metadata, client attestation) before `FlowActiveView`
/// below has anything to show - without it, a slow issuer left the screen
/// looking unchanged long enough that a user could reasonably conclude the
/// scan hadn't registered.
struct FlowStartingView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    let flowType: String

    private var messageKey: String {
        flowType == "presentation" ? "flow.starting.presentation" : "flow.starting.issuance"
    }

    var body: some View {
        VStack(spacing: 16) {
            ProgressView()
                .scaleEffect(1.5)
                .tint(SirosTheme.brand)
            Text(L10n.string(messageKey))
                .font(.body)
                .foregroundColor(SirosTheme.onSurfaceVariant)
            Button(L10n.string("flow.cancelButton")) {
                viewModel.cancelFlowStarting()
            }
            .buttonStyle(.bordered)
            .tint(SirosTheme.brand)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(SirosTheme.background)
    }
}

// MARK: - Flow Active View

struct FlowActiveView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    let flowType: String
    let status: String

    // Guard against a visible backward jump: real execution order can
    // deviate slightly from the canonical step list (e.g. a step retried
    // after a transient error), but the bar should never un-progress.
    @State private var maxProgress: Double = 0

    private var stepProgress: Double? { flowStepProgress(flowType: flowType, step: status) }

    var body: some View {
        VStack(spacing: 16) {
            if let stepProgress {
                ProgressView(value: maxProgress)
                    .tint(SirosTheme.brand)
                    .onAppear { maxProgress = max(maxProgress, stepProgress) }
                    // Single-param onChange(of:perform:) - the two-param
                    // (oldValue, newValue) overload needs iOS 17+, but this
                    // app's deployment target is iOS 16.
                    .onChange(of: stepProgress) { newValue in
                        maxProgress = max(maxProgress, newValue)
                    }
            } else {
                ProgressView()
                    .scaleEffect(1.5)
                    .tint(SirosTheme.brand)
            }
            Text(flowStepLabel(status))
                .font(.body)
                .foregroundColor(SirosTheme.onSurfaceVariant)
            if viewModel.showDiagnosticMessages {
                Text(L10n.string("flow.diagnosticLabel", status))
                    .font(.caption)
                    .foregroundColor(SirosTheme.onSurfaceVariant.opacity(0.7))
            }
            Button(L10n.string("flow.cancelButton")) {
                viewModel.cancelCurrentFlow()
            }
            .buttonStyle(.bordered)
            .tint(SirosTheme.brand)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(SirosTheme.background)
    }
}

// MARK: - Error View

struct ErrorView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    let message: String

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 48))
                .foregroundColor(SirosTheme.error)
            Text("Something went wrong")
                .font(.title2.bold())
            Text(message)
                .font(.body)
                .foregroundColor(SirosTheme.onSurfaceVariant)
                .multilineTextAlignment(.center)
            Button("Retry") {
                viewModel.disconnect()
            }
            .buttonStyle(.borderedProminent)
            .tint(SirosTheme.brand)
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(SirosTheme.background)
    }
}

// MARK: - Main Tab View

struct MainTabView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @State private var selectedTab = 0

    var body: some View {
        VStack(spacing: 0) {
            // Top bar matching Android
            HStack {
                SirosMarkView()
                    .frame(width: 28, height: 28)
                Spacer().frame(width: 10)
                Text("SIROS Wallet")
                    .font(.headline)
                    .fontWeight(.semibold)
                Spacer()
                Button(action: { viewModel.openProximityEngagement() }) {
                    Image(systemName: "wave.3.right")
                        .font(.title3)
                        .foregroundColor(SirosTheme.onSurface)
                }
                Button(action: { viewModel.openQrScanner() }) {
                    Image(systemName: "qrcode.viewfinder")
                        .font(.title3)
                        .foregroundColor(SirosTheme.onSurface)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .background(SirosTheme.surface)

            Divider()

            // Content area
            Group {
                switch selectedTab {
                case 0:
                    CredentialsView()
                case 2:
                    SettingsView()
                default:
                    EmptyView()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            Divider()

            // Bottom tab bar matching Android
            HStack {
                tabButton(
                    icon: "wallet.pass",
                    label: "Credentials",
                    tag: 0
                )
                Spacer()
                tabButton(
                    icon: "plus",
                    label: "Add",
                    tag: 1,
                    action: {
                        selectedTab = 1
                        viewModel.openAddCredential()
                    }
                )
                Spacer()
                tabButton(
                    icon: "gear",
                    label: "Settings",
                    tag: 2
                )
            }
            .padding(.horizontal, 32)
            .padding(.vertical, 8)
            .background(SirosTheme.surfaceVariant)
        }
        .background(SirosTheme.background)
    }

    @ViewBuilder
    private func tabButton(icon: String, label: String, tag: Int, action: (() -> Void)? = nil) -> some View {
        let isSelected = selectedTab == tag
        Button(action: {
            if let action {
                action()
            } else {
                selectedTab = tag
            }
        }) {
            VStack(spacing: 2) {
                Image(systemName: icon)
                    .font(.system(size: 20))
                Text(label)
                    .font(.caption2)
            }
            .foregroundColor(isSelected ? SirosTheme.brand : SirosTheme.onSurfaceVariant)
        }
        .buttonStyle(.plain)
    }
}

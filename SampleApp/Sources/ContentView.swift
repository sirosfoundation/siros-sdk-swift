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
                if viewModel.pendingPresentation != nil {
                    PresentationConsentView()
                } else if let credential = viewModel.selectedCredential {
                    CredentialDetailView(credential: credential)
                } else if viewModel.showHistory {
                    PresentationHistoryView()
                } else if viewModel.showQrScanner {
                    QRScannerView()
                } else if viewModel.showAddCredential {
                    AddCredentialView()
                } else if viewModel.showWscaDeveloper {
                    WscaDeveloperView()
                } else {
                    MainTabView()
                }
            case .flowActive(let message):
                FlowActiveView(message: message)
            case .error(let message):
                ErrorView(message: message)
            }
        }
        .alert("Error", isPresented: $viewModel.showError) {
            Button("OK") { viewModel.clearError() }
        } message: {
            Text(viewModel.errorMessage ?? "")
        }
    }
}

// MARK: - Flow Active View

struct FlowActiveView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    let message: String

    var body: some View {
        VStack(spacing: 16) {
            ProgressView()
                .scaleEffect(1.5)
                .tint(Color(SirosTheme.brand))
            Text(message)
                .font(.body)
                .foregroundColor(Color(SirosTheme.onSurfaceVariant))
            Button("Cancel") {
                viewModel.cancelCurrentFlow()
            }
            .buttonStyle(.bordered)
            .tint(Color(SirosTheme.brand))
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(SirosTheme.background))
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
                .foregroundColor(Color(SirosTheme.error))
            Text("Something went wrong")
                .font(.title2.bold())
            Text(message)
                .font(.body)
                .foregroundColor(Color(SirosTheme.onSurfaceVariant))
                .multilineTextAlignment(.center)
            Button("Retry") {
                viewModel.disconnect()
            }
            .buttonStyle(.borderedProminent)
            .tint(Color(SirosTheme.brand))
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(SirosTheme.background))
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
                Button(action: { viewModel.openQrScanner() }) {
                    Image(systemName: "qrcode.viewfinder")
                        .font(.title3)
                        .foregroundColor(Color(SirosTheme.onSurface))
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .background(Color(SirosTheme.surface))

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
            .background(Color(SirosTheme.surfaceVariant))
        }
        .background(Color(SirosTheme.background))
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
            .foregroundColor(isSelected ? Color(SirosTheme.brand) : Color(SirosTheme.onSurfaceVariant))
        }
        .buttonStyle(.plain)
    }
}

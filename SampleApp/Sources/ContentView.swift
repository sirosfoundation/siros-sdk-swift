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
            Text(message)
                .font(.body)
                .foregroundStyle(.secondary)
            Button("Cancel") {
                viewModel.cancelCurrentFlow()
            }
            .buttonStyle(.bordered)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
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
                .foregroundStyle(.red)
            Text("Something went wrong")
                .font(.title2.bold())
            Text(message)
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("Disconnect") {
                viewModel.disconnect()
            }
            .buttonStyle(.borderedProminent)
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Main Tab View

struct MainTabView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @State private var selectedTab = 0

    var body: some View {
        TabView(selection: $selectedTab) {
            CredentialsView()
                .tabItem {
                    Label("Credentials", systemImage: "wallet.pass")
                }
                .tag(0)

            Button(action: { viewModel.openAddCredential() }) {
                VStack(spacing: 12) {
                    Image(systemName: "plus.circle.fill")
                        .font(.system(size: 48))
                    Text("Add Credential")
                        .font(.headline)
                }
            }
            .tabItem {
                Label("Add", systemImage: "plus")
            }
            .tag(1)

            SettingsView()
                .tabItem {
                    Label("Settings", systemImage: "gear")
                }
                .tag(2)
        }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button(action: { viewModel.openQrScanner() }) {
                    Image(systemName: "qrcode.viewfinder")
                }
            }
        }
    }
}

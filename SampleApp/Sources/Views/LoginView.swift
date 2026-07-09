// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI

struct LoginView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @State private var showRegister = false
    @State private var showOtherLogin = false
    @State private var registerName = ""
    @State private var showBackendInfo = false

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                Spacer().frame(height: 24)

                // Logo — matches Android ic_siros_mark
                SirosMarkView()
                    .frame(width: 56, height: 56)

                Spacer().frame(height: 8)

                Text("SIROS Wallet")
                    .font(.title)
                    .fontWeight(.bold)

                // Info toggle — matches Android: tap to reveal backend URL
                Button(action: { showBackendInfo.toggle() }) {
                    HStack(spacing: 4) {
                        Image(systemName: "info.circle")
                            .font(.caption2)
                        Text(showBackendInfo ? viewModel.backendUrl : "Digital Identity For Humans")
                            .font(.caption)
                    }
                    .foregroundColor(Color(SirosTheme.onSurfaceVariant))
                }
                .buttonStyle(.plain)

                Spacer().frame(height: 20)

                VStack(spacing: 12) {
                    if showBackendInfo {
                        TextField("Backend URL", text: $viewModel.backendUrl)
                            .textFieldStyle(.roundedBorder)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .disabled(viewModel.isLoading)

                        TextField("Tenant ID", text: $viewModel.tenantId)
                            .textFieldStyle(.roundedBorder)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .disabled(viewModel.isLoading)
                    }

                    loginContent
                }
                .padding(20)
                .background(
                    RoundedRectangle(cornerRadius: 16)
                        .fill(Color(SirosTheme.surface))
                        .shadow(color: .black.opacity(0.05), radius: 2, y: 1)
                )
            }
            .padding(.horizontal, 32)
        }
        .background(Color(SirosTheme.background))
    }

    @ViewBuilder
    private var loginContent: some View {
        if showRegister {
            // Mode C: Registration
            Text("Create Account")
                .font(.headline)
                .fontWeight(.semibold)

            TextField("Display name", text: $registerName)
                .textFieldStyle(.roundedBorder)
                .autocorrectionDisabled()
                .disabled(viewModel.isLoading)

            Text("\(registerName.utf8.count)/64")
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .trailing)

            Button(action: {
                viewModel.register(displayName: registerName)
            }) {
                HStack {
                    if viewModel.isLoading {
                        ProgressView()
                            .tint(.white)
                    }
                    Text("Sign up with passkey")
                }
                .frame(maxWidth: .infinity)
                .frame(height: 48)
            }
            .buttonStyle(.borderedProminent)
            .tint(Color(SirosTheme.brand))
            .clipShape(RoundedRectangle(cornerRadius: 12))
            .disabled(viewModel.isLoading || registerName.isEmpty || registerName.utf8.count > 64)

            Button("Already have an account? Login") {
                showRegister = false
            }
            .font(.subheadline)

        } else if !viewModel.cachedAccounts.isEmpty && !showOtherLogin {
            // Mode A: Cached accounts picker
            Text("Welcome back")
                .font(.headline)
                .fontWeight(.semibold)

            ForEach(viewModel.cachedAccounts, id: \.accountId) { account in
                HStack(spacing: 8) {
                    Button(action: {
                        viewModel.loginWithAccount(account)
                    }) {
                        HStack {
                            if viewModel.isLoading {
                                ProgressView()
                                    .tint(.white)
                            }
                            Text(account.displayName)
                                .lineLimit(1)
                        }
                        .frame(maxWidth: .infinity)
                        .frame(height: 48)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(Color(SirosTheme.brand))
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                    .disabled(viewModel.isLoading)

                    Button(action: {
                        viewModel.forgetAccount(account.accountId)
                    }) {
                        Image(systemName: "xmark")
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.borderless)
                }
            }

            Button("Use other account") {
                showOtherLogin = true
            }
            .font(.subheadline)

        } else {
            // Mode B: Generic passkey login
            Button(action: viewModel.login) {
                HStack {
                    if viewModel.isLoading {
                        ProgressView()
                            .tint(.white)
                    }
                    Text("Log in with Passkey")
                }
                .frame(maxWidth: .infinity)
                .frame(height: 48)
            }
            .buttonStyle(.borderedProminent)
            .tint(Color(SirosTheme.brand))
            .clipShape(RoundedRectangle(cornerRadius: 12))
            .disabled(viewModel.isLoading)

            Button("New here? Sign up") {
                showRegister = true
            }
            .font(.subheadline)

            if !viewModel.cachedAccounts.isEmpty {
                Button("Back to saved accounts") {
                    showOtherLogin = false
                }
                .font(.subheadline)
            }
        }
    }
}

// MARK: - SIROS Mark (brand logo)

/// SwiftUI rendering of the SIROS mark (ic_siros_mark).
/// Uses the same path data as the Android vector drawable.
struct SirosMarkView: View {
    var body: some View {
        ZStack {
            // Navy background circle
            Circle()
                .fill(Color(SirosTheme.brand))

            // Simplified SIROS star/compass mark in white
            Image(systemName: "sparkle")
                .font(.system(size: 24, weight: .bold))
                .foregroundColor(.white)
        }
    }
}

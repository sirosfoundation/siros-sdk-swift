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

                Image(systemName: "shield.checkered")
                    .font(.system(size: 56))
                    .foregroundColor(.accentColor)

                Text("SIROS ID")
                    .font(.title.bold())

                Button(action: { showBackendInfo.toggle() }) {
                    HStack(spacing: 4) {
                        Image(systemName: "info.circle")
                            .font(.caption2)
                        Text(showBackendInfo ? viewModel.backendUrl : "Sample Wallet App")
                            .font(.subheadline)
                    }
                    .foregroundStyle(.secondary)
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
                        .fill(.regularMaterial)
                )
            }
            .padding(.horizontal, 32)
        }
    }

    @ViewBuilder
    private var loginContent: some View {
        if showRegister {
            // Mode C: Registration
            Text("Create Account")
                .font(.headline)

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
                .frame(height: 44)
            }
            .buttonStyle(.borderedProminent)
            .disabled(viewModel.isLoading || registerName.isEmpty || registerName.utf8.count > 64)

            Button("Already have an account? Login") {
                showRegister = false
            }
            .font(.subheadline)

        } else if !viewModel.cachedAccounts.isEmpty && !showOtherLogin {
            // Mode A: Cached accounts picker
            Text("Welcome back")
                .font(.headline)

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
                        .frame(height: 44)
                    }
                    .buttonStyle(.borderedProminent)
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
                    Text("Sign In with Passkey")
                }
                .frame(maxWidth: .infinity)
                .frame(height: 44)
            }
            .buttonStyle(.borderedProminent)
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

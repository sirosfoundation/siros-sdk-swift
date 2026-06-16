// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI

struct LoginView: View {
    @EnvironmentObject var viewModel: WalletViewModel

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                Spacer().frame(height: 24)

                Image(systemName: "shield.checkered")
                    .font(.system(size: 56))
                    .foregroundStyle(.accent)

                Text("SIROS ID")
                    .font(.title.bold())

                Text("Sample Wallet App")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)

                Spacer().frame(height: 20)

                VStack(spacing: 12) {
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

                    Spacer().frame(height: 4)

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

                    Button(action: viewModel.register) {
                        Text("Create Account")
                            .frame(maxWidth: .infinity)
                            .frame(height: 44)
                    }
                    .buttonStyle(.bordered)
                    .disabled(viewModel.isLoading)
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
}

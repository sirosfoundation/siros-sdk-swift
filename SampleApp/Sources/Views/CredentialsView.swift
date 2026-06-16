// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosCredentials

struct CredentialsView: View {
    @EnvironmentObject var viewModel: WalletViewModel

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 8) {
                Text("Welcome, \(viewModel.displayName ?? "User")")
                    .font(.title2.bold())
                    .padding(.horizontal)

                Text(credentialCountText)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal)

                if viewModel.credentials.isEmpty {
                    emptyState
                } else if viewModel.credentials.count == 1 {
                    CredentialCardView(credential: viewModel.credentials[0])
                        .onTapGesture {
                            viewModel.openCredentialDetail(viewModel.credentials[0])
                        }
                        .padding(.horizontal)
                } else {
                    TabView {
                        ForEach(viewModel.credentials, id: \.id) { credential in
                            CredentialCardView(credential: credential)
                                .onTapGesture {
                                    viewModel.openCredentialDetail(credential)
                                }
                                .padding(.horizontal)
                        }
                    }
                    .tabViewStyle(.page(indexDisplayMode: .always))
                }

                Spacer()
            }
            .padding(.top, 12)
            .navigationTitle("Credentials")
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private var credentialCountText: String {
        let count = viewModel.credentials.count
        switch count {
        case 0: return "No credentials yet"
        case 1: return "1 credential"
        default: return "\(count) credentials"
        }
    }

    private var emptyState: some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: "wallet.pass")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
            Text("No credentials yet")
                .font(.headline)
            Text("Add your first credential to get started.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("Add Credential") {
                viewModel.openAddCredential()
            }
            .buttonStyle(.borderedProminent)
            Spacer()
        }
        .frame(maxWidth: .infinity)
        .padding()
    }
}

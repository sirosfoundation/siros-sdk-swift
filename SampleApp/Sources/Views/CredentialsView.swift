// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosCredentials

struct CredentialsView: View {
    @EnvironmentObject var viewModel: WalletViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Welcome, \(viewModel.displayName ?? "User")")
                .font(.title2)
                .fontWeight(.semibold)
                .padding(.horizontal, 16)

            Text(credentialCountText)
                .font(.subheadline)
                .foregroundColor(Color(SirosTheme.onSurfaceVariant))
                .padding(.horizontal, 16)

            Spacer().frame(height: 16)

            if viewModel.credentials.isEmpty {
                emptyState
            } else if viewModel.credentials.count == 1 {
                CredentialCardView(credential: viewModel.credentials[0])
                    .onTapGesture {
                        viewModel.openCredentialDetail(viewModel.credentials[0])
                    }
                    .padding(.horizontal, 16)
            } else {
                TabView {
                    ForEach(viewModel.credentials, id: \.id) { credential in
                        CredentialCardView(credential: credential)
                            .onTapGesture {
                                viewModel.openCredentialDetail(credential)
                            }
                            .padding(.horizontal, 16)
                    }
                }
                .tabViewStyle(.page(indexDisplayMode: .always))
            }

            Spacer()
        }
        .padding(.top, 12)
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
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "plus.circle.fill")
                .font(.system(size: 48))
                .foregroundColor(Color(SirosTheme.brand))
            Text("No credentials yet")
                .font(.headline)
                .fontWeight(.medium)
            Text("Tap to add your first credential")
                .font(.subheadline)
                .foregroundColor(Color(SirosTheme.onSurfaceVariant))
                .multilineTextAlignment(.center)
            Spacer()
        }
        .frame(maxWidth: .infinity)
        .padding(32)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(SirosTheme.surfaceVariant))
        )
        .padding(.horizontal, 16)
        .onTapGesture {
            viewModel.openAddCredential()
        }
    }
}

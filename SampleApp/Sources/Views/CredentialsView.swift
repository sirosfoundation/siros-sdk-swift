// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosCredentials

struct CredentialsView: View {
    @EnvironmentObject var viewModel: WalletViewModel

    /// One entry per batch (see `StoredCredential.batchId`) instead of one
    /// per issued copy - mirrors wallet-frontend's `fetchVcData` grouping
    /// (and the Kotlin sample app's `CredentialsTab`) so a 5-copy batch
    /// issuance shows as a single card with a remaining-copies ribbon, not
    /// five swipeable duplicates.
    private var grouped: [CredentialWithInstances] {
        CredentialUtils.groupForDisplay(
            credentials: viewModel.credentials,
            presentationHistory: viewModel.currentPresentationHistory
        )
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Welcome, \(viewModel.displayName ?? "User")")
                .font(.title2)
                .fontWeight(.semibold)
                .padding(.horizontal, 16)

            Text(credentialCountText)
                .font(.subheadline)
                .foregroundColor(SirosTheme.onSurfaceVariant)
                .padding(.horizontal, 16)

            Spacer().frame(height: 16)

            let entries = grouped
            if entries.isEmpty {
                emptyState
            } else if entries.count == 1 {
                let entry = entries[0]
                CredentialCardView(
                    credential: entry.credential,
                    instances: entry.instances,
                    onClick: { viewModel.openCredentialDetail(entry.credential) },
                    onRenewClick: { viewModel.renewCredential(entry.credential) }
                )
                .padding(.horizontal, 16)
            } else {
                TabView {
                    ForEach(entries, id: \.credential.id) { entry in
                        CredentialCardView(
                            credential: entry.credential,
                            instances: entry.instances,
                            onClick: { viewModel.openCredentialDetail(entry.credential) },
                            onRenewClick: { viewModel.renewCredential(entry.credential) }
                        )
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
        let count = grouped.count
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
                .foregroundColor(SirosTheme.brand)
            Text("No credentials yet")
                .font(.headline)
                .fontWeight(.medium)
            Text("Tap to add your first credential")
                .font(.subheadline)
                .foregroundColor(SirosTheme.onSurfaceVariant)
                .multilineTextAlignment(.center)
            Spacer()
        }
        .frame(maxWidth: .infinity)
        .padding(32)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(SirosTheme.surfaceVariant)
        )
        .padding(.horizontal, 16)
        .onTapGesture {
            viewModel.openAddCredential()
        }
    }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosCredentials

/// Credential picker list — shows available credentials from all issuers.
struct AddCredentialView: View {
    @EnvironmentObject var viewModel: WalletViewModel

    var body: some View {
        NavigationStack {
            Group {
                if viewModel.isLoadingOffers {
                    VStack(spacing: 12) {
                        ProgressView()
                        Text("Loading available credentials...")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if viewModel.availableCredentials.isEmpty {
                    Text("No credentials available")
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    List(viewModel.availableCredentials, id: \.credentialConfigurationId) { offer in
                        CredentialOfferRow(offer: offer)
                            .contentShape(Rectangle())
                            .onTapGesture {
                                viewModel.selectCredentialOffer(offer)
                            }
                    }
                    .listStyle(.plain)
                }
            }
            .navigationTitle("Add Credential")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Back") { viewModel.closeAddCredential() }
                }
            }
            .alert("Add Credential?", isPresented: showIssuanceConsent) {
                Button("Accept") { viewModel.confirmIssuance() }
                Button("Cancel", role: .cancel) { viewModel.cancelIssuance() }
            } message: {
                if let offer = viewModel.pendingIssuanceOffer {
                    Text("You are about to request \"\(offer.credentialName)\" from \(offer.issuerName).")
                }
            }
        }
    }

    private var showIssuanceConsent: Binding<Bool> {
        Binding(
            get: { viewModel.pendingIssuanceOffer != nil },
            set: { if !$0 { viewModel.cancelIssuance() } }
        )
    }
}

// MARK: - Credential Offer Row

struct CredentialOfferRow: View {
    let offer: CredentialOffer

    var body: some View {
        HStack(spacing: 12) {
            // Initial badge
            let bgColor = offer.backgroundColor.flatMap { Color(hex: $0) } ?? .accentColor
            Circle()
                .fill(bgColor)
                .frame(width: 40, height: 40)
                .overlay(
                    Text(offer.credentialName.prefix(1).uppercased())
                        .font(.headline.bold())
                        .foregroundStyle(.white)
                )

            VStack(alignment: .leading, spacing: 2) {
                Text(offer.credentialName)
                    .font(.body.weight(.medium))
                    .lineLimit(1)
                Text(offer.issuerName)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            Spacer()

            Image(systemName: "chevron.right")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
    }
}

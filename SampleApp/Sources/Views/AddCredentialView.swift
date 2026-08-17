// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosCredentials

/// Credential picker list — shows available credentials from all issuers.
struct AddCredentialView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @State private var showIDVPreparation = false

    var body: some View {
        NavigationStack {
            Group {
                if viewModel.isLoadingOffers {
                    VStack(spacing: 12) {
                        ProgressView()
                        Text(L10n.string("credentials.addLoading"))
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if viewModel.availableCredentials.isEmpty {
                    Text(L10n.string("credentials.addEmpty"))
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    List {
                        // Scan Physical ID card
                        Section {
                            Button(action: { showIDVPreparation = true }) {
                                HStack(spacing: 12) {
                                    ZStack {
                                        RoundedRectangle(cornerRadius: 8)
                                            .fill(Color.accentColor.opacity(0.15))
                                            .frame(width: 40, height: 40)
                                        Image(systemName: "camera")
                                            .foregroundColor(.accentColor)
                                    }
                                    VStack(alignment: .leading) {
                                        Text(L10n.string("credentials.scanPhysicalIdTitle"))
                                            .font(.body)
                                            .fontWeight(.medium)
                                        Text(L10n.string("credentials.scanPhysicalIdSubtitle"))
                                            .font(.caption)
                                            .foregroundColor(.secondary)
                                    }
                                    Spacer()
                                    Image(systemName: "chevron.right")
                                        .foregroundColor(.secondary)
                                }
                            }
                            .buttonStyle(.plain)
                        }

                        // Credential offers
                        Section {
                            ForEach(viewModel.availableCredentials, id: \.credentialConfigurationId) { offer in
                                CredentialOfferRow(offer: offer)
                                    .contentShape(Rectangle())
                                    .onTapGesture {
                                        viewModel.selectCredentialOffer(offer)
                                    }
                            }
                        }
                    }
                    .listStyle(.plain)
                }
            }
            .navigationTitle(L10n.string("credentials.addTitle"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button(L10n.string("nav.back")) { viewModel.closeAddCredential() }
                }
            }
            .alert(L10n.string("credentials.addConfirmTitle"), isPresented: showIssuanceConsent) {
                Button(L10n.string("credentials.addConfirmAccept")) { viewModel.confirmIssuance() }
                Button(L10n.string("common.cancel"), role: .cancel) { viewModel.cancelIssuance() }
            } message: {
                if let offer = viewModel.pendingIssuanceOffer {
                    Text(L10n.string("credentials.addConfirmMessage", offer.credentialName, offer.issuerName))
                }
            }
        }
        .sheet(isPresented: $showIDVPreparation) {
            IDVPreparationView(
                onStartScan: {
                    showIDVPreparation = false
                    viewModel.startIDV()
                },
                onDismiss: { showIDVPreparation = false }
            )
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

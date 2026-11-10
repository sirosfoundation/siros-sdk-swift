// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosCredentials

/// Add Credentials: two ways to bring a credential in from outside - scan an
/// issuer's QR code (the wallet's one QR scanner) or scan a passport into a
/// Photo ID (`IDVPreparationView`) - followed by the catalog of credentials
/// the wallet's issuers offer, listed in place.
///
/// The Scan Photo ID card is shown whatever `availableCredentials` holds: a
/// tenant whose one catalog offer is the Photo ID itself (filtered out of the
/// list - see `openAddCredential`) still reaches it here while the list below
/// is empty. Chrome-free - `ContentView` frames it.
struct AddCredentialView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @State private var detailOffer: CredentialOffer?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                ScreenTitle(text: L10n.string("credentials.addTitle"))
                ActionCard(
                    title: L10n.string("credentials.scanQrTitle"),
                    subtitle: L10n.string("credentials.scanQrSubtitle"),
                    systemImage: "qrcode",
                    identifier: "add-scan-qr"
                ) {
                    viewModel.openActivate()
                }
                ActionCard(
                    title: L10n.string("credentials.scanPhysicalIdTitle"),
                    subtitle: L10n.string("credentials.scanPhysicalIdSubtitle"),
                    systemImage: "camera",
                    identifier: "add-scan-photo-id"
                ) {
                    viewModel.openIDVPreparation()
                }

                Text(L10n.string("credentials.addAvailable"))
                    .font(.body.weight(.semibold))
                    .foregroundColor(SirosTheme.ink)
                    .padding(.top, 14)

                if viewModel.isLoadingOffers {
                    VStack(spacing: 12) {
                        ProgressView()
                        Text(L10n.string("credentials.addLoading"))
                            .font(.subheadline)
                            .foregroundColor(SirosTheme.secondaryText)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 24)
                } else if viewModel.availableCredentials.isEmpty {
                    Text(L10n.string("credentials.addEmpty"))
                        .font(.body)
                        .foregroundColor(SirosTheme.secondaryText)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 24)
                } else {
                    ForEach(viewModel.availableCredentials, id: \.offerIdentity) { offer in
                        CredentialOfferRow(offer: offer)
                            // `.onTapGesture` + `.onLongPressGesture` on the
                            // same view both fire on a long-press release in
                            // SwiftUI (a real bug this replaced: tapping to add
                            // a credential could immediately follow opening its
                            // detail sheet) - `exclusively(before:)` recognizes
                            // whichever gesture succeeds first and suppresses
                            // the other.
                            .gesture(
                                LongPressGesture(minimumDuration: 0.5)
                                    .onEnded { _ in detailOffer = offer }
                                    .exclusively(
                                        before: TapGesture()
                                            .onEnded { viewModel.selectCredentialOffer(offer) }
                                    )
                            )
                            .accessibilityAddTraits(.isButton)
                            .accessibilityAction { viewModel.selectCredentialOffer(offer) }
                    }
                }
            }
            .padding(.horizontal, SirosTheme.screenMargin)
            .padding(.vertical, 12)
        }
        .background(SirosTheme.screenBackground)
        .alert(L10n.string("credentials.addConfirmTitle"), isPresented: showIssuanceConsent) {
            Button(L10n.string("credentials.addConfirmAccept")) { viewModel.confirmIssuance() }
            Button(L10n.string("common.cancel"), role: .cancel) { viewModel.cancelIssuance() }
        } message: {
            if let offer = viewModel.pendingIssuanceOffer {
                Text(L10n.string("credentials.addConfirmMessage", offer.credentialName, offer.issuerName))
            }
        }
        .sheet(isPresented: showDetailOffer) {
            if let offer = detailOffer {
                CredentialOfferDetailView(
                    offer: offer,
                    onAdd: {
                        detailOffer = nil
                        viewModel.selectCredentialOffer(offer)
                    },
                    onClose: { detailOffer = nil }
                )
            }
        }
    }

    private var showDetailOffer: Binding<Bool> {
        Binding(
            get: { detailOffer != nil },
            set: { if !$0 { detailOffer = nil } }
        )
    }

    private var showIssuanceConsent: Binding<Bool> {
        Binding(
            get: { viewModel.pendingIssuanceOffer != nil },
            set: { if !$0 { viewModel.cancelIssuance() } }
        )
    }
}

// MARK: - Credential Offer Row

/// One offer of the catalog, as a card: the credential's initial on the
/// issuer's colour, its name, its description, and the issuer on a grey chip.
struct CredentialOfferRow: View {
    let offer: CredentialOffer

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            let bgColor = offer.backgroundColor.flatMap { Color(hex: $0) } ?? SirosTheme.iconTile
            let fgColor: Color = offer.backgroundColor.flatMap { Color(hex: $0) } == nil ? SirosTheme.iconTileContent : .white
            RoundedRectangle(cornerRadius: 4)
                .fill(bgColor)
                .frame(width: 44, height: 44)
                .overlay(
                    Text(offer.credentialName.prefix(1).uppercased())
                        .font(.headline.bold())
                        .foregroundColor(fgColor)
                )

            VStack(alignment: .leading, spacing: 4) {
                Text(offer.credentialName)
                    .font(.body.weight(.medium))
                    .foregroundColor(SirosTheme.ink)
                    .lineLimit(2)
                if let description = offer.credentialDescription, !description.isEmpty {
                    Text(description)
                        .font(.body)
                        .foregroundColor(SirosTheme.secondaryText)
                        .lineLimit(2)
                }
                Text(offer.issuerName)
                    .font(.body)
                    .foregroundColor(SirosTheme.secondaryText)
                    .lineLimit(1)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 2)
                    .background(RoundedRectangle(cornerRadius: 2).fill(SirosTheme.altSurface))
                    .padding(.top, 4)
            }

            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .walletCard()
    }
}

// MARK: - Credential Offer Detail (long-press modal)

/// Detail modal shown on long-press of a `CredentialOfferRow` - lets the
/// user inspect the issuer name and (if published) the credential's
/// description before committing to the issuance-consent dialog, without
/// the row's own tap target already starting that flow.
struct CredentialOfferDetailView: View {
    let offer: CredentialOffer
    let onAdd: () -> Void
    let onClose: () -> Void

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 12) {
                Text(offer.issuerName)
                    .font(.headline)
                if let description = offer.credentialDescription {
                    Text(description)
                        .font(.body)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding()
            .navigationTitle(offer.credentialName)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button(L10n.string("credentials.rowActionClose")) { onClose() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(L10n.string("credentials.rowActionAdd")) { onAdd() }
                }
            }
        }
    }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosCredentials

/// Full credential detail screen with Info/Claims/Raw tabs.
struct CredentialDetailView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    let credential: StoredCredential

    @State private var selectedTab = 0
    @State private var showDeleteConfirmation = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                // Tab picker
                Picker("", selection: $selectedTab) {
                    Text(L10n.string("credentials.tabInfo")).tag(0)
                    Text(L10n.string("credentials.tabClaims")).tag(1)
                    Text(L10n.string("credentials.tabRaw")).tag(2)
                }
                .pickerStyle(.segmented)
                .padding()

                // Tab content
                TabView(selection: $selectedTab) {
                    infoTab.tag(0)
                    claimsTab.tag(1)
                    rawTab.tag(2)
                }
                .tabViewStyle(.page(indexDisplayMode: .never))
            }
            .navigationTitle(credential.metadata?.name ?? credential.format)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button(L10n.string("nav.back")) { viewModel.closeCredentialDetail() }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        viewModel.renewCredential(credential)
                    } label: {
                        Image(systemName: "arrow.clockwise")
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button(role: .destructive) {
                        showDeleteConfirmation = true
                    } label: {
                        Image(systemName: "trash")
                    }
                }
            }
            .confirmationDialog(
                L10n.string("credentials.deleteConfirmTitle"),
                isPresented: $showDeleteConfirmation,
                titleVisibility: .visible
            ) {
                Button(L10n.string("common.delete"), role: .destructive) {
                    viewModel.deleteCredential(credential.id)
                }
                Button(L10n.string("common.cancel"), role: .cancel) {}
            } message: {
                Text(L10n.string("credentials.deleteConfirmMessage", credential.metadata?.name ?? credential.format))
            }
        }
    }

    // MARK: - Info Tab

    private var infoTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                CredentialCardView(credential: credential)

                infoRow(L10n.string("credentials.fieldFormat"), credential.format)

                if let vct = credential.metadata?.vct {
                    infoRow(L10n.string("credentials.fieldType"), vct)
                }
                if let doctype = credential.metadata?.doctype {
                    infoRow(L10n.string("credentials.fieldDocumentType"), doctype)
                }
                if let issuer = credential.metadata?.issuer?.name {
                    infoRow(L10n.string("credentials.fieldIssuer"), issuer)
                }
                if let issuedAt = credential.issuedAt {
                    infoRow(L10n.string("credentials.fieldIssued"), formatTimestamp(issuedAt))
                }
                if let expiresAt = credential.expiresAt {
                    infoRow(L10n.string("credentials.fieldExpires"), formatTimestamp(expiresAt))
                }
            }
            .padding()
        }
    }

    // MARK: - Claims Tab

    private var claimsTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                let claims = CredentialUtils.extractClaims(credential)
                if claims.isEmpty {
                    Text(L10n.string("credentials.noClaims"))
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .center)
                        .padding(.top, 32)
                } else {
                    ForEach(claims, id: \.key) { claim in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(claim.label)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            CopyableTextBlock(text: claim.value)
                        }
                        Divider()
                    }
                }
            }
            .padding()
        }
    }

    // MARK: - Raw Tab

    private var rawTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                let parts = CredentialUtils.parseSdJwtParts(credential.raw)
                if let header = parts.header {
                    CopyableTextBlock(text: header, label: L10n.string("credentials.headerLabel"))
                }
                if let payload = parts.payload {
                    CopyableTextBlock(text: payload, label: L10n.string("credentials.payloadLabel"))
                }
                ForEach(Array(parts.disclosures.enumerated()), id: \.offset) { index, disclosure in
                    CopyableTextBlock(text: disclosure, label: L10n.string("credentials.disclosureLabel", index + 1))
                }
                if parts.header == nil && parts.payload == nil && parts.disclosures.isEmpty {
                    CopyableTextBlock(text: credential.raw)
                }
            }
            .padding()
        }
    }

    // MARK: - Helpers

    private func infoRow(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.body)
        }
    }

    private func formatTimestamp(_ timestamp: Int64) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(timestamp))
        return date.formatted(date: .abbreviated, time: .shortened)
    }
}

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
                    Text("Info").tag(0)
                    Text("Claims").tag(1)
                    Text("Raw").tag(2)
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
                    Button("Back") { viewModel.closeCredentialDetail() }
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
                "Delete Credential",
                isPresented: $showDeleteConfirmation,
                titleVisibility: .visible
            ) {
                Button("Delete", role: .destructive) {
                    viewModel.deleteCredential(credential.id)
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Are you sure you want to delete \"\(credential.metadata?.name ?? credential.format)\"? This cannot be undone.")
            }
        }
    }

    // MARK: - Info Tab

    private var infoTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                CredentialCardView(credential: credential)

                infoRow("Format", credential.format)

                if let vct = credential.metadata?.vct {
                    infoRow("Type", vct)
                }
                if let doctype = credential.metadata?.doctype {
                    infoRow("Document Type", doctype)
                }
                if let issuer = credential.metadata?.issuer?.name {
                    infoRow("Issuer", issuer)
                }
                if let issuedAt = credential.issuedAt {
                    infoRow("Issued", formatTimestamp(issuedAt))
                }
                if let expiresAt = credential.expiresAt {
                    infoRow("Expires", formatTimestamp(expiresAt))
                }
            }
            .padding()
        }
    }

    // MARK: - Claims Tab

    private var claimsTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                let claims = CredentialUtils.extractClaims(from: credential)
                if claims.isEmpty {
                    Text("No claims available")
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .center)
                        .padding(.top, 32)
                } else {
                    ForEach(claims, id: \.key) { claim in
                        HStack(alignment: .top) {
                            Text(claim.label)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .frame(width: 100, alignment: .trailing)
                            Text(claim.value)
                                .font(.body)
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
            Text(credential.raw)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
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

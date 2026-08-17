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
            Text(L10n.string("credentials.welcome", viewModel.displayName ?? L10n.string("credentials.unknownUser")))
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
                .credentialContextMenu(entry.credential, viewModel: viewModel)
            } else {
                // Vertically-scrolling list rather than a horizontal
                // one-at-a-time pager: phone screens are tall, not wide, so
                // a horizontal `TabView` page wastes the ample vertical
                // screen estate available for showing multiple credentials
                // at once (live-testing feedback from the user). Kept
                // conceptually aligned with the equivalent fix in the
                // Kotlin sample app's `CredentialsTab`.
                ScrollView(.vertical, showsIndicators: true) {
                    LazyVStack(spacing: 16) {
                        ForEach(entries, id: \.credential.id) { entry in
                            CredentialCardView(
                                credential: entry.credential,
                                instances: entry.instances,
                                onClick: { viewModel.openCredentialDetail(entry.credential) },
                                onRenewClick: { viewModel.renewCredential(entry.credential) }
                            )
                            .padding(.horizontal, 16)
                            .credentialContextMenu(entry.credential, viewModel: viewModel)
                        }
                    }
                    .padding(.bottom, 16)
                }
            }

            Spacer()
        }
        .padding(.top, 12)
    }

    private var credentialCountText: String {
        let count = grouped.count
        switch count {
        case 0: return L10n.string("credentials.countZero")
        case 1: return L10n.string("credentials.countOne")
        default: return L10n.string("credentials.countOther", count)
        }
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "plus.circle.fill")
                .font(.system(size: 48))
                .foregroundColor(SirosTheme.brand)
            Text(L10n.string("credentials.emptyTitle"))
                .font(.headline)
                .fontWeight(.medium)
            Text(L10n.string("credentials.emptySubtitle"))
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

private struct CredentialContextMenuModifier: ViewModifier {
    let credential: StoredCredential
    let viewModel: WalletViewModel
    @State private var showDeleteConfirmation = false

    func body(content: Content) -> some View {
        content
            .contextMenu {
                Button {
                    viewModel.renewCredential(credential)
                } label: {
                    Label(L10n.string("credentials.renew"), systemImage: "arrow.clockwise")
                }
                Button(role: .destructive) {
                    showDeleteConfirmation = true
                } label: {
                    Label(L10n.string("common.delete"), systemImage: "trash")
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

private extension View {
    /// Long-press action menu (Renew/Delete) for a credential card - SwiftUI's
    /// native `.contextMenu` gesture, matching the Kotlin sample app's
    /// long-press bottom sheet.
    func credentialContextMenu(_ credential: StoredCredential, viewModel: WalletViewModel) -> some View {
        modifier(CredentialContextMenuModifier(credential: credential, viewModel: viewModel))
    }
}

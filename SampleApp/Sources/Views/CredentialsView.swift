// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosCredentials

/// Number of credential cards shown in full before the rest collapse into
/// `CredentialStackOverflow` - mirrors the Kotlin sample app's
/// `CREDENTIAL_STACK_THRESHOLD` exactly.
private let credentialStackThreshold = 3

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

    /// Past `credentialStackThreshold` cards, the tail collapses into one
    /// fanned overflow item instead of extending the scroll further - keeps
    /// the common case (a handful of credentials) showing several full
    /// cards at once, while an overview that would otherwise need a lot of
    /// scrolling gets a single glanceable summary that expands to the full
    /// list on tap. Mirrors the Kotlin sample app's `showAllCredentials`.
    @State private var showAllCredentials = false

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
                let visibleCount = showAllCredentials ? entries.count : min(entries.count, credentialStackThreshold)
                ScrollView(.vertical, showsIndicators: true) {
                    LazyVStack(spacing: 16) {
                        ForEach(entries.prefix(visibleCount), id: \.credential.id) { entry in
                            CredentialCardView(
                                credential: entry.credential,
                                instances: entry.instances,
                                onClick: { viewModel.openCredentialDetail(entry.credential) },
                                onRenewClick: { viewModel.renewCredential(entry.credential) }
                            )
                            .padding(.horizontal, 16)
                            .credentialContextMenu(entry.credential, viewModel: viewModel)
                        }
                        if visibleCount < entries.count {
                            CredentialStackOverflow(
                                remaining: entries.dropFirst(visibleCount),
                                onClick: { showAllCredentials = true }
                            )
                            .padding(.horizontal, 16)
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

/// Compact fanned-card summary for credentials past `credentialStackThreshold`
/// - a glance at how many/which issuers are collapsed, without rendering
/// each one's full SVG card (that's the expensive part the cache in
/// `CredentialCardView` handles; this overview only needs flat background
/// colors). Tapping it expands the full list. Mirrors the Kotlin sample
/// app's `CredentialStackOverflow`.
private struct CredentialStackOverflow: View {
    // ArraySlice, not [CredentialWithInstances] - avoids copying the whole
    // (potentially large) overflow tail on every body recompute, since the
    // caller only ever passes `entries.dropFirst(visibleCount)`.
    let remaining: ArraySlice<CredentialWithInstances>
    let onClick: () -> Void

    private let maxFanned = 3

    var body: some View {
        Button(action: onClick) {
            ZStack {
                ForEach(Array(remaining.prefix(maxFanned).enumerated()), id: \.element.credential.id) { index, entry in
                    let bgColor = entry.credential.metadata?.backgroundColor.flatMap { Color(hex: $0) } ?? SirosTheme.brandLighter
                    RoundedRectangle(cornerRadius: 4)
                        .fill(bgColor)
                        .frame(width: 40, height: 26)
                        .offset(x: CGFloat(index * 14))
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                Text(L10n.string("credentials.stackOverflowMore", remaining.count))
                    .font(.headline)
                    .foregroundColor(SirosTheme.onSurface)
                    .frame(maxWidth: .infinity, alignment: .trailing)
            }
            .padding(12)
            .frame(maxWidth: .infinity)
            .frame(height: 72)
            .background(
                RoundedRectangle(cornerRadius: 16)
                    .fill(SirosTheme.surfaceVariant)
            )
        }
        .buttonStyle(.plain)
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

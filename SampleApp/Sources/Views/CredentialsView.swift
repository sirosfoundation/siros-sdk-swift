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

    /// Long-press action menu (Renew/Delete), driven by `CredentialStack`'s
    /// `onCredentialLongClick` rather than SwiftUI's native `.contextMenu` -
    /// see `CredentialStack.swift`'s doc comment for why a native
    /// `.contextMenu` (this screen's previous long-press mechanism, before
    /// the stack) can't be reused here: it's a self-contained system
    /// interaction with its own gesture recognizer, not something that can
    /// be triggered imperatively from a hand-rolled one, and layering it
    /// alongside a custom drag/tap recognizer on the same card reproduces
    /// the same two-recognizers-starve-each-other problem the stack's own
    /// gesture handling was written specifically to avoid. Same two actions,
    /// same two-step confirmation for Delete, only a bottom action sheet
    /// instead of the native popup.
    @State private var actionMenuFor: StoredCredential?
    @State private var pendingDeleteFor: StoredCredential?

    @State private var query = ""

    var body: some View {
        content
            .background(SirosTheme.screenBackground)
            .overlay(alignment: .bottomTrailing) {
                Button(action: { viewModel.openAddCredential() }) {
                    Image(systemName: "plus")
                        .font(.system(size: 26, weight: .medium))
                        .foregroundColor(.white)
                        .frame(width: 64, height: 64)
                        .background(Circle().fill(SirosTheme.brand))
                        .shadow(color: .black.opacity(0.2), radius: 4, y: 2)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(L10n.string("credentials.addTitle"))
                .accessibilityIdentifier("manage-add")
                .padding(.trailing, SirosTheme.screenMargin)
                .padding(.bottom, 16)
            }
    }

    /// What the search field and the filter leave of `all`.
    private func shown(_ all: [CredentialWithInstances]) -> [CredentialWithInstances] {
        all.filter {
            (!viewModel.needsAttentionOnly || $0.needsAttention(statuses: viewModel.credentialStatuses))
                && $0.credential.matchesSearch(query)
        }
    }

    private func filterPill(_ label: String, selected: Bool, identifier: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(label)
                .font(.body.weight(.medium))
                .foregroundColor(selected ? .white : SirosTheme.ink)
                .padding(.horizontal, 18)
                .padding(.vertical, 8)
                .background(Capsule().fill(selected ? SirosTheme.chipSelected : Color.clear))
                .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier(identifier)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    private var content: some View {
        VStack(alignment: .leading, spacing: 0) {
            let all = grouped
            VStack(alignment: .leading, spacing: 16) {
                ScreenTitle(text: L10n.string("manage.title"))
                TextField(L10n.string("manage.search"), text: $query)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .padding(.horizontal, 14)
                    .frame(minHeight: 44)
                    .background(RoundedRectangle(cornerRadius: 4).fill(SirosTheme.altSurface))
                    .overlay(RoundedRectangle(cornerRadius: 4).stroke(SirosTheme.hairline, lineWidth: 1))
                    .accessibilityIdentifier("manage-search")
                HStack(spacing: 8) {
                    filterPill(
                        L10n.string("manage.filterAll", all.count),
                        selected: !viewModel.needsAttentionOnly,
                        identifier: "manage-filter-all"
                    ) { viewModel.needsAttentionOnly = false }
                    filterPill(
                        L10n.string("manage.filterAttention"),
                        selected: viewModel.needsAttentionOnly,
                        identifier: "manage-filter-attention"
                    ) { viewModel.needsAttentionOnly = true }
                }
            }
            .padding(.horizontal, SirosTheme.screenMargin)
            .padding(.bottom, 16)

            let entries = shown(all)
            if all.isEmpty {
                emptyState
                Spacer()
            } else if entries.isEmpty {
                Text(viewModel.needsAttentionOnly && query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                    ? L10n.string("manage.noneNeedAttention")
                    : L10n.string("manage.noMatch"))
                    .font(.body)
                    .foregroundColor(SirosTheme.secondaryText)
                    .padding(.horizontal, SirosTheme.screenMargin)
                    .padding(.vertical, 24)
                Spacer()
            } else {
                // A partially-overlapping, interactive deck instead of a
                // plain scrolling list - see `CredentialStack.swift`'s doc
                // comment. It owns its own scrolling (a card's drag and a
                // plain vertical scroll are the same gesture, so it has to
                // arbitrate between them itself) and its own reorder state,
                // so there's nothing further to wrap it in here.
                CredentialStack(
                    entries: entries,
                    credentialStatuses: viewModel.credentialStatuses,
                    onCredentialClick: { viewModel.openCredentialDetail($0) },
                    onCredentialLongClick: { actionMenuFor = $0 },
                    onRenewCredential: { viewModel.renewCredential($0) }
                )
                .padding(.horizontal, SirosTheme.screenMargin)
            }
        }
        .padding(.top, 12)
        .confirmationDialog(
            actionMenuFor.map { $0.metadata?.name ?? $0.format } ?? "",
            isPresented: Binding(
                get: { actionMenuFor != nil },
                set: { if !$0 { actionMenuFor = nil } }
            ),
            titleVisibility: .visible,
            presenting: actionMenuFor
        ) { credential in
            Button(L10n.string("credentials.renew")) {
                viewModel.renewCredential(credential)
                actionMenuFor = nil
            }
            Button(L10n.string("common.delete"), role: .destructive) {
                pendingDeleteFor = credential
                actionMenuFor = nil
            }
            Button(L10n.string("common.cancel"), role: .cancel) {
                actionMenuFor = nil
            }
        }
        .confirmationDialog(
            L10n.string("credentials.deleteConfirmTitle"),
            isPresented: Binding(
                get: { pendingDeleteFor != nil },
                set: { if !$0 { pendingDeleteFor = nil } }
            ),
            titleVisibility: .visible,
            presenting: pendingDeleteFor
        ) { credential in
            Button(L10n.string("common.delete"), role: .destructive) {
                viewModel.deleteCredential(credential.id)
                pendingDeleteFor = nil
            }
            Button(L10n.string("common.cancel"), role: .cancel) {
                pendingDeleteFor = nil
            }
        } message: { credential in
            Text(L10n.string("credentials.deleteConfirmMessage", credential.metadata?.name ?? credential.format))
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

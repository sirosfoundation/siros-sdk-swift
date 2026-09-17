// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosAuth
import SirosCredentials

/// Settings → Devices: the wallet instances this user has in this tenant
/// (SID-AUTH-06, go-wallet-backend#319), and the two things a user can do
/// about them - suspend/reactivate/remove one, or deactivate the whole wallet.
///
/// A thin consumer, deliberately: every rule about what a status change costs
/// (the token cut-off and the re-login that follows it, the erasure retry,
/// what becomes of the local account) lives in the SDK. This view only renders
/// what `listWalletInstances()` returned and calls the two facade methods.
struct DevicesView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @State private var pendingRemoval: WalletInstance?
    @State private var showDeactivateSheet = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    if viewModel.walletInstances.isEmpty {
                        Text(viewModel.devicesLoading
                            ? L10n.string("devices.loading")
                            : L10n.string("devices.empty"))
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(viewModel.walletInstances, id: \.id) { instance in
                            DeviceRow(instance: instance, onRemove: { pendingRemoval = instance })
                        }
                    }
                } header: {
                    Text(L10n.string("devices.title"))
                } footer: {
                    Text(L10n.string("devices.description"))
                }

                if let error = viewModel.devicesError {
                    Section {
                        Text(error).font(.subheadline).foregroundStyle(.red)
                    }
                }

                Section {
                    Button(role: .destructive, action: { showDeactivateSheet = true }) {
                        Text(L10n.string("devices.deactivateButton"))
                    }
                    .disabled(viewModel.deactivating || viewModel.devicesBusyInstanceId != nil)
                } header: {
                    Text(L10n.string("devices.deactivateTitle"))
                } footer: {
                    if let outcome = viewModel.deactivationOutcome {
                        Text(outcome.complete
                            ? L10n.string("devices.deactivateComplete", outcome.revoked)
                            : L10n.string("devices.deactivateIncomplete", outcome.revoked))
                            .foregroundStyle(outcome.complete ? Color.secondary : Color.red)
                    } else {
                        Text(L10n.string("devices.deactivateDescription"))
                    }
                }
            }
            .navigationTitle(L10n.string("devices.title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button(action: { viewModel.closeDevices() }) {
                        Image(systemName: "chevron.left")
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button(action: { viewModel.refreshDevices() }) {
                        Image(systemName: "arrow.clockwise")
                    }
                    .disabled(viewModel.devicesLoading)
                }
            }
            .onAppear { viewModel.refreshDevices() }
            // Revocation is terminal and removing the last instance
            // deactivates the wallet, so it is the one per-row action that
            // asks first - and the confirmation names the device.
            .confirmationDialog(
                L10n.string("devices.removeConfirmTitle"),
                isPresented: Binding(
                    get: { pendingRemoval != nil },
                    set: { if !$0 { pendingRemoval = nil } }
                ),
                titleVisibility: .visible
            ) {
                if let instance = pendingRemoval {
                    Button(L10n.string("devices.remove"), role: .destructive) {
                        viewModel.setWalletInstanceStatus(instanceId: instance.id, status: .revoked)
                        pendingRemoval = nil
                    }
                }
                Button(L10n.string("devices.cancel"), role: .cancel) { pendingRemoval = nil }
            } message: {
                if let instance = pendingRemoval {
                    Text(L10n.string("devices.removeConfirmMessage", instance.deviceLabel))
                }
            }
            .sheet(isPresented: $showDeactivateSheet) {
                DeactivateWalletSheet()
            }
        }
    }
}

private struct DeviceRow: View {
    @EnvironmentObject var viewModel: WalletViewModel
    let instance: WalletInstance
    let onRemove: () -> Void

    private var busy: Bool { viewModel.devicesBusyInstanceId == instance.id }
    private var actionsEnabled: Bool {
        viewModel.devicesBusyInstanceId == nil && !viewModel.deactivating
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(instance.deviceLabel).font(.body).fontWeight(.semibold)
                Spacer()
                StatusPill(status: instance.status)
            }
            if instance.isThisDevice {
                Text(L10n.string("devices.thisDevice"))
                    .font(.caption)
                    .foregroundStyle(Color.accentColor)
            }
            LabeledContent(L10n.string("devices.instanceId"), value: instance.id)
                .font(.caption)
            if !instance.wscdType.isEmpty {
                LabeledContent(L10n.string("devices.wscdType"), value: instance.wscdType).font(.caption)
            }
            if let lastAttested = instance.lastAttestedAt, !lastAttested.isEmpty {
                LabeledContent(L10n.string("devices.lastAttested"), value: lastAttested).font(.caption)
            }
            if let reason = instance.statusReason, !reason.isEmpty {
                LabeledContent(L10n.string("devices.statusReason"), value: reason).font(.caption)
            }

            if busy {
                ProgressView().padding(.top, 4)
            } else {
                HStack(spacing: 12) {
                    switch instance.status {
                    case .active:
                        Button(L10n.string("devices.suspend")) {
                            viewModel.setWalletInstanceStatus(instanceId: instance.id, status: .suspended)
                        }
                        .buttonStyle(.bordered)
                        .disabled(!actionsEnabled)
                    case .suspended:
                        Button(L10n.string("devices.reactivate")) {
                            viewModel.setWalletInstanceStatus(instanceId: instance.id, status: .active)
                        }
                        .buttonStyle(.bordered)
                        .disabled(!actionsEnabled)
                    case .revoked:
                        // Terminal: nothing to offer but the record itself.
                        EmptyView()
                    }
                    // Only for a status this SDK understands. `Status` is a
                    // closed enum today, so `.active`/`.suspended` is the same
                    // set as "not revoked" - written this way so a status a
                    // newer backend introduces is not silently treated as
                    // removable (the Kotlin port, whose status enum is
                    // nullable, had exactly that gap).
                    if instance.status == .active || instance.status == .suspended {
                        Button(L10n.string("devices.remove"), role: .destructive, action: onRemove)
                            .buttonStyle(.bordered)
                            .disabled(!actionsEnabled)
                    }
                }
                .padding(.top, 4)
            }

            // Suspending this device signs it out until someone else
            // reactivates it - the SDK re-logs in after the write and lands in
            // .lifecycleBlocked(.suspended). Say so before the tap, not after.
            if instance.isThisDevice && instance.status == .active {
                Text(L10n.string("devices.suspendSelfWarning"))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
        // The buttons must not each swallow the row's tap.
        .buttonStyle(.borderless)
    }
}

/// The typed confirmation for deactivating the whole wallet, plus the optional
/// reason the backend records on every revoked instance.
private struct DeactivateWalletSheet: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var typed = ""
    @State private var reason = ""

    private var confirmWord: String { L10n.string("devices.deactivateConfirmWord") }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(L10n.string("devices.deactivateConfirmMessage", confirmWord))
                        .font(.subheadline)
                    TextField(confirmWord, text: $typed)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.characters)
                    TextField(L10n.string("devices.reasonOptional"), text: $reason)
                }
                Section {
                    Button(role: .destructive) {
                        viewModel.deactivateWallet(
                            reason: reason.trimmingCharacters(in: .whitespaces).isEmpty
                                ? nil
                                : reason.trimmingCharacters(in: .whitespaces)
                        )
                        dismiss()
                    } label: {
                        Text(L10n.string("devices.deactivateButton"))
                    }
                    .disabled(typed.trimmingCharacters(in: .whitespaces).uppercased() != confirmWord.uppercased())
                }
            }
            .navigationTitle(L10n.string("devices.deactivateConfirmTitle"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button(L10n.string("devices.cancel")) { dismiss() }
                }
            }
        }
    }
}

private struct StatusPill: View {
    let status: WalletInstance.Status

    var body: some View {
        Text(label)
            .font(.caption)
            .padding(.horizontal, 10)
            .padding(.vertical, 2)
            .background(color.opacity(0.12), in: Capsule())
            .foregroundStyle(color)
    }

    private var label: String {
        switch status {
        case .active: return L10n.string("devices.statusActive")
        case .suspended: return L10n.string("devices.statusSuspended")
        case .revoked: return L10n.string("devices.statusRevoked")
        }
    }

    private var color: Color {
        switch status {
        case .active: return .accentColor
        case .suspended: return .orange
        case .revoked: return .red
        }
    }
}

private extension WalletInstance {
    /// Something short enough to name a device in a confirmation dialog. The
    /// backend has no display name for an instance - the id is a JWK
    /// thumbprint - so this is the key storage type when there is one, plus a
    /// truncated id.
    var deviceLabel: String {
        let head = String(id.prefix(10))
        return wscdType.isEmpty ? "\(head)…" : "\(wscdType) · \(head)…"
    }
}

/// The screen for `WalletState.lifecycleBlocked`: the backend refuses this
/// installation and no amount of retrying the same login changes that until
/// someone else acts. A suspended instance can be reactivated from another
/// device, so the offer is to try again later; a revoked wallet is gone, and
/// the only way forward is a new enrollment.
struct WalletBlockedView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    let reason: SirosError.WalletLifecycleRefusal
    let message: String?

    private var suspended: Bool { reason == .suspended }

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: suspended ? "pause.circle" : "xmark.octagon")
                .font(.system(size: 48))
                .foregroundStyle(suspended ? Color.orange : Color.red)
            Text(L10n.string(suspended ? "walletBlocked.suspendedTitle" : "walletBlocked.revokedTitle"))
                .font(.title2)
                .fontWeight(.semibold)
                .multilineTextAlignment(.center)
            // The backend's own text when it sent one - it is written for the
            // user and may say more than the app can (who suspended it, why).
            Text(message ?? L10n.string(suspended ? "walletBlocked.suspendedMessage" : "walletBlocked.revokedMessage"))
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button {
                guard !viewModel.isLoading else { return }
                if suspended {
                    viewModel.login()
                } else {
                    // The account is already forgotten by the time a revoked
                    // wallet reaches here; disconnecting is what puts the app
                    // back on the login/register screen where enrollment starts.
                    viewModel.disconnect()
                }
            } label: {
                Text(L10n.string(suspended ? "walletBlocked.retry" : "walletBlocked.enrollAgain"))
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            // A login is already in flight; the single action here must not
            // start a second - two WebAuthn ceremonies would race.
            .disabled(viewModel.isLoading)
            .padding(.top, 8)
        }
        .padding(32)
    }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosKeystore
import SirosCredentials

struct SettingsView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @State private var showDeleteConfirm = false

    var body: some View {
        NavigationStack {
            List {
                // Account section
                Section("Account") {
                    LabeledContent("Signed in as", value: viewModel.displayName ?? viewModel.userId ?? "—")
                    LabeledContent("Backend", value: viewModel.backendUrl)
                    LabeledContent("Tenant", value: viewModel.tenantId)
                    LabeledContent("Credentials", value: "\(viewModel.credentials.count)")
                    LabeledContent("Transport", value: viewModel.useWmpProtocol ? "WMP (JSON-RPC 2.0)" : "Legacy")
                }

                // Credential consumption policy section
                Section {
                    Picker(selection: $viewModel.credentialConsumptionPolicy) {
                        ForEach(CredentialConsumptionPolicy.allCases, id: \.self) { policy in
                            Text(policy.localizedLabel).tag(policy)
                        }
                    } label: {
                        EmptyView()
                    }
                    .pickerStyle(.inline)
                    .labelsHidden()
                } header: {
                    Text(L10n.string("settings.credentialConsumptionTitle"))
                } footer: {
                    Text(L10n.string("settings.credentialConsumptionDescription"))
                }

                // WSCD key-storage choices (TOFU mapping) section - see
                // `WscdSelectionPolicy`'s doc comment. Read-only display +
                // per-entry/clear-all, matching the credential consumption
                // section's plain-List-row convention above. The actual
                // dev-only `defaultWscdMapping`/multi-plugin toggle lives in
                // `WscaDeveloperView` instead - see its own doc comment for
                // why that split makes sense.
                if !viewModel.wscdTofuMappingSnapshot.isEmpty {
                    Section {
                        ForEach(viewModel.wscdTofuMappingSnapshot.sorted(by: { $0.key < $1.key }), id: \.key) { key, pluginId in
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(key)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                        .lineLimit(1)
                                        .truncationMode(.middle)
                                    Text(pluginId)
                                        .font(.body.weight(.medium))
                                }
                                Spacer()
                                Button(action: { viewModel.clearWscdTofuMapping(forKey: key) }) {
                                    Image(systemName: "xmark.circle")
                                        .foregroundStyle(.secondary)
                                }
                                .buttonStyle(.borderless)
                            }
                        }
                        Button(role: .destructive, action: { viewModel.clearAllWscdTofuMappings() }) {
                            Text("Clear All")
                        }
                    } header: {
                        Text("Security Key Choices")
                    } footer: {
                        Text("Which security key was picked for each credential you've received. Clearing an entry asks again next time.")
                    }
                }

                // Passkeys section
                Section("Passkeys") {
                    if viewModel.passkeys.isEmpty {
                        Text("No passkeys registered")
                            .foregroundStyle(.secondary)
                            .font(.subheadline)
                    } else {
                        ForEach(viewModel.passkeys, id: \.credentialId) { passkey in
                            PasskeyRow(
                                passkey: passkey,
                                onRename: { nickname in
                                    viewModel.renamePasskey(credentialId: passkey.credentialId, nickname: nickname)
                                }
                            )
                        }
                    }
                }

                // Other accounts
                if viewModel.cachedAccounts.count > 1 {
                    Section("Other Accounts") {
                        let otherAccounts = viewModel.cachedAccounts.filter {
                            $0.accountId != "\(viewModel.tenantId):\(viewModel.userId ?? "")"
                        }
                        ForEach(otherAccounts, id: \.accountId) { account in
                            HStack {
                                VStack(alignment: .leading) {
                                    Text(account.displayName)
                                    Text(account.tenantId)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                Button(action: {
                                    viewModel.forgetAccount(account.accountId)
                                }) {
                                    Image(systemName: "xmark")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                .buttonStyle(.borderless)
                            }
                        }
                    }
                }

                // Activity
                Section("Activity") {
                    Button(action: { viewModel.openHistory() }) {
                        HStack {
                            Label("Presentation History", systemImage: "clock")
                            Spacer()
                            Text("\(viewModel.presentationHistory.count)")
                                .foregroundStyle(.secondary)
                        }
                    }
                }

                // WSCD Lifecycle
                Section("WSCD Lifecycle") {
                    LabeledContent("State", value: viewModel.lifecycleState.map(String.init(describing:)) ?? "Not enrolled")

                    Button(action: { viewModel.enrollWscd() }) {
                        HStack {
                            if viewModel.enrollmentInProgress {
                                ProgressView()
                            }
                            Text("Enroll WSCD")
                        }
                    }
                    .disabled(viewModel.enrollmentInProgress || (viewModel.lifecycleState != nil && viewModel.lifecycleState != .destroyed))

                    Button("WSCA Developer") {
                        viewModel.openWscaDeveloper()
                    }
                }

                // Disconnect
                Section {
                    Button(role: .destructive, action: { viewModel.disconnect() }) {
                        Label("Disconnect", systemImage: "rectangle.portrait.and.arrow.right")
                    }

                    Button(role: .destructive, action: { showDeleteConfirm = true }) {
                        Label("Delete Account", systemImage: "trash")
                    }
                    .alert("Delete Account?", isPresented: $showDeleteConfirm) {
                        Button("Delete", role: .destructive) {
                            viewModel.disconnect()
                        }
                        Button("Cancel", role: .cancel) {}
                    } message: {
                        Text("This will remove all local data, credentials, and passkeys. This cannot be undone.")
                    }
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .onAppear {
                viewModel.listPasskeysForUI()
                viewModel.refreshWscdTofuMapping()
            }
        }
    }
}

// MARK: - Passkey Row with inline rename

struct PasskeyRow: View {
    let passkey: CachedPasskey
    let onRename: (String) -> Void

    @State private var editing = false
    @State private var nickname: String

    init(passkey: CachedPasskey, onRename: @escaping (String) -> Void) {
        self.passkey = passkey
        self.onRename = onRename
        _nickname = State(initialValue: passkey.nickname)
    }

    var body: some View {
        if editing {
            HStack {
                TextField("Nickname", text: $nickname)
                    .textFieldStyle(.roundedBorder)
                Button(action: {
                    onRename(nickname)
                    editing = false
                }) {
                    Image(systemName: "checkmark")
                }
                .buttonStyle(.borderless)
                Button(action: {
                    nickname = passkey.nickname
                    editing = false
                }) {
                    Image(systemName: "xmark")
                }
                .buttonStyle(.borderless)
            }
        } else {
            HStack {
                VStack(alignment: .leading) {
                    Text(passkey.nickname.isEmpty ? "Passkey \(passkey.credentialId.prefix(8))..." : passkey.nickname)
                        .font(.body)
                    Text("ID: \(passkey.credentialId.prefix(16))...")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button(action: { editing = true }) {
                    Image(systemName: "pencil")
                        .font(.caption)
                }
                .buttonStyle(.borderless)
            }
        }
    }
}

// Re-export for use in views
import SirosWallet

/// Localized display label for a `CredentialConsumptionPolicy` value.
extension CredentialConsumptionPolicy {
    var localizedLabel: String {
        switch self {
        case .consumeAll: return L10n.string("settings.credentialConsumptionConsumeAll")
        case .consumeNonZkp: return L10n.string("settings.credentialConsumptionConsumeNonZkp")
        case .neverConsume: return L10n.string("settings.credentialConsumptionNeverConsume")
        }
    }
}

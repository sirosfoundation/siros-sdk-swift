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

                // Global user preference - a deliberate "always use X"
                // choice, distinct from the TOFU section above (see
                // `WscdRememberScope`'s doc comment): this is never
                // auto-picked by the SDK, only ever set here or from the
                // choice sheet's "Always" option, and it outranks TOFU for
                // every issuer that doesn't have its own more specific
                // per-issuer override below.
                Section {
                    Picker("Preferred security key", selection: Binding(
                        get: { viewModel.wscdGlobalOverrideSnapshot ?? "" },
                        set: { newValue in
                            if newValue.isEmpty {
                                viewModel.clearWscdGlobalOverride()
                            } else {
                                viewModel.setWscdGlobalOverride(pluginId: newValue)
                            }
                        }
                    )) {
                        Text("No preference").tag("")
                        ForEach(Array(WscdPluginCapabilities.pluginTiers.keys.sorted()), id: \.self) { pluginId in
                            Text(pluginId).tag(pluginId)
                        }
                    }
                } header: {
                    Text("Preferred Security Key")
                } footer: {
                    Text("Always use this security key when it meets a credential's requirement, even if a lower-assurance key would also qualify.")
                }

                // Per-issuer user overrides - distinct from both the TOFU
                // section (auto-remembered) and the global preference above
                // (applies everywhere): each entry here is a deliberate
                // "always use X for this specific issuer" choice that wins
                // over both.
                if !viewModel.wscdUserOverridesSnapshot.isEmpty {
                    Section {
                        ForEach(viewModel.wscdUserOverridesSnapshot.sorted(by: { $0.key < $1.key }), id: \.key) { key, pluginId in
                            let parts = key.split(separator: "|", maxSplits: 1)
                            let issuer = parts.first.map(String.init) ?? key
                            let credentialType = parts.count > 1 ? String(parts[1]) : ""
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(key)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                        .lineLimit(1)
                                        .truncationMode(.middle)
                                    Picker("Security key", selection: Binding(
                                        get: { pluginId },
                                        set: { viewModel.setWscdUserOverride(issuer: issuer, credentialType: credentialType, pluginId: $0) }
                                    )) {
                                        ForEach(Array(WscdPluginCapabilities.pluginTiers.keys.sorted()), id: \.self) { candidate in
                                            Text(candidate).tag(candidate)
                                        }
                                    }
                                    .labelsHidden()
                                    .pickerStyle(.menu)
                                }
                                Spacer()
                                Button(action: { viewModel.clearWscdUserOverride(issuer: issuer, credentialType: credentialType) }) {
                                    Image(systemName: "xmark.circle")
                                        .foregroundStyle(.secondary)
                                }
                                .buttonStyle(.borderless)
                            }
                        }
                    } header: {
                        Text("Per-Issuer Overrides")
                    } footer: {
                        Text("A deliberate choice to always use a specific security key for a specific issuer/credential type - set from the security key prompt's \"This issuer\" option.")
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
                viewModel.refreshWscdUserOverrides()
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

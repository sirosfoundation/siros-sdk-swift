// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosKeystore

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

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosCredentials

/// The settings tree (2026-11-16 review, mirroring the Kotlin sample app's
/// restructure): a menu of sub-screens, one per concern -
///
/// - General (first): the account facts, Appearance, passkeys, other
///   accounts, presentation history.
/// - Security & Trust: reader (RICAL) / issuer (VICAL) trust evaluation
///   (mode pickers + roots) AND the Security Keys (WSCD) entries - the
///   key-storage choices are part of the trust surface.
/// - Credentials: the consumption policy.
/// - Profiles: TS12 transaction data.
/// - Diagnostics: the diagnostic toggles.
/// - Danger Zone: delete account, isolated from everything routine.
///
/// Backends (multi-backend add/switch) and the ISO 18045 assurance-scheme
/// editor are Android-sample-only by design: iOS registers custom URL
/// schemes statically in the Info.plist (universal links in the
/// Associated-Domains entitlement), so a backend added at runtime could
/// never complete its own login round-trip - and the 18045 mapping tables
/// are ecosystem policy no deployment exposes.
struct SettingsView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @State private var showDeleteConfirm = false
    @AppStorage(ThemeMode.storageKey) private var themeMode = ThemeMode.system.rawValue

    var body: some View {
        NavigationStack {
            List {
                // General, first: the account facts, Appearance, passkeys,
                // other accounts, and the presentation history.
                Section {
                    NavigationLink(value: SettingsDestination.general) {
                        Label("General", systemImage: "person.crop.circle")
                    }
                    NavigationLink(value: SettingsDestination.security) {
                        Label("Security & Trust", systemImage: "lock.shield")
                    }
                    NavigationLink(value: SettingsDestination.credentials) {
                        Label("Credentials", systemImage: "creditcard")
                    }
                    NavigationLink(value: SettingsDestination.profiles) {
                        Label("Profiles", systemImage: "doc.badge.gearshape")
                    }
                    NavigationLink(value: SettingsDestination.diagnostics) {
                        Label("Diagnostics", systemImage: "wrench.and.screwdriver")
                    }
                    NavigationLink(value: SettingsDestination.danger) {
                        Label("Danger Zone", systemImage: "exclamationmark.triangle")
                            .foregroundStyle(.red)
                    }
                } header: {
                    Text("Settings")
                }

                // Terminal actions, on the root: not settings groups.
                Section {
                    Button(action: { viewModel.disconnect() }) {
                        Label("Disconnect", systemImage: "rectangle.portrait.and.arrow.right")
                    }
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .navigationDestination(for: SettingsDestination.self) { destination in
                SettingsDestinationView(destination: destination)
                    .environmentObject(viewModel)
            }
            .onAppear {
                viewModel.listPasskeysForUI()
            }
        }
    }
}

/// The settings sub-screens.
enum SettingsDestination: Hashable {
    case general
    case security
    case credentials
    case profiles
    case diagnostics
    case danger
}

/// One sub-screen, routing on the destination.
struct SettingsDestinationView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    let destination: SettingsDestination

    var body: some View {
        Group {
            switch destination {
            case .general: SettingsGeneralView()
            case .security: SettingsSecurityView()
            case .credentials: SettingsCredentialsView()
            case .profiles: SettingsProfilesView()
            case .diagnostics: SettingsDiagnosticsView()
            case .danger: SettingsDangerView()
            }
        }
        .environmentObject(viewModel)
    }
}

// MARK: - General (the account facts + appearance + passkeys + accounts + history)

private struct SettingsGeneralView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @AppStorage(ThemeMode.storageKey) private var themeMode = ThemeMode.system.rawValue

    var body: some View {
        List {
            // Appearance folded into General (2026-11-16): follow the
            // device, or always light, or always dark.
            Section(L10n.string("settings.appearanceSection")) {
                Picker(L10n.string("settings.appearanceSection"), selection: $themeMode) {
                    ForEach(ThemeMode.allCases) { mode in
                        Text(mode.label).tag(mode.rawValue)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .accessibilityIdentifier("settings-appearance")
            }

            // The account facts.
            Section("Account") {
                LabeledContent("Signed in as", value: viewModel.displayName ?? viewModel.userId ?? "—")
                LabeledContent("Backend", value: viewModel.backendUrl)
                LabeledContent("Tenant", value: viewModel.tenantId)
                LabeledContent("ZK Circuit Hosting", value: viewModel.zkCircuitUrls.joined(separator: ", "))
                LabeledContent("Credentials", value: "\(viewModel.credentials.count)")
                LabeledContent("Transport", value: viewModel.useWmpProtocol ? "WMP (JSON-RPC 2.0)" : "Legacy")
                // Which interoperability profiles this wallet can speak.
                // Deliberately a fact, not a control: which one is used is
                // negotiated per issuer from its advertised
                // `cryptographic_binding_methods_supported`.
                LabeledContent(
                    L10n.string("settings.interopProfiles"),
                    value: "HAIP \u{00b7} DIIP \(viewModel.diipProfile.version.uppercased())"
                )
            }

            // Passkeys (in General per the review: account-level facts).
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

            // Other cached accounts.
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

            // Activity: the journal owns the aggregate (see the Kotlin
            // sample's ErrorJournalScreen); the full history is a screen.
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
        }
        .navigationTitle("General")
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - Security & Trust (RICAL/VICAL modes + roots + the WSCD entries)

private struct SettingsSecurityView: View {
    @EnvironmentObject var viewModel: WalletViewModel

    var body: some View {
        List {
            // Reader (RICAL) trust: the mode - the deprecated boolean's full
            // form (LOCAL_ONLY is what that toggle meant; the other two
            // modes were previously unreachable from the UI).
            Section {
                Picker("Reader trust (RICAL)", selection: $viewModel.readerTrustEvaluationMode) {
                    Text("Remote, fall back to local roots").tag(MdocTrustEvaluationMode.remoteWithLocalFallback)
                    Text("Remote only (fail closed)").tag(MdocTrustEvaluationMode.remoteOnly)
                    Text("Local roots only").tag(MdocTrustEvaluationMode.localOnly)
                }
                .pickerStyle(.inline)
                .labelsHidden()
                TextField(
                    "RICAL root certificate (PEM)",
                    text: $viewModel.readerTrustRootCertificatePem,
                    axis: .vertical
                )
                .font(.caption.monospaced())
            } header: {
                Text("Reader Trust (RICAL)")
            } footer: {
                Text("How proximity-reader trust is evaluated, and the local-fallback root.")
            }

            // Issuer (VICAL) trust - previously unexposed entirely.
            Section {
                Picker("Issuer trust (VICAL)", selection: $viewModel.issuerTrustEvaluationMode) {
                    Text("Remote, fall back to local roots").tag(MdocTrustEvaluationMode.remoteWithLocalFallback)
                    Text("Remote only (fail closed)").tag(MdocTrustEvaluationMode.remoteOnly)
                    Text("Local roots only").tag(MdocTrustEvaluationMode.localOnly)
                }
                .pickerStyle(.inline)
                .labelsHidden()
                TextField(
                    "VICAL root certificate (PEM)",
                    text: $viewModel.issuerTrustRootCertificatePem,
                    axis: .vertical
                )
                .font(.caption.monospaced())
            } header: {
                Text("Issuer Trust (VICAL)")
            } footer: {
                Text("How attestation-issuer trust is evaluated - independent of reader trust.")
            }

            // Security Keys folded into Security & Trust (2026-11-16): the
            // key-storage choices are part of the trust surface.
            Section {
                Button(action: { viewModel.openWscaDeveloper() }) {
                    Label("WSCD Settings", systemImage: "key")
                }
            } header: {
                Text("Security Keys (WSCD)")
            } footer: {
                Text("Which secure key storage (software, R2PS remote HSM, or a FIDO2 security key) backs each credential, plus enrollment and developer diagnostics.")
            }
        }
        .navigationTitle("Security & Trust")
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - Credentials (the consumption policy)

private struct SettingsCredentialsView: View {
    @EnvironmentObject var viewModel: WalletViewModel

    var body: some View {
        List {
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

            // Devices (wallet instances) - the credential-access surface.
            Section {
                Button(action: { viewModel.openDevices() }) {
                    Label(L10n.string("devices.manageButton"), systemImage: "iphone")
                }
            } header: {
                Text(L10n.string("devices.title"))
            } footer: {
                Text(L10n.string("devices.description"))
            }
        }
        .navigationTitle("Credentials")
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - Profiles (TS12)

private struct SettingsProfilesView: View {
    @EnvironmentObject var viewModel: WalletViewModel

    var body: some View {
        List {
            // EC TS12 payment SCA: the runtime switch and the log.
            Section {
                Toggle(L10n.string("settings.transactionDataToggle"), isOn: $viewModel.transactionDataEnabled)
                Button(action: { viewModel.openTransactionLog() }) {
                    Label(L10n.string("settings.transactionLogButton"), systemImage: "list.bullet.rectangle")
                }
            } footer: {
                Text(L10n.string("settings.transactionDataDescription"))
            }
        }
        .navigationTitle("Profiles")
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - Diagnostics

private struct SettingsDiagnosticsView: View {
    @EnvironmentObject var viewModel: WalletViewModel

    var body: some View {
        List {
            Section {
                Toggle("Credential details", isOn: $viewModel.showCredentialDetails)
                Toggle("Diagnostic messages", isOn: $viewModel.showDiagnosticMessages)
                Toggle("PhotoID onboarding", isOn: $viewModel.showPhotoIdOnboarding)
            } header: {
                Text("Diagnostics")
            } footer: {
                Text("The message/diagnostic toggles; the error journal is on the menu's Recent messages row.")
            }
        }
        .navigationTitle("Diagnostics")
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - Danger Zone

private struct SettingsDangerView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @State private var showDeleteConfirm = false

    var body: some View {
        List {
            Section {
                Button(role: .destructive, action: { showDeleteConfirm = true }) {
                    Label("Delete Account", systemImage: "trash")
                }
            } header: {
                Text("Danger Zone")
            } footer: {
                Text("Irreversible: delete this account on the backend and wipe this device.")
            }
        }
        .navigationTitle("Danger Zone")
        .navigationBarTitleDisplayMode(.inline)
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
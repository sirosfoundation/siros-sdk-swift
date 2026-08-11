// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosKeystore

/// The three WSCD plugin IDs `FfiWscdConfig(defaultPlugin:)` knows about - one tab each.
private let wscdPluginIds = ["softkey", "r2ps", "fido2"]

/// Single consolidated WSCD settings screen, replacing the old standalone
/// "WSCA Developer" screen (`WscaDeveloperView`, deleted) plus the three
/// separate WSCD-related sections that used to live in `SettingsView`
/// (Security Key Choices/TOFU, Preferred Security Key, Per-Issuer Overrides,
/// WSCD Lifecycle/Enroll) - see the Kotlin sample app's `WscdScreen.kt` doc
/// comment, which is the design spec this file ports. Two parts:
///
/// - A **common section** (always visible, shown once, above the tabs):
///   [WscdMappingCard] (the per-(issuer, credentialType) -> plugin ID
///   mapping table, combining `wscdUserOverridesSnapshot` real preferences
///   with `wscdDefaultMapping` dev-only session entries) and [TofuCard] (the
///   auto-remembered TOFU choices table). Neither is scoped to one plugin,
///   so - unlike the Kotlin reference's own first consolidation pass, since
///   fixed - these are shown once here, not once per tab.
/// - A **plugin-specific sub-group** below: one tab per plugin
///   ([wscdPluginIds]), each with a [PreferredWscdCard] toggle for that
///   plugin and a collapsible "Developer" section (collapsed by default:
///   transport config, lifecycle actions, Stored Keys, Build Info -
///   everything the old standalone WSCA Developer screen had).
///
/// There is exactly one Enroll action app-wide (in the Developer section -
/// diagnostic, not something an end user taps routinely) and exactly one
/// Destroy action/confirmation (in [DeveloperSection]), both previously
/// duplicated between the standalone dev screen and `SettingsView`. Unlike
/// this repo's previous `WscaDeveloperView` (which had separate "Destroy
/// (Local)" and "Destroy + Revoke" buttons), this single Destroy always uses
/// `.remoteRevokeIfSupported` - matching the Kotlin reference's own single
/// `destroyLifecycle()`, which hardcodes the same mode.
///
/// Two deliberate deviations from the Kotlin reference, both because the
/// underlying capability doesn't exist in this SDK yet (out of scope for a
/// sample-app-only port):
/// - No "Discover from TS11 Registry" action - Swift's `SirosCredentials`
///   has no `Ts11RegistryClient`/`Ts11CredentialDiscovery` equivalent yet
///   (Kotlin's `sdk/credentials`), so [WscdMappingCard] only shows saved
///   overrides and dev defaults, not a third "discovered" row origin.
/// - No FIDO2 transport-mode chooser - Swift only has one real CTAP2
///   transport (`NfcCtap2Transport`; no USB HID host mode is available to
///   third-party iOS apps), so there's nothing to choose between, unlike
///   Kotlin's USB/NFC race.
struct WscdSettingsView: View {
    @EnvironmentObject var viewModel: WalletViewModel

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    // Common section - neither card is scoped to one plugin.
                    WscdMappingCard()
                    TofuCard()

                    Divider()
                    Text("WSCD Plugin")
                        .font(.subheadline)
                        .fontWeight(.semibold)

                    Picker("Plugin", selection: Binding(
                        get: { viewModel.selectedPluginId },
                        set: { viewModel.selectPlugin($0) }
                    )) {
                        ForEach(wscdPluginIds, id: \.self) { pluginId in
                            Text(pluginId).tag(pluginId)
                        }
                    }
                    .pickerStyle(.segmented)

                    PluginSpecificSection()
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            }
            .navigationTitle("WSCD Settings")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button(action: { viewModel.closeWscaDeveloper() }) {
                        Image(systemName: "chevron.left")
                    }
                }
            }
            .onAppear {
                viewModel.refreshWscdTofuMapping()
                viewModel.refreshWscdUserOverrides()
                viewModel.refreshWscdInfo()
            }
        }
    }
}

// MARK: - Plugin-specific sub-group

/// One plugin tab's genuinely plugin-specific content: the "Preferred WSCD"
/// toggle, then the collapsible Developer section - the Mapping/TOFU cards
/// that used to live here too were hoisted out to `WscdSettingsView`'s
/// common section (see that struct's doc comment for why).
private struct PluginSpecificSection: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @State private var developerExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            PreferredWscdCard()

            DisclosureGroup("Developer", isExpanded: $developerExpanded) {
                DeveloperSection()
                    .padding(.top, 8)
            }
            .font(.subheadline.weight(.semibold))
        }
        // Mirrors the Kotlin reference's `rememberSaveable(pluginId)` -
        // switching tabs always starts the Developer section collapsed
        // again, rather than leaving whichever tab was expanded before.
        .onChange(of: viewModel.selectedPluginId) { _ in
            developerExpanded = false
        }
    }
}

/// "Always use this WSCD, even for credentials that don't require it" - a
/// single per-plugin toggle (each tab now already IS one plugin). Turning
/// this ON makes the current tab's plugin the sole global override (any
/// other plugin previously preferred is implicitly replaced, matching
/// `setWscdGlobalOverride`'s "one value" semantics); turning it OFF clears
/// the override entirely (only meaningful when this plugin IS the current
/// override).
private struct PreferredWscdCard: View {
    @EnvironmentObject var viewModel: WalletViewModel

    var body: some View {
        let pluginId = viewModel.selectedPluginId
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Preferred WSCD")
                        .font(.subheadline)
                        .fontWeight(.semibold)
                        .foregroundStyle(.secondary)
                    Text("Always use \(pluginId), even for credentials that don't require it. Applies to every issuer unless a per-issuer override below takes precedence.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Toggle("", isOn: Binding(
                    get: { viewModel.wscdGlobalOverrideSnapshot == pluginId },
                    set: { checked in
                        if checked {
                            viewModel.setWscdGlobalOverride(pluginId: pluginId)
                        } else {
                            viewModel.clearWscdGlobalOverride()
                        }
                    }
                ))
                .labelsHidden()
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(.secondarySystemBackground))
        )
    }
}

// MARK: - Common section: Mapping + TOFU

/// The per-(issuer, credentialType) -> plugin ID mapping, combining two row
/// origins in one list/card (see `WscdSettingsView`'s doc comment for why
/// there's no third "discovered" origin here, unlike the Kotlin reference):
/// - A row for every `wscdUserOverridesSnapshot` entry ("Saved") - a real,
///   persisted preference; removing it calls `clearWscdUserOverride`.
/// - A row for every `wscdDefaultMapping` entry ("Dev default") - a
///   session-only `WalletConfig.defaultWscdMapping` entry (added via the
///   Developer section's own form below, since it requires a
///   `wscdMultiPluginEnabled` reconnect to take effect); removing it calls
///   `removeWscdDefaultMapping`.
///
/// Shown once, in `WscdSettingsView`'s common section above the plugin tabs
/// - this is a single global resolution table, not scoped to any one plugin.
private struct WscdMappingCard: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @State private var showAddOverride = false
    @State private var newIssuer = ""
    @State private var newCredentialType = ""
    @State private var newPluginId = wscdPluginIds[0]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Mapping")
                .font(.subheadline)
                .fontWeight(.semibold)
                .foregroundStyle(.secondary)
            Text("Which (issuer, credential type) pairs always use a specific WSCD plugin. \"Saved\" rows are real per-issuer preferences (also set from the security-key prompt's \"This issuer\" option); \"Dev default\" rows are session-only entries added in a plugin tab's Developer section below.")
                .font(.caption)
                .foregroundStyle(.secondary)

            if viewModel.wscdUserOverridesSnapshot.isEmpty && viewModel.wscdDefaultMapping.isEmpty {
                Text("No mapping entries yet")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(viewModel.wscdUserOverridesSnapshot.sorted(by: { $0.key < $1.key }), id: \.key) { key, pluginId in
                    let parts = splitMappingKey(key)
                    MappingRow(
                        title: parts.credentialType,
                        subtitle: parts.issuer,
                        technical: "Saved · → \(pluginId)",
                        technicalColor: .accentColor,
                        onRemove: { viewModel.clearWscdUserOverride(issuer: parts.issuer, credentialType: parts.credentialType) }
                    )
                }
                ForEach(Array(viewModel.wscdDefaultMapping.keys.sorted()), id: \.self) { key in
                    if let pluginId = viewModel.wscdDefaultMapping[key] {
                        let parts = splitMappingKey(key)
                        MappingRow(
                            title: parts.credentialType,
                            subtitle: parts.issuer,
                            technical: "Dev default · → \(pluginId)",
                            technicalColor: .secondary,
                            onRemove: { viewModel.removeWscdDefaultMapping(key: key) }
                        )
                    }
                }
            }

            if showAddOverride {
                VStack(alignment: .leading, spacing: 8) {
                    TextField("Issuer URL", text: $newIssuer)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    TextField("Credential type (vct/doctype)", text: $newCredentialType)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    HStack(spacing: 8) {
                        ForEach(wscdPluginIds, id: \.self) { pluginId in
                            PluginChip(label: pluginId, isSelected: newPluginId == pluginId, action: { newPluginId = pluginId })
                        }
                    }
                    HStack(spacing: 8) {
                        Button("Add") {
                            viewModel.setWscdUserOverride(
                                issuer: newIssuer.trimmingCharacters(in: .whitespacesAndNewlines),
                                credentialType: newCredentialType.trimmingCharacters(in: .whitespacesAndNewlines),
                                pluginId: newPluginId
                            )
                            newIssuer = ""
                            newCredentialType = ""
                            showAddOverride = false
                        }
                        .buttonStyle(.bordered)
                        .disabled(newIssuer.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                            || newCredentialType.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                        Button("Cancel") { showAddOverride = false }
                            .buttonStyle(.bordered)
                    }
                }
            } else {
                Button("Add override") { showAddOverride = true }
                    .buttonStyle(.bordered)
                    .frame(maxWidth: .infinity)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(.secondarySystemBackground))
        )
    }
}

/// The single global auto-remembered trust-on-first-use choices (see
/// `WscdSelectionPolicy`'s doc comment) - same `"issuer|credentialType"` ->
/// plugin ID shape as [WscdMappingCard]'s data, and, like that card, not
/// scoped to any one plugin, so it's shown once here rather than filtered
/// per tab.
private struct TofuCard: View {
    @EnvironmentObject var viewModel: WalletViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("WSCD Choices")
                    .font(.subheadline)
                    .fontWeight(.semibold)
                    .foregroundStyle(.secondary)
                Spacer()
                if !viewModel.wscdTofuMappingSnapshot.isEmpty {
                    Button("Forget All") { viewModel.clearAllWscdTofuMappings() }
                        .font(.caption)
                }
            }
            Text("Ambiguous-choice outcomes remembered per (issuer, credential type), so you're only asked once. Forget a choice to be asked again next time.")
                .font(.caption)
                .foregroundStyle(.secondary)

            if viewModel.wscdTofuMappingSnapshot.isEmpty {
                Text("No WSCD choices remembered yet")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(viewModel.wscdTofuMappingSnapshot.sorted(by: { $0.key < $1.key }), id: \.key) { key, pluginId in
                    let parts = splitMappingKey(key)
                    MappingRow(
                        title: parts.credentialType,
                        subtitle: parts.issuer,
                        technical: "→ \(pluginId)",
                        technicalColor: .accentColor,
                        onRemove: { viewModel.clearWscdTofuMapping(forKey: key) }
                    )
                }
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Color(.secondarySystemBackground))
        )
    }
}

/// One mapping/TOFU entry: a primary label, a secondary detail line, a small
/// technical line, and a trailing remove button. Shared by [WscdMappingCard]
/// and [TofuCard].
private struct MappingRow: View {
    let title: String
    let subtitle: String
    let technical: String
    let technicalColor: Color
    let onRemove: () -> Void

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.body)
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text(technical)
                    .font(.caption2)
                    .fontWeight(.semibold)
                    .foregroundStyle(technicalColor)
            }
            Spacer()
            Button(action: onRemove) {
                Image(systemName: "xmark.circle")
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.borderless)
        }
        .padding(.vertical, 4)
    }
}

/// Splits a `"issuer|credentialType"` mapping key back into its two parts
/// (see `WscdSelectionPolicy.tofuKey`) - ports the Kotlin reference's
/// `splitMappingKey` free function.
private func splitMappingKey(_ key: String) -> (issuer: String, credentialType: String) {
    let parts = key.split(separator: "|", maxSplits: 1)
    let issuer = parts.first.map(String.init) ?? key
    let credentialType = parts.count > 1 ? String(parts[1]) : ""
    return (issuer, credentialType)
}

// MARK: - Developer section

/// Everything that used to live in the standalone "WSCA Developer" screen:
/// transport config, lifecycle status/actions, Stored Keys, Build Info.
/// Collapsed by default behind [PluginSpecificSection]'s "Developer"
/// disclosure group - this is diagnostic/test content, not a thing an end
/// user needs routinely.
///
/// Owns the single app-wide Destroy confirmation (`showDestroyConfirm`) -
/// destroying a WSCD key is not reversible, and there's only one Destroy
/// action now (previously duplicated between the standalone dev screen's
/// "Destroy (Local)"/"Destroy + Revoke" buttons and nothing in Settings).
/// Always uses `.remoteRevokeIfSupported`, matching the Kotlin reference's
/// own single `destroyLifecycle()` (whether that also revokes anything
/// server-side is up to the active plugin's own destroy hook - fido2 has no
/// remote to revoke, r2ps does).
private struct DeveloperSection: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @State private var showDestroyConfirm = false
    @State private var newMappingIssuer = ""
    @State private var newMappingCredentialType = ""
    @State private var newMappingPluginId = "fido2"

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            // ── Build Info ──────────────────────────────────
            sectionHeader("Build Info")
            infoCard {
                infoRow("App Version", "0.1.0")
                infoRow("Platform", "iOS")
                infoRow("WSCD Manager", "siros-wscd-manager (UniFFI)")
            }

            // ── Transport / plugin-specific config ───────────
            if viewModel.selectedPluginId == "r2ps" {
                sectionHeader("R2PS Server")
                TextField("R2PS Server URL", text: $viewModel.r2psServerUrl)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                // No real R2PS dev server key is wired into this sample app
                // yet (see `r2psServerPublicKeyPem`'s doc comment) - left
                // blank by default rather than silently reusing the
                // client's own key, which would be actively wrong.
                TextField("R2PS Server Public Key (PEM)", text: $viewModel.r2psServerPublicKeyPem, axis: .vertical)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .font(.caption.monospaced())
                    .lineLimit(3...6)
                if viewModel.r2psServerPublicKeyPem.isEmpty {
                    Text("No server public key configured - R2PS registration will fail until one is provided.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }

            // ── WSCD Selection Policy (dev config) ───────────
            sectionHeader("WSCD Selection Policy")
            infoCard {
                Toggle("Enable multi-plugin selection", isOn: $viewModel.wscdMultiPluginEnabled)
                    .font(.subheadline)
                Text("Requires reconnecting to take effect.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            if viewModel.wscdMultiPluginEnabled {
                Text("Default Mapping (dev, session-only)")
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundStyle(.secondary)
                Text("Adds a WalletConfig.defaultWscdMapping entry - see the Mapping card above the tabs for the full, unfiltered table across ALL plugins. Host-app/dev config, not persisted across restarts.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)

                VStack(alignment: .leading, spacing: 8) {
                    TextField("Issuer URL", text: $newMappingIssuer)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    TextField("Credential type (vct/doctype)", text: $newMappingCredentialType)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    HStack(spacing: 8) {
                        ForEach(wscdPluginIds, id: \.self) { pluginId in
                            PluginChip(
                                label: pluginId,
                                isSelected: newMappingPluginId == pluginId,
                                action: { newMappingPluginId = pluginId }
                            )
                        }
                    }
                    Button("Add Mapping") {
                        viewModel.addWscdDefaultMapping(
                            issuer: newMappingIssuer,
                            credentialType: newMappingCredentialType,
                            pluginId: newMappingPluginId
                        )
                        newMappingIssuer = ""
                        newMappingCredentialType = ""
                    }
                    .buttonStyle(.bordered)
                    .disabled(newMappingIssuer.isEmpty || newMappingCredentialType.isEmpty)
                }
            }

            // ── Lifecycle Status ──────────────────────────────
            sectionHeader("Lifecycle Status")
            infoCard {
                infoRow("State", viewModel.lifecycleState.map(String.init(describing:)) ?? "Not enrolled")
                if let status = viewModel.lifecycleStatus {
                    infoRow("Context ID", status.contextId)
                    infoRow("Plugin", status.pluginId)
                    infoRow("Factor Kind", String(describing: status.factorKind))
                    infoRow("Updated", formatTimestamp(status.updatedAt))
                }
            }

            // ── Lifecycle Actions ─────────────────────────────
            Button(action: { viewModel.enrollWscd() }) {
                HStack {
                    if viewModel.enrollmentInProgress {
                        ProgressView()
                            .tint(.white)
                    }
                    Text("Enroll (\(viewModel.selectedPluginId))")
                }
                .frame(maxWidth: .infinity)
                .frame(height: 44)
            }
            .buttonStyle(.borderedProminent)
            .disabled(
                viewModel.enrollmentInProgress ||
                (viewModel.lifecycleState != nil && viewModel.lifecycleState != .destroyed)
            )

            HStack(spacing: 8) {
                Button("Rotate Keys") {
                    viewModel.rotateLifecycle()
                }
                .buttonStyle(.borderedProminent)
                .frame(maxWidth: .infinity)
                .frame(height: 44)
                .disabled(viewModel.lifecycleState != .active)

                Button("Destroy") {
                    showDestroyConfirm = true
                }
                .buttonStyle(.bordered)
                .tint(.red)
                .frame(maxWidth: .infinity)
                .frame(height: 44)
                .disabled(viewModel.lifecycleState == nil || viewModel.lifecycleState == .destroyed)
            }

            Button("Refresh") {
                viewModel.refreshWscdInfo()
            }
            .buttonStyle(.bordered)
            .frame(maxWidth: .infinity)
            .frame(height: 44)

            // ── Keys ───────────────────────────────────────────
            sectionHeader("Stored Keys (\(viewModel.wscdKeys.count))")
            if viewModel.wscdKeys.isEmpty {
                infoCard {
                    Text("No keys stored")
                        .foregroundStyle(.secondary)
                }
            } else {
                infoCard {
                    ForEach(Array(viewModel.wscdKeys.enumerated()), id: \.element.keyId) { index, key in
                        if index > 0 {
                            Divider()
                        }
                        keyInfoRow(key)
                    }
                }
            }
        }
        .alert("Destroy this key?", isPresented: $showDestroyConfirm) {
            Button("Destroy", role: .destructive) {
                viewModel.destroyLifecycle(mode: .remoteRevokeIfSupported)
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This permanently destroys the enrolled key and any keys derived from it, locally and on the backend if the active plugin supports remote revocation. This cannot be undone.")
        }
    }

    // MARK: - Helpers

    @ViewBuilder
    private func sectionHeader(_ title: String) -> some View {
        Text(title)
            .font(.subheadline)
            .fontWeight(.semibold)
    }

    @ViewBuilder
    private func infoCard(@ViewBuilder content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            content()
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(Color(.secondarySystemBackground))
        )
    }

    @ViewBuilder
    private func infoRow(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label)
                .foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .fontWeight(.medium)
        }
        .font(.subheadline)
    }

    @ViewBuilder
    private func keyInfoRow(_ key: SignerKeyInfo) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(key.keyId)
                .font(.caption)
                .monospaced()
                .lineLimit(1)
            HStack(spacing: 16) {
                Text(key.algorithm)
                    .font(.caption2)
                    .foregroundStyle(.blue)
            }
            if let props = viewModel.wscdKeySecurityProps[key.keyId] {
                HStack(spacing: 16) {
                    Text("Storage: \(props.keyStorage.joined(separator: ", "))")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    Text("Cert: \(certificationText(props.certification))")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                if !props.userAuthentication.isEmpty {
                    Text("Auth: \(props.userAuthentication.joined(separator: ", "))")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                if !props.amr.isEmpty {
                    Text("AMR: \(props.amr.joined(separator: ", "))")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding(.vertical, 4)
    }

    private func certificationText(_ cert: CertificationInfo) -> String {
        switch cert {
        case .none:
            return "none"
        case .certified(let scheme, let level):
            return "\(scheme) (\(level))"
        }
    }

    private func formatTimestamp(_ epochMs: Int64) -> String {
        if epochMs == 0 { return "—" }
        let date = Date(timeIntervalSince1970: Double(epochMs) / 1000.0)
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm"
        return formatter.string(from: date)
    }
}

// MARK: - Plugin selection chip

private struct PluginChip: View {
    let label: String
    let isSelected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(label)
                .font(.subheadline)
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(
                    RoundedRectangle(cornerRadius: 8)
                        .fill(isSelected ? Color.accentColor : Color.clear)
                )
                .foregroundColor(isSelected ? .white : .accentColor)
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(Color.accentColor, lineWidth: 1)
                )
        }
        .buttonStyle(.plain)
    }
}

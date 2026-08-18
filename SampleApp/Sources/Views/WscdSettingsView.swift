// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosKeystore
import SirosCredentials
import SirosWallet

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
///   mapping table, combining `wscdUserOverridesSnapshot` real preferences,
///   `wscdDefaultMapping` dev-only session entries, and now
///   `Ts11CredentialDiscovery`-sourced candidates from `registry.siros.org`
///   - see that struct's doc comment) and [TofuCard] (the auto-remembered
///   TOFU choices table). Neither is scoped to one plugin, so - unlike the
///   Kotlin reference's own first consolidation pass, since fixed - these
///   are shown once here, not once per tab.
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
/// One remaining deliberate deviation from the Kotlin reference, because the
/// underlying capability doesn't exist in this SDK (out of scope for a
/// sample-app-only port): no FIDO2 transport-mode chooser - Swift only has
/// one real CTAP2 transport (`NfcCtap2Transport`; no USB HID host mode is
/// available to third-party iOS apps), so there's nothing to choose between,
/// unlike Kotlin's USB/NFC race.
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
                    Text(L10n.string("wscd.pluginPickerSection"))
                        .font(.subheadline)
                        .fontWeight(.semibold)

                    Picker(L10n.string("wscd.pluginLabel"), selection: Binding(
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
            .navigationTitle(L10n.string("wscd.settingsTitle"))
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

            DisclosureGroup(L10n.string("common.developer"), isExpanded: $developerExpanded) {
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
                    Text(L10n.string("wscd.preferredWscdTitle"))
                        .font(.subheadline)
                        .fontWeight(.semibold)
                        .foregroundStyle(.secondary)
                    Text(L10n.string("wscd.preferredWscdDescription", pluginId))
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

// MARK: - Common section: Mapping + Discovery + TOFU

/// The per-(issuer, credentialType) -> plugin ID mapping, combining three row
/// origins in one list/card - now including TS11 registry discovery,
/// matching the Kotlin reference's own combined "Mapping & Discovery" widget
/// (an earlier version of both apps kept Discovery and Mapping as two
/// separate cards, which meant tapping "Add" on a discovered candidate gave
/// no visible feedback in the Mapping card without scrolling to it):
/// - A row for every `viewModel.ts11DiscoveredCredentials` entry (see
///   `Ts11CredentialDiscovery`) is STICKY - it stays in the list once
///   discovered regardless of whether it's currently mapped, since discovery
///   state is independent of mapping state. Its `Toggle` calls
///   `setWscdUserOverride`/`clearWscdUserOverride` using the wildcard issuer
///   `"*"` (see below) and the cheapest plugin whose nominal tier satisfies
///   the credential's declared `attestationLoS` (`bestPluginFor`) - "Add"
///   from an earlier Discovery-only card is now just switching a row on.
///   Credentials with no plugin able to satisfy their tier are dropped
///   entirely (nothing to offer a switch for).
/// - A row for every `wscdUserOverridesSnapshot` entry not already shown as
///   a discovered row ("Saved") - a real, persisted preference; removing it
///   calls `clearWscdUserOverride`.
/// - A row for every `wscdDefaultMapping` entry not already covered above
///   ("Dev default") - a session-only `WalletConfig.defaultWscdMapping`
///   entry (added via the Developer section's own form below, since it
///   requires a `wscdMultiPluginEnabled` reconnect to take effect); removing
///   it calls `removeWscdDefaultMapping`.
///
/// NOTE: a TS11 schema entry has no issuer of its own (it describes a
/// credential *type*, not an (issuer, credentialType) pair), so discovered
/// rows are mapped using the wildcard issuer `"*"` - "use this plugin for
/// this credential type, regardless of issuer." `WscdSelectionPolicy.resolve`
/// explicitly interprets that placeholder as a fallback when no
/// issuer-specific entry matches, so switching a discovered row on resolves
/// end-to-end immediately, not just as a hand-edit starting point.
///
/// Shown once, in `WscdSettingsView`'s common section above the plugin tabs
/// - this is a single global resolution table, not scoped to any one plugin.
private struct WscdMappingCard: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @State private var showAddOverride = false
    @State private var newIssuer = ""
    @State private var newCredentialType = ""
    @State private var newPluginId = wscdPluginIds[0]

    /// identifier -> cheapest-sufficient plugin, dropping any discovered
    /// credential with no required tier or no plugin able to satisfy it.
    private var discoveredByIdentifier: [String: (Ts11DiscoveredCredential, String)] {
        var result: [String: (Ts11DiscoveredCredential, String)] = [:]
        for dc in viewModel.ts11DiscoveredCredentials {
            guard let requiredTier = dc.schema.attestationLoS, let pluginId = bestPluginFor(requiredTier) else { continue }
            result[dc.identifier] = (dc, pluginId)
        }
        return result
    }

    var body: some View {
        let discovered = discoveredByIdentifier
        let discoveredKeys = Set(discovered.keys.map { "\(WscdSelectionPolicy.wildcardIssuer)|\($0)" })
        let savedOnly = viewModel.wscdUserOverridesSnapshot.keys.filter { !discoveredKeys.contains($0) }
        let devDefaultOnly = viewModel.wscdDefaultMapping.keys.filter { !discoveredKeys.contains($0) }

        VStack(alignment: .leading, spacing: 8) {
            Text(L10n.string("wscd.mappingTitle"))
                .font(.subheadline)
                .fontWeight(.semibold)
                .foregroundStyle(.secondary)
            Text(L10n.string("wscd.mappingDescription"))
                .font(.caption)
                .foregroundStyle(.secondary)

            Button(action: { viewModel.discoverTs11Schemas() }) {
                HStack {
                    if viewModel.ts11DiscoveryInProgress {
                        ProgressView()
                            .controlSize(.small)
                    }
                    Text(L10n.string("wscd.discoverButton"))
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .disabled(viewModel.ts11DiscoveryInProgress)

            if discovered.isEmpty && savedOnly.isEmpty && devDefaultOnly.isEmpty {
                Text(L10n.string("wscd.mappingEmpty"))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(discovered.keys.sorted(), id: \.self) { identifier in
                    if let (dc, pluginId) = discovered[identifier] {
                        let key = "\(WscdSelectionPolicy.wildcardIssuer)|\(identifier)"
                        // If this row was already turned on with a custom
                        // plugin (e.g. hand-edited via "Add override" for the
                        // same wildcard identifier), reflect what's actually
                        // saved rather than the raw discovery suggestion.
                        let effectivePluginId = viewModel.wscdUserOverridesSnapshot[key] ?? pluginId
                        DiscoveredMappingRow(
                            title: dc.displayName,
                            subtitle: dc.description ?? L10n.string("wscd.mappingDiscoveredAnyIssuer"),
                            technical: "\(dc.schema.attestationLoS ?? "?") → \(effectivePluginId) · \(identifier)",
                            technicalColor: .accentColor,
                            isOn: viewModel.wscdUserOverridesSnapshot[key] != nil,
                            onToggle: { isOn in
                                if isOn {
                                    viewModel.setWscdUserOverride(issuer: WscdSelectionPolicy.wildcardIssuer, credentialType: identifier, pluginId: pluginId)
                                } else {
                                    viewModel.clearWscdUserOverride(issuer: WscdSelectionPolicy.wildcardIssuer, credentialType: identifier)
                                }
                            }
                        )
                    }
                }
                ForEach(savedOnly.sorted(), id: \.self) { key in
                    let parts = splitMappingKey(key)
                    MappingRow(
                        title: parts.credentialType,
                        subtitle: parts.issuer,
                        technical: L10n.string("wscd.mappingSavedTechnical", viewModel.wscdUserOverridesSnapshot[key] ?? ""),
                        technicalColor: .accentColor,
                        onRemove: { viewModel.clearWscdUserOverride(issuer: parts.issuer, credentialType: parts.credentialType) }
                    )
                }
                ForEach(devDefaultOnly.sorted(), id: \.self) { key in
                    if let pluginId = viewModel.wscdDefaultMapping[key] {
                        let parts = splitMappingKey(key)
                        MappingRow(
                            title: parts.credentialType,
                            subtitle: parts.issuer,
                            technical: L10n.string("wscd.mappingDevDefaultTechnical", pluginId),
                            technicalColor: .secondary,
                            onRemove: { viewModel.removeWscdDefaultMapping(key: key) }
                        )
                    }
                }
            }

            if showAddOverride {
                VStack(alignment: .leading, spacing: 8) {
                    TextField(L10n.string("wscd.issuerUrlPlaceholder"), text: $newIssuer)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    TextField(L10n.string("wscd.credentialTypePlaceholder"), text: $newCredentialType)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    HStack(spacing: 8) {
                        ForEach(wscdPluginIds, id: \.self) { pluginId in
                            PluginChip(label: pluginId, isSelected: newPluginId == pluginId, action: { newPluginId = pluginId })
                        }
                    }
                    HStack(spacing: 8) {
                        Button(L10n.string("wscd.addButton")) {
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
                        Button(L10n.string("common.cancel")) { showAddOverride = false }
                            .buttonStyle(.bordered)
                    }
                }
            } else {
                Button(L10n.string("wscd.addOverrideButton")) { showAddOverride = true }
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
                Text(L10n.string("wscd.tofuTitle"))
                    .font(.subheadline)
                    .fontWeight(.semibold)
                    .foregroundStyle(.secondary)
                Spacer()
                if !viewModel.wscdTofuMappingSnapshot.isEmpty {
                    Button(L10n.string("wscd.forgetAllButton")) { viewModel.clearAllWscdTofuMappings() }
                        .font(.caption)
                }
            }
            Text(L10n.string("wscd.tofuDescription"))
                .font(.caption)
                .foregroundStyle(.secondary)

            if viewModel.wscdTofuMappingSnapshot.isEmpty {
                Text(L10n.string("wscd.tofuEmpty"))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(viewModel.wscdTofuMappingSnapshot.sorted(by: { $0.key < $1.key }), id: \.key) { key, pluginId in
                    let parts = splitMappingKey(key)
                    MappingRow(
                        title: parts.credentialType,
                        subtitle: parts.issuer,
                        technical: L10n.string("wscd.tofuTechnical", pluginId),
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

/// One TS11-discovered candidate row: same layout as [MappingRow] but with a
/// trailing on/off `Toggle` instead of a remove button, since discovered
/// rows are STICKY (see [WscdMappingCard]'s doc comment) - they stay in the
/// list regardless of the toggle's state.
private struct DiscoveredMappingRow: View {
    let title: String
    let subtitle: String
    let technical: String
    let technicalColor: Color
    let isOn: Bool
    let onToggle: (Bool) -> Void

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
            Toggle("", isOn: Binding(get: { isOn }, set: onToggle))
                .labelsHidden()
        }
        .padding(.vertical, 4)
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

/// Tie-break order used by `bestPluginFor` when two plugins tie on nominal
/// tier rank. Prefers a plugin that's genuinely real/local over one whose
/// assurance is a config-dependent placeholder: `WscdPluginCapabilities`'s
/// doc comment explicitly documents `r2ps`'s "high" tier as best-effort/
/// config-dependent, not a guarantee, whereas `fido2` is a real
/// hardware-backed authenticator. Ports Kotlin's `PLUGIN_TIE_BREAK_ORDER` -
/// a real bug found there via live testing, where every high-tier discovered
/// credential silently defaulted to `r2ps` because it happened to come
/// first in `wscdPluginIds` and Kotlin's `minWithOrNull` breaks ties by
/// iteration order. `softkey` never actually ties with either (it's the
/// only "basic" plugin), so its position here is arbitrary but harmless.
private let pluginTieBreakOrder = ["softkey", "fido2", "r2ps"]

/// The cheapest known plugin ID whose `WscdPluginCapabilities` nominal tier
/// meets `requiredTier`, or `nil` if none does (either an unrecognized tier
/// string, or every known plugin's tier falls short). Ports Kotlin's
/// `bestPluginFor`, used by [WscdMappingCard] to auto-assign a plugin to
/// each TS11-discovered credential rather than defaulting to whichever
/// plugin tab happens to be open.
private func bestPluginFor(_ requiredTier: String) -> String? {
    wscdPluginIds
        .compactMap { pluginId -> (id: String, tier: String)? in
            guard let tier = WscdPluginCapabilities.tier(forPluginId: pluginId) else { return nil }
            return (pluginId, tier)
        }
        .filter { WscdPluginCapabilities.meets(actual: $0.tier, required: requiredTier) }
        .min { lhs, rhs in
            let lhsRank = WscdPluginCapabilities.tierOrder.firstIndex(of: lhs.tier) ?? Int.max
            let rhsRank = WscdPluginCapabilities.tierOrder.firstIndex(of: rhs.tier) ?? Int.max
            if lhsRank != rhsRank { return lhsRank < rhsRank }
            let lhsTieBreak = pluginTieBreakOrder.firstIndex(of: lhs.id) ?? Int.max
            let rhsTieBreak = pluginTieBreakOrder.firstIndex(of: rhs.id) ?? Int.max
            return lhsTieBreak < rhsTieBreak
        }
        .map(\.id)
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
            sectionHeader(L10n.string("wscd.buildInfo"))
            infoCard {
                infoRow(L10n.string("wscd.appVersion"), "0.1.0")
                infoRow(L10n.string("wscd.platform"), "iOS")
                infoRow(L10n.string("wscd.wscdManagerLabel"), L10n.string("wscd.wscdManager"))
            }

            // ── Transport / plugin-specific config ───────────
            if viewModel.selectedPluginId == "r2ps" {
                sectionHeader(L10n.string("wscd.r2psServerSection"))
                TextField(L10n.string("wscd.r2psServerUrlPlaceholder"), text: $viewModel.r2psServerUrl)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                // No real R2PS dev server key is wired into this sample app
                // yet (see `r2psServerPublicKeyPem`'s doc comment) - left
                // blank by default rather than silently reusing the
                // client's own key, which would be actively wrong.
                TextField(L10n.string("wscd.r2psServerPublicKeyPlaceholder"), text: $viewModel.r2psServerPublicKeyPem, axis: .vertical)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .font(.caption.monospaced())
                    .lineLimit(3...6)
                if viewModel.r2psServerPublicKeyPem.isEmpty {
                    Text(L10n.string("wscd.r2psNoPublicKeyWarning"))
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }

            // ── WSCD Selection Policy (dev config) ───────────
            sectionHeader(L10n.string("wscd.selectionPolicySection"))
            infoCard {
                Toggle(L10n.string("wscd.multiPluginToggle"), isOn: $viewModel.wscdMultiPluginEnabled)
                    .font(.subheadline)
                Text(L10n.string("wscd.requiresReconnect"))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            if viewModel.wscdMultiPluginEnabled {
                Text(L10n.string("wscd.defaultMappingSection"))
                    .font(.caption)
                    .fontWeight(.semibold)
                    .foregroundStyle(.secondary)
                Text(L10n.string("wscd.defaultMappingDescription"))
                    .font(.caption2)
                    .foregroundStyle(.secondary)

                VStack(alignment: .leading, spacing: 8) {
                    TextField(L10n.string("wscd.issuerUrlPlaceholder"), text: $newMappingIssuer)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    TextField(L10n.string("wscd.credentialTypePlaceholder"), text: $newMappingCredentialType)
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
                    Button(L10n.string("wscd.addMappingButton")) {
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
            sectionHeader(L10n.string("wscd.lifecycleStatus"))
            infoCard {
                infoRow(L10n.string("wscd.stateLabel"), viewModel.lifecycleState.map(String.init(describing:)) ?? L10n.string("settings.wscdNotEnrolled"))
                if let status = viewModel.lifecycleStatus {
                    infoRow(L10n.string("wscd.contextId"), status.contextId)
                    infoRow(L10n.string("wscd.pluginLabel"), status.pluginId)
                    infoRow(L10n.string("wscd.factorKind"), String(describing: status.factorKind))
                    infoRow(L10n.string("wscd.updatedLabel"), formatTimestamp(status.updatedAt))
                }
            }

            // ── Lifecycle Actions ─────────────────────────────
            Button(action: { viewModel.enrollWscd() }) {
                HStack {
                    if viewModel.enrollmentInProgress {
                        ProgressView()
                            .tint(.white)
                    }
                    Text(L10n.string("wscd.enrollButton", viewModel.selectedPluginId))
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
                Button(L10n.string("wscd.rotateButton")) {
                    viewModel.rotateLifecycle()
                }
                .buttonStyle(.borderedProminent)
                .frame(maxWidth: .infinity)
                .frame(height: 44)
                .disabled(viewModel.lifecycleState != .active)

                Button(L10n.string("wscd.destroyButton")) {
                    showDestroyConfirm = true
                }
                .buttonStyle(.bordered)
                .tint(.red)
                .frame(maxWidth: .infinity)
                .frame(height: 44)
                .disabled(viewModel.lifecycleState == nil || viewModel.lifecycleState == .destroyed)
            }

            Button(L10n.string("wscd.refreshButton")) {
                viewModel.refreshWscdInfo()
            }
            .buttonStyle(.bordered)
            .frame(maxWidth: .infinity)
            .frame(height: 44)

            // ── Keys ───────────────────────────────────────────
            sectionHeader(L10n.string("wscd.storedKeys", viewModel.wscdKeys.count))
            if viewModel.wscdKeys.isEmpty {
                infoCard {
                    Text(L10n.string("wscd.noKeys"))
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
        .alert(L10n.string("wscd.destroyConfirmTitle"), isPresented: $showDestroyConfirm) {
            Button(L10n.string("wscd.destroyButton"), role: .destructive) {
                viewModel.destroyLifecycle(mode: .remoteRevokeIfSupported)
            }
            Button(L10n.string("common.cancel"), role: .cancel) {}
        } message: {
            Text(L10n.string("wscd.destroyConfirmMessage"))
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
                    Text(L10n.string("wscd.keyStorageLabel", props.keyStorage.joined(separator: ", ")))
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    Text(L10n.string("wscd.keyCertLabel", certificationText(props.certification)))
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                if !props.userAuthentication.isEmpty {
                    Text(L10n.string("wscd.keyAuthLabel", props.userAuthentication.joined(separator: ", ")))
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                if !props.amr.isEmpty {
                    Text(L10n.string("wscd.keyAmrLabel", props.amr.joined(separator: ", ")))
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

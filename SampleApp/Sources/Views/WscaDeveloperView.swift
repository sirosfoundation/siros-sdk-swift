// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosKeystore

/// Developer screen for inspecting and controlling the WSCA/WSCD.
/// Mirrors the Android WscaDeveloperScreen for feature parity.
struct WscaDeveloperView: View {
    @EnvironmentObject var viewModel: WalletViewModel

    // WSCD Selection Policy - new-entry form state for
    // `WalletConfig.defaultWscdMapping` (see the section below's header
    // comment for why this dev-only config lives here rather than in
    // end-user Settings).
    @State private var newMappingIssuer = ""
    @State private var newMappingCredentialType = ""
    @State private var newMappingPluginId = "fido2"

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    // Build Info
                    sectionHeader("Build Info")
                    infoCard {
                        infoRow("App Version", "0.1.0")
                        infoRow("Platform", "iOS")
                        infoRow("WSCD Manager", "siros-wscd-manager (UniFFI)")
                    }

                    // Plugin Selection
                    sectionHeader("Plugin")
                    HStack(spacing: 8) {
                        ForEach(["softkey", "r2ps", "fido2"], id: \.self) { pluginId in
                            PluginChip(
                                label: pluginId,
                                isSelected: viewModel.selectedPluginId == pluginId,
                                action: { viewModel.selectPlugin(pluginId) }
                            )
                        }
                    }

                    if viewModel.selectedPluginId == "r2ps" {
                        TextField("R2PS Server URL", text: $viewModel.r2psServerUrl)
                            .textFieldStyle(.roundedBorder)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                        // No real R2PS dev server key is wired into this
                        // sample app yet (see `r2psServerPublicKeyPem`'s doc
                        // comment) - left blank by default rather than
                        // silently reusing the client's own key, which
                        // would be actively wrong. Paste the real server's
                        // PEM public key here to test against an actual
                        // R2PS server.
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

                    // WSCD Selection Policy - `WscdSelectionPolicy`'s
                    // multi-plugin key-storage selection (see its doc
                    // comment). Dev config, not end-user Settings: unlike
                    // the "Security Key Choices" TOFU section in
                    // `SettingsView` (which shows/clears what the wallet
                    // already decided per-credential), `defaultWscdMapping`
                    // is an integrator's up-front shortcut answer for a
                    // given issuer/credential type - not a preference an
                    // end user would ever configure for themselves - and
                    // `availableKeystores`/`requestWscdChoice` only need to
                    // exist at all when this toggle is on, so it belongs
                    // next to the plugin chooser above, matching the
                    // Kotlin sample app's equivalent dev-only placement.
                    sectionHeader("WSCD Selection Policy")
                    infoCard {
                        Toggle("Enable multi-plugin selection", isOn: $viewModel.wscdMultiPluginEnabled)
                            .font(.subheadline)
                        Text("Requires reconnecting to take effect.")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }

                    if viewModel.wscdMultiPluginEnabled {
                        Text("Default Mapping")
                            .font(.caption)
                            .fontWeight(.semibold)
                            .foregroundStyle(.secondary)

                        if viewModel.wscdDefaultMapping.isEmpty {
                            Text("No default mappings configured")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        } else {
                            infoCard {
                                ForEach(Array(viewModel.wscdDefaultMapping.keys.sorted()), id: \.self) { key in
                                    if let pluginId = viewModel.wscdDefaultMapping[key] {
                                        HStack {
                                            VStack(alignment: .leading, spacing: 2) {
                                                Text(key)
                                                    .font(.caption2)
                                                    .foregroundStyle(.secondary)
                                                    .lineLimit(1)
                                                    .truncationMode(.middle)
                                                Text(pluginId)
                                                    .font(.caption.weight(.medium))
                                            }
                                            Spacer()
                                            Button(action: { viewModel.removeWscdDefaultMapping(key: key) }) {
                                                Image(systemName: "xmark.circle")
                                                    .foregroundStyle(.secondary)
                                            }
                                            .buttonStyle(.borderless)
                                        }
                                        .padding(.vertical, 2)
                                    }
                                }
                            }
                        }

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
                                ForEach(["softkey", "r2ps", "fido2"], id: \.self) { pluginId in
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

                    // Lifecycle Status
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

                    // Lifecycle Actions
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

                        Button("Destroy (Local)") {
                            viewModel.destroyLifecycle(mode: .localOnly)
                        }
                        .buttonStyle(.bordered)
                        .tint(.red)
                        .frame(maxWidth: .infinity)
                        .frame(height: 44)
                        .disabled(viewModel.lifecycleState == nil || viewModel.lifecycleState == .destroyed)
                    }

                    HStack(spacing: 8) {
                        Button("Destroy + Revoke") {
                            viewModel.destroyLifecycle(mode: .remoteRevokeIfSupported)
                        }
                        .buttonStyle(.bordered)
                        .tint(.red)
                        .frame(maxWidth: .infinity)
                        .frame(height: 44)
                        .disabled(viewModel.lifecycleState == nil || viewModel.lifecycleState == .destroyed)

                        Button("Refresh") {
                            viewModel.refreshWscdInfo()
                        }
                        .buttonStyle(.bordered)
                        .frame(maxWidth: .infinity)
                        .frame(height: 44)
                    }

                    // Keys
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
                .padding(.horizontal, 16)
                .padding(.vertical, 12)
            }
            .navigationTitle("WSCA Developer")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button(action: { viewModel.closeWscaDeveloper() }) {
                        Image(systemName: "chevron.left")
                    }
                }
            }
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

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosKeystore

/// Developer screen for inspecting and controlling the WSCA/WSCD.
/// Mirrors the Android WscaDeveloperScreen for feature parity.
struct WscaDeveloperView: View {
    @EnvironmentObject var viewModel: WalletViewModel

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
                            Button(action: { viewModel.selectPlugin(pluginId) }) {
                                Text(pluginId)
                                    .font(.subheadline)
                                    .padding(.horizontal, 12)
                                    .padding(.vertical, 6)
                            }
                            .buttonStyle(
                                viewModel.selectedPluginId == pluginId
                                    ? .borderedProminent
                                    : .bordered
                            )
                        }
                    }

                    if viewModel.selectedPluginId == "r2ps" {
                        TextField("R2PS Server URL", text: $viewModel.r2psServerUrl)
                            .textFieldStyle(.roundedBorder)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
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

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosWallet

/// Per-backend opt-in for the group message trace.
enum WmpTracePreference {
    static func key(for backend: String) -> String {
        "wmp.trace.\(backend)"
    }

    static func isEnabled(for backend: String, defaults: UserDefaults = .standard) -> Bool {
        defaults.bool(forKey: key(for: backend))
    }

    static func set(_ enabled: Bool, for backend: String, defaults: UserDefaults = .standard) {
        defaults.set(enabled, forKey: key(for: backend))
    }
}

/// The connected WMP groups and their opt-in message traces.
struct WmpEndpointsScreen: View {
    @EnvironmentObject var viewModel: WalletViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                ScreenTitle(text: L10n.string("menu.groups"))
                Button(L10n.string("wmpEndpoints.refresh")) {
                    viewModel.refreshWmpEndpoints()
                }
                .buttonStyle(.bordered)
                .tint(SirosTheme.brand)
            }

            if viewModel.wmpEndpoints.isEmpty {
                Text(L10n.string("wmpEndpoints.empty"))
                    .font(.body)
                    .foregroundColor(SirosTheme.secondaryText)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 16) {
                        ForEach(viewModel.wmpEndpoints, id: \.wmpBackend) { endpoint in
                            WmpEndpointCard(
                                endpoint: endpoint,
                                messages: viewModel.wmpMessages,
                                onSend: { text in
                                    viewModel.sendWmpGroupReply(backend: endpoint.wmpBackend, text: text)
                                },
                                onLeave: endpoint.origin == .invitation ? { backend in
                                    viewModel.leaveGroup(backend: backend)
                                } : nil
                            )
                            .walletCard(padding: 14)
                        }
                    }
                    .padding(.bottom, 24)
                }
            }
        }
        .padding(.horizontal, SirosTheme.screenMargin)
        .padding(.top, 24)
        .background(SirosTheme.screenBackground)
    }
}

private struct WmpEndpointCard: View {
    let endpoint: WmpEndpointInfo
    let messages: [WmpGroupMessage]
    let onSend: (String) -> Void
    /// The leave affordance — nil on the engine card (its "session" is the
    /// wallet's own connection, not a group membership).
    let onLeave: ((String) -> Void)?

    @State private var reply = ""
    @State private var traceEnabled: Bool
    @State private var confirmingLeave = false

    init(
        endpoint: WmpEndpointInfo,
        messages: [WmpGroupMessage],
        onSend: @escaping (String) -> Void,
        onLeave: ((String) -> Void)? = nil
    ) {
        self.endpoint = endpoint
        self.messages = messages
        self.onSend = onSend
        self.onLeave = onLeave
        _traceEnabled = State(initialValue: WmpTracePreference.isEnabled(for: endpoint.wmpBackend))
    }

    private var title: String {
        endpoint.groupName ?? endpoint.groupId ?? endpoint.sessionId ?? endpoint.providerUrl ?? endpoint.sendUrl
    }

    private var traceMessages: [WmpGroupMessage] {
        Array(messages.filter {
            $0.backend == endpoint.wmpBackend && $0.sessionId == endpoint.sessionId
        }.prefix(6))
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text(title)
                    .font(.body.weight(.semibold))
                    .foregroundColor(SirosTheme.ink)
                    .lineLimit(1)
                Spacer()
                Text(endpoint.state)
                    .font(.caption)
                    .foregroundColor(SirosTheme.secondaryText)
            }

            Toggle(L10n.string("wmpEndpoints.trace"), isOn: $traceEnabled)
                .font(.body.weight(.medium))
                .tint(SirosTheme.brand)
                .onChange(of: traceEnabled) { _, enabled in
                    WmpTracePreference.set(enabled, for: endpoint.wmpBackend)
                }

            if traceEnabled {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(Array(traceMessages.enumerated()), id: \.offset) { _, message in
                        Text("\(message.outbound ? "→" : "←") \(message.text)")
                            .font(.caption)
                            .foregroundColor(SirosTheme.onSurfaceVariant)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }

            HStack {
                TextField(L10n.string("wmpEndpoints.reply"), text: $reply)
                    .textFieldStyle(.roundedBorder)
                    .autocorrectionDisabled()
                Button(L10n.string("wmpEndpoints.send")) {
                    let text = reply.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !text.isEmpty else { return }
                    onSend(text)
                    reply = ""
                }
                .buttonStyle(.borderedProminent)
                .tint(SirosTheme.brand)
                .disabled(reply.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }

            // The leave is destructive (a fresh invite is needed to rejoin):
            // invitation cards only, behind a confirmation naming the group.
            if let onLeave {
                HStack {
                    Spacer()
                    Button(L10n.string("wmpEndpoints.leave")) {
                        confirmingLeave = true
                    }
                    .font(.caption)
                    .foregroundColor(SirosTheme.error)
                    .confirmationDialog(
                        L10n.string("wmpEndpoints.leaveConfirmTitle"),
                        isPresented: $confirmingLeave,
                        titleVisibility: .visible
                    ) {
                        Button(
                            L10n.string("wmpEndpoints.leaveConfirm"),
                            role: .destructive
                        ) {
                            onLeave(endpoint.wmpBackend)
                        }
                        Button(L10n.string("common.cancel"), role: .cancel) {}
                    } message: {
                        Text(
                            L10n.string(
                                "wmpEndpoints.leaveConfirmText",
                                endpoint.groupName ?? endpoint.groupId ?? endpoint.wmpBackend
                            )
                        )
                    }
                }
            }
        }
    }
}

private extension WmpEndpointInfo {
    var wmpBackend: String {
        providerUrl ?? WmpEndpointInfo.Origin.engine.rawValue
    }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var viewModel: WalletViewModel

    var body: some View {
        NavigationStack {
            List {
                Section("Account") {
                    LabeledContent("User", value: viewModel.displayName ?? "—")
                    LabeledContent("Backend", value: viewModel.backendUrl)
                    LabeledContent("Tenant", value: viewModel.tenantId)
                    if viewModel.r2psEnabled {
                        LabeledContent("R2PS Server", value: viewModel.r2psServerUrl)
                    }
                }

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

                Section {
                    Button(role: .destructive, action: { viewModel.disconnect() }) {
                        Label("Disconnect", systemImage: "rectangle.portrait.and.arrow.right")
                    }
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}

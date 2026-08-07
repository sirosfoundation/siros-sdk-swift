// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosWallet

/// One in-flight `RequestWscdChoice` prompt plus how to answer it - fired
/// only when more than one registered WSCD plugin
/// (`WalletConfig.availableKeystores`) meets a credential type's declared
/// key-storage requirement and neither TOFU nor `WalletConfig.defaultWscdMapping`
/// resolved it automatically (see `WscdSelectionPolicy.resolve`'s doc
/// comment, steps 2-5). `Identifiable` so it can drive a `.sheet(item:)`
/// presentation directly, mirroring `ProximityEngagementScreen`'s
/// `PendingConsent`.
struct PendingWscdChoice: Identifiable {
    let id = UUID()
    let issuer: String
    let credentialType: String
    let eligiblePluginIds: [String]
    /// Call with the chosen plugin ID + how long to remember it to approve,
    /// or `nil` (scope is irrelevant for a cancel) to cancel.
    let respond: (String?, WscdRememberScope) -> Void
}

/// Bridges `RequestWscdChoice`'s async callback to this sheet: suspends the
/// caller (`WalletViewModel.requestWscdChoice`) until the user taps a plugin
/// or Cancel. Mirrors `ProximityEngagementScreen`'s `ConsentContinuationBox`
/// - resumes at most once, guarding the race between the user answering and
/// the sheet being dismissed some other way (e.g. swiping it away).
final class WscdChoiceContinuationBox {
    private var continuation: CheckedContinuation<WscdChoiceResult, Never>?

    func set(_ continuation: CheckedContinuation<WscdChoiceResult, Never>) {
        self.continuation = continuation
    }

    func resumeOnce(_ result: WscdChoiceResult) {
        let continuation = self.continuation
        self.continuation = nil
        continuation?.resume(returning: result)
    }
}

/// Sheet shown when `RequestWscdChoice` fires - a plain button-per-eligible-
/// plugin-ID chooser. Unlike `ProximityConsentSheet`, the SDK only asks
/// about eligible PLUGIN IDS here, not `KeystoreManager` instances or
/// credential families (`WalletConfig.availableKeystores` already holds the
/// concrete instances), so there's no credential preview to render - just
/// the choice itself.
struct WscdChoiceSheet: View {
    let choice: PendingWscdChoice

    /// Defaults to "Remember for this issuer" - the TOFU behavior this
    /// sheet always had before `WscdRememberScope` existed, so leaving the
    /// picker untouched keeps the same outcome as before this feature.
    @State private var rememberScope: WscdRememberScope = .thisIssuer

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 20) {
                HStack(spacing: 12) {
                    Image(systemName: "lock.shield.fill")
                        .font(.system(size: 28))
                        .foregroundColor(SirosTheme.brand)
                    Text("Choose a Security Key")
                        .font(.title2.bold())
                }

                Text("This credential (\(choice.credentialType) from \(choice.issuer)) requires a hardware-backed key. Choose which security key to use:")
                    .font(.body)
                    .foregroundColor(SirosTheme.onSurfaceVariant)

                VStack(spacing: 8) {
                    ForEach(choice.eligiblePluginIds, id: \.self) { pluginId in
                        Button(action: { choice.respond(pluginId, rememberScope) }) {
                            HStack {
                                Text(pluginId)
                                    .font(.body.weight(.medium))
                                Spacer()
                                Image(systemName: "chevron.right")
                                    .font(.caption)
                                    .foregroundColor(SirosTheme.onSurfaceVariant)
                            }
                            .padding(.horizontal, 16)
                            .padding(.vertical, 12)
                            .background(
                                RoundedRectangle(cornerRadius: 10)
                                    .fill(SirosTheme.surfaceVariant)
                            )
                        }
                        .buttonStyle(.plain)
                    }
                }

                VStack(alignment: .leading, spacing: 6) {
                    Text("Remember this choice")
                        .font(.caption)
                        .foregroundColor(SirosTheme.onSurfaceVariant)
                    Picker("Remember this choice", selection: $rememberScope) {
                        Text("Just this once").tag(WscdRememberScope.once)
                        Text("This issuer").tag(WscdRememberScope.thisIssuer)
                        Text("Always").tag(WscdRememberScope.allIssuers)
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                }

                Spacer()

                Button(action: { choice.respond(nil, rememberScope) }) {
                    Text("Cancel")
                        .frame(maxWidth: .infinity)
                        .frame(height: 48)
                }
                .buttonStyle(.bordered)
                .tint(.red)
            }
            .padding()
            .navigationTitle("Security Key Required")
            .navigationBarTitleDisplayMode(.inline)
        }
    }
}

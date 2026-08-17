// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI

/// One in-flight FIDO2 ClientPin prompt plus how to answer it - fired from
/// `SampleAppAuthProvider.requestPin` (a synchronous, FFI-thread-blocking
/// callback - see its doc comment) whenever the "fido2" plugin needs the
/// authenticator's real PIN. `Identifiable` so it can drive a
/// `.sheet(item:)` presentation directly, mirroring `PendingWscdChoice`.
struct PendingFido2PinEntry: Identifiable {
    let id = UUID()
    /// Call with the PIN the user entered, or `nil` to cancel.
    let respond: (String?) -> Void
}

/// Sheet shown when a FIDO2 plugin operation needs the authenticator's real
/// CTAP2 ClientPin PIN. Mirrors the Kotlin sample app's `PinEntryDialog`: a
/// single text field with a show/hide toggle so the user can visually
/// verify what they typed (found necessary during live hardware testing -
/// a silent typo/autocorrect is otherwise indistinguishable from a genuine
/// wrong-PIN authenticator rejection).
///
/// CTAP2 PINs aren't necessarily numeric (FIDO2 allows any UTF-8 PIN), so
/// this uses a general text keyboard rather than a numeric one.
struct Fido2PinEntryView: View {
    let pending: PendingFido2PinEntry

    @State private var pin: String = ""
    @State private var pinVisible = false
    @FocusState private var fieldFocused: Bool

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 20) {
                HStack(spacing: 12) {
                    Image(systemName: "wave.3.right.circle.fill")
                        .font(.system(size: 28))
                        .foregroundColor(SirosTheme.brand)
                    Text(L10n.string("fido2.pinTitle"))
                        .font(.title2.bold())
                }

                Text(L10n.string("fido2.pinDescription"))
                    .font(.body)
                    .foregroundColor(SirosTheme.onSurfaceVariant)

                HStack {
                    Group {
                        if pinVisible {
                            TextField(L10n.string("fido2.pinPlaceholder"), text: $pin)
                        } else {
                            SecureField(L10n.string("fido2.pinPlaceholder"), text: $pin)
                        }
                    }
                    .textFieldStyle(.roundedBorder)
                    .focused($fieldFocused)

                    Button(action: { pinVisible.toggle() }) {
                        Image(systemName: pinVisible ? "eye.slash" : "eye")
                            .foregroundColor(SirosTheme.onSurfaceVariant)
                    }
                }

                Spacer()

                HStack(spacing: 12) {
                    Button(action: { pending.respond(nil) }) {
                        Text(L10n.string("common.cancel"))
                            .frame(maxWidth: .infinity)
                            .frame(height: 48)
                    }
                    .buttonStyle(.bordered)
                    .tint(.red)

                    Button(action: { pending.respond(pin) }) {
                        Text(L10n.string("fido2.submitButton"))
                            .frame(maxWidth: .infinity)
                            .frame(height: 48)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(SirosTheme.brand)
                    .disabled(pin.isEmpty)
                }
            }
            .padding()
            .navigationTitle(L10n.string("fido2.navTitle"))
            .navigationBarTitleDisplayMode(.inline)
            .onAppear { fieldFocused = true }
        }
    }
}

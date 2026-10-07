// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import UIKit
import SirosWallet
import SirosCredentials

/// FaceTec-backed PhotoID onboarding: the IDV preparation/consent screen
/// (`IDVPreparationView`) and the capture flow behind it (`startIDV()`).
/// `@Published showIDVPreparation`/`showPhotoIdOnboarding` state stays in
/// `WalletViewModel.swift`, since Swift extensions cannot add stored
/// properties; only the behaviour lives here, mirroring this app's existing
/// `WalletViewModel+Activate.swift`/`WalletViewModel+Devices.swift` split.
///
/// `showIDVPreparation` used to be `AddCredentialView`'s own local `@State`
/// (sheeted there only) - lifted to the ViewModel so Home's onboarding CTA
/// (see `HomeView`, gated by `showPhotoIdOnboarding`) can reach the same
/// screen directly, bypassing the Credentials tab/Add Credential list
/// entirely.
extension WalletViewModel {

    /// IDV server URL — defaults to facetec-api co-hosted behind /idv path.
    var idvServerUrl: String { backendUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + "/idv" }

    /// Shows the IDV preparation/consent screen - the real entry point for
    /// both the "Scan Physical ID card" row (`AddCredentialView`) and Home's
    /// PhotoID onboarding CTA (`HomeView`). Its own "Start Scan" action calls
    /// `startIDV()`.
    func openIDVPreparation() {
        showIDVPreparation = true
    }

    func closeIDVPreparation() {
        showIDVPreparation = false
    }

    func startIDV() {
        showAddCredential = false
        showIDVPreparation = false
        Task {
            do {
                isLoading = true
                guard let wallet else { throw SirosError.wallet(message: "Wallet is not connected") }
                let token = try await wallet.getAccessToken()
                // FaceTec 10: one session relays its blobs to facetec-api's
                // process-request. Needs the FaceTec xcframework linked into the
                // app and a device key identifier (FACETEC_DEVICE_KEY_IDENTIFIER
                // build setting); without either, verifyIdentityAndIssue reports
                // the provider unavailable.
                guard let processRequestUrl = URL(string: idvServerUrl + "/v1/process-request") else {
                    throw IDVError.unavailable(reason: "invalid IDV server URL")
                }
                let provider = FaceTecIDVProvider(config: FaceTecIDVConfig(
                    processRequestUrl: processRequestUrl,
                    authToken: "Bearer \(token)",
                    deviceKeyIdentifier: Self.faceTecDeviceKeyIdentifier
                ))
                let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene
                let rootViewController = windowScene?.windows.first?.rootViewController ?? UIViewController()
                try await wallet.verifyIdentityAndIssue(provider: provider, presentingViewController: rootViewController)
            } catch let error as IDVError {
                setError(Self.idvErrorMessage(for: error))
            } catch {
                // Per Copilot review: this must set `showError` too, not just
                // `errorMessage` - ContentView.syncBanner() only displays an
                // error when both are set, so a failure here previously sent
                // the user back to Home with no visible feedback at all.
                setError("IDV failed: \(error.localizedDescription)")
            }
            isLoading = false
        }
    }

    /// FaceTec device key identifier from the app's Info.plist (set from the
    /// `FACETEC_DEVICE_KEY_IDENTIFIER` build setting); empty when not configured.
    static var faceTecDeviceKeyIdentifier: String {
        deviceKeyIdentifier(fromInfoValue: Bundle.main.object(forInfoDictionaryKey: "FaceTecDeviceKeyIdentifier"))
    }

    /// An Info.plist value is a real key only if it is a non-blank string that is
    /// not an unresolved `$(BUILD_SETTING)` placeholder, which Xcode leaves in
    /// the built plist when the build setting is not defined.
    static func deviceKeyIdentifier(fromInfoValue value: Any?) -> String {
        guard let key = (value as? String)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !key.hasPrefix("$(") else { return "" }
        return key
    }

    /// The `idv.errors.*` key of the user-facing text for an IDV failure, from its
    /// `errorCode` (`idv_nfc_skipped`, `idv_chip_untrusted`,
    /// `idv_provider_internal_error`, ...).
    static func idvErrorKey(for error: IDVError) -> String {
        var name = error.errorCode
        for prefix in ["idv_provider_", "idv_"] where name.hasPrefix(prefix) {
            name.removeFirst(prefix.count)
            break
        }
        return "idv.errors.\(name)"
    }

    /// The user-facing, localized text for an IDV failure. `IDVError` is not a
    /// `SirosError`, so it needs its own lookup. Falls back to the error's own
    /// description for a code with no entry, e.g. one a newer facetec-api
    /// introduces.
    static func idvErrorMessage(for error: IDVError) -> String {
        let key = idvErrorKey(for: error)
        let text = L10n.string(key)
        return text == key ? error.localizedDescription : text
    }

    /// Whether `credentials` already includes the PhotoID credential (see
    /// `sirosIdCredentialConfigurationId`'s doc comment) - Home's onboarding
    /// CTA (gated by `showPhotoIdOnboarding`) only makes sense to offer when
    /// it's still missing.
    func hasPhotoIdCredential() -> Bool {
        credentials.contains { $0.credentialConfigurationId == sirosIdCredentialConfigurationId }
    }
}

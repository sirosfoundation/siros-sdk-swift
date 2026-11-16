// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import CryptoKit
import SirosAuth
import SirosCredentials
import SirosKeystore
import SirosWallet
#if canImport(siros_wscd_managerFFI)
import siros_wscd_managerFFI
#endif

/// WSCD lifecycle: enrolling a signer, selecting a plugin, and the rest of the
/// actions behind `WscdSettingsView`. Its `@Published` state stays in
/// `WalletViewModel.swift`, since Swift extensions cannot add stored
/// properties; only the behaviour lives here, mirroring the SDK's own
/// `SirosWallet+*.swift` split.
extension WalletViewModel {

    func selectPlugin(_ pluginId: String) {
        // The previous selection has to be read before it is overwritten:
        // comparing the new value against "r2ps" in the else branch made it
        // unreachable, so switching away from r2ps left r2psEnabled stuck on.
        let previous = selectedPluginId
        selectedPluginId = pluginId
        if pluginId == "r2ps" {
            r2psEnabled = true
        } else if previous == "r2ps" {
            r2psEnabled = false
        }
    }

    func enrollWscd() {
        #if canImport(siros_wscd_managerFFI)
        guard let manager = wallet?.wscdManager else {
            setError("WSCD signer not initialized")
            return
        }
        enrollmentInProgress = true
        Task {
            do {
                let pluginId = selectedPluginId
                let contextId = "ctx-\(Int(Date().timeIntervalSince1970 * 1000))"
                let factorKind: FactorKind = pluginId == "r2ps" ? .opaque : .rawSign

                let regOutcome = try await manager.registerLifecycle(
                    request: RegisterLifecycleRequest(
                        pluginId: pluginId,
                        contextId: contextId,
                        factorKind: factorKind
                    )
                )
                lifecycleState = regOutcome.state

                let actOutcome = try await manager.activateLifecycle(
                    request: ActivateLifecycleRequest(
                        pluginId: pluginId,
                        contextId: contextId
                    )
                )
                lifecycleState = actOutcome.state
                lifecycleContextId = contextId

                // Persist the FIDO2 plugin's key metadata via privatedata so
                // this key stays addressable on any device sharing this
                // account - CTAP2 roaming authenticators (e.g. a YubiKey)
                // aren't tied to the device that enrolled them. Only wallet
                // exists by this point (unlike buildWscdSigner's initial,
                // eager keystore construction, which runs before `wallet`
                // does and so can't restore saved state the same way -
                // a real, accepted limitation mirrored from the Kotlin SDK,
                // not something newly introduced here).
                if pluginId == "fido2" {
                    do {
                        let stateData = try manager.exportFido2State()
                        // Stored as a UTF-8 string, not base64 - matches the
                        // Kotlin SDK's convention (exportFido2State's Data is
                        // already the plugin's JSON state encoded as UTF-8;
                        // registerFido2PluginWithState expects the same
                        // encoding back).
                        if let stateString = String(data: stateData, encoding: .utf8) {
                            await wallet?.saveWscdCredentials(pluginId: "fido2", state: stateString)
                        } else {
                            print("FIDO2 plugin state was not valid UTF-8 - not saving")
                        }
                    } catch {
                        print("Failed to export/save FIDO2 plugin state: \(error)")
                    }
                }
            } catch {
                setError("Enrollment failed: \(error.localizedDescription)")
            }
            enrollmentInProgress = false
        }
        #else
        setError("WSCD not available (siros_wscd_managerFFI not linked)")
        #endif
    }

    func rotateLifecycle() {
        #if canImport(siros_wscd_managerFFI)
        guard let manager = wallet?.wscdManager, let ctxId = lifecycleContextId else {
            setError("WSCD not enrolled")
            return
        }
        Task {
            do {
                let outcome = try await manager.rotateLifecycle(
                    request: RotateLifecycleRequest(
                        pluginId: selectedPluginId,
                        contextId: ctxId
                    )
                )
                lifecycleState = outcome.state
                refreshWscdInfo()
            } catch {
                setError("Rotation failed: \(error.localizedDescription)")
            }
        }
        #endif
    }

    func destroyLifecycle(mode: DestroyMode) {
        #if canImport(siros_wscd_managerFFI)
        guard let manager = wallet?.wscdManager, let ctxId = lifecycleContextId else {
            setError("WSCD not enrolled")
            return
        }
        Task {
            do {
                let outcome = try await manager.destroyLifecycle(
                    request: DestroyLifecycleRequest(
                        pluginId: selectedPluginId,
                        contextId: ctxId,
                        mode: mode
                    )
                )
                lifecycleState = outcome.state
                lifecycleContextId = nil
                refreshWscdInfo()
            } catch {
                setError("Destruction failed: \(error.localizedDescription)")
            }
        }
        #endif
    }

    // The signer builder (2026-11-16 split from WalletViewModel.swift,
    // which is over SwiftLint's 1500-line limit): the one place the
    // FfiWscdConfig is built - including the softkey plugin's durable
    // backing file (the security invariant: every generated key is durable
    // BEFORE generate_key returns).
    /// Builds a WSCD-backed `Signer` for a single plugin ID, using exactly
    /// the `FfiWscdConfig`/`UniFFISigner`/R2PS-registration construction
    /// `rebuildWalletIfNeeded` always used for its one `selectedPluginId`
    /// signer - factored out here so `WalletConfig.availableKeystores` can
    /// reuse it once per known plugin ID instead of duplicating it, per
    /// `WscdSelectionPolicy`'s multi-plugin selection feature.
    func buildWscdSigner(forPlugin pluginId: String) -> UniFFISigner? {
        do {
            // The softkey plugin's OWN durable backing (the security
            // invariant, 2026-11-15): every generated key is durable BEFORE
            // generate_key returns - the plugin writes its container through
            // to this file inside the mutating critical section, so an app
            // restart can never orphan a stored credential's bound key.
            // Empty would be the volatile historic behaviour.
            let wscdConfig = FfiWscdConfig(
                defaultPlugin: pluginId,
                softkeyKeysFile: FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("wscd_softkey_keys.json").path
            )
            let signer = try UniFFISigner(config: wscdConfig, authProvider: wscdAuthProvider)

            if pluginId == "fido2" {
                // No USB HID host mode is available to third-party iOS
                // apps (a real platform constraint, not a gap to fix), so
                // unlike the Kotlin sample app's USB/NFC race
                // (CompositeCtap2Transport), there's only one real
                // transport to register here.
                try signer.registerFido2Plugin(transport: NfcCtap2Transport())
            }

            if pluginId == "apple-se" {
                // A Copilot review finding: `WscdPluginCapabilities.pluginTiers`
                // (and so `pluginIdsToTry` below) already lists "apple-se",
                // advertising it as an available keystore choice, but nothing
                // registered the actual backend - every generate/sign call
                // would have failed with `NoPlugin`. `SystemSecureEnclaveKeyStore`
                // is always safe to register unconditionally here, the same
                // way `fido2`'s `NfcCtap2Transport` is: if the device has no
                // Secure Enclave, `generateKey`/`sign` throw `.notAvailable`
                // (mapped to `Unsupported`) at call time, not registration
                // time - the same graceful-failure shape every other plugin
                // here already has.
                try signer.registerAppleSecureEnclavePlugin(backend: SystemSecureEnclaveKeyStore())
            }

            if pluginId == "r2ps" {
                // Ephemeral P-256 key pair for the R2PS message envelope
                // (JWS/JWE identity) - required regardless of auth mode.
                let clientKey = P256.Signing.PrivateKey()
                // `serverPublicKeyPem` MUST be the R2PS SERVER's own public
                // key (for JWE envelope encryption TO the server) - never
                // the client's own key, which would break the security
                // model entirely (encrypting to a key the client itself
                // holds the private half of defeats the point). See
                // `r2psServerPublicKeyPem`'s doc comment: no real dev server
                // key is available to hardcode here, so this is left as an
                // explicit dev-configurable placeholder rather than
                // silently substituting `clientKey.publicKey` again.
                let r2psConfig = R2psConfig(
                    serverUrl: r2psServerUrl,
                    clientId: "sample-app",
                    context: "wallet",
                    clientKeyPem: clientKey.pemRepresentation,
                    serverPublicKeyPem: r2psServerPublicKeyPem,
                    authMode: .opaque
                )
                let transport = URLSessionR2psTransport(serverUrl: r2psServerUrl)
                try signer.registerR2psPlugin(config: r2psConfig, transport: transport)
            }

            return signer
        } catch {
            print("WSCD setup failed for plugin \(pluginId): \(error). Skipping.")
            return nil
        }
    }
}

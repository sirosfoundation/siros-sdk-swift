// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
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
        selectedPluginId = pluginId
        if pluginId == "r2ps" {
            r2psEnabled = true
        } else if selectedPluginId == "r2ps" {
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
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosAuth
import SirosCredentials
import SirosWallet

/// Settings → Devices: the actions behind `DevicesView` (wallet instance
/// lifecycle, SID-AUTH-06). Its `@Published` state stays in
/// `WalletViewModel.swift`, since Swift extensions cannot add stored
/// properties; only the behaviour lives here, mirroring the SDK's own
/// `SirosWallet+*.swift` split.
extension WalletViewModel {

    func openDevices() {
        deactivationOutcome = nil
        showDevices = true
    }

    func closeDevices() {
        showDevices = false
        devicesError = nil
    }

    func refreshDevices() {
        Task { @MainActor in await loadDevices() }
    }

    /// The listing itself. `async` rather than fire-and-forget, so a caller
    /// that must not re-enable its buttons until the list is current (see
    /// `setWalletInstanceStatus`) can await it - otherwise a second status
    /// write could start against a list still showing the pre-write state, and
    /// the two refreshes could land out of order.
    @MainActor
    func loadDevices() async {
        guard let wallet else { return }
        devicesLoading = true
        devicesError = nil
        do {
            walletInstances = try await wallet.listWalletInstances()
        } catch {
            devicesError = error.localizedDescription
        }
        devicesLoading = false
    }

    /// Suspend, reactivate or revoke one instance. The SDK re-logs in after
    /// the write (the change cuts this session's tokens off), so when the
    /// target is this device the wallet may land in `.lifecycleBlocked` and
    /// this screen disappears behind the blocked login screen - which is the
    /// truthful outcome, not an error to report here.
    func setWalletInstanceStatus(instanceId: String, status: WalletInstance.Status, reason: String? = nil) {
        Task { @MainActor in
            guard let wallet else { return }
            devicesBusyInstanceId = instanceId
            devicesError = nil
            do {
                _ = try await wallet.setWalletInstanceStatus(
                    instanceId: instanceId, status: status, reason: reason
                )
                await loadDevices()
                devicesBusyInstanceId = nil
            } catch {
                devicesError = error.localizedDescription
                devicesBusyInstanceId = nil
            }
        }
    }

    /// Deactivate the wallet. The SDK forgets the local account in both
    /// outcomes (the revocations stand even when the erasure cascade did not
    /// finish), so this screen closes either way and the result is kept only
    /// to be shown once before it does.
    func deactivateWallet(reason: String? = nil) {
        Task { @MainActor in
            guard let wallet else { return }
            deactivating = true
            devicesError = nil
            do {
                let outcome = try await wallet.deactivateWallet(reason: reason)
                deactivationOutcome = outcome
                walletInstances = []
                showAddCredential = false
                showDevices = false
                // deactivateWallet also forgets the account and logs out, so
                // this screen is gone by the next render. Report the outcome
                // through the app-wide banner instead, which the login screen
                // shows too - otherwise a user who deactivated with an
                // unfinished erasure would never learn that their provider
                // still has cleanup to do.
                if outcome.complete {
                    infoMessage = L10n.string("devices.deactivateComplete", outcome.revoked)
                    // `infoMessage` alone does not raise the banner - see
                    // `syncBanner()`, which is driven by these flags.
                    showInfo = true
                } else {
                    errorMessage = L10n.string("devices.deactivateIncomplete", outcome.revoked)
                    showError = true
                }
            } catch {
                devicesError = error.localizedDescription
            }
            deactivating = false
        }
    }

    /// Leaving the session must leave the Devices sub-screen: left set, it
    /// would be what the next login renders instead of the wallet tabs.
    func resetDevicesNavigation() {
        showDevices = false
        walletInstances = []
    }
}

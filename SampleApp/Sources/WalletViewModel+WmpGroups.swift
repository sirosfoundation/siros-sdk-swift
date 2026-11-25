// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SirosWallet

/// The WMP Groups screen's state and actions (split from WalletViewModel to
/// keep the view model below the file-length lint ceiling).
extension WalletViewModel {
    func cancelCurrentFlow() {
        wallet?.cancelCurrentFlow()
    }


    func openWmpEndpoints() {
        showWmpEndpoints = true
        wmpEventsJob?.cancel()
        guard let wallet else {
            refreshWmpEndpoints()
            return
        }
        wmpEventsJob = Task { @MainActor [weak self, wallet] in
            // Entry waits for any startup restore, then takes the endpoint
            // snapshot and starts the collector with the restored peers.
            await self?.wmpJoinRestoreJob?.value
            guard let self, !Task.isCancelled, self.showWmpEndpoints else { return }
            self.refreshWmpEndpoints()
            for await _ in wallet.groupMessageEvents() {
                self.wmpMessages = wallet.wmpGroupInbox()
            }
        }
    }

    func closeWmpEndpoints() {
        showWmpEndpoints = false
        wmpEventsJob?.cancel()
        wmpEventsJob = nil
    }

    func refreshWmpEndpoints() {
        guard let wallet else {
            wmpEndpoints = []
            wmpMessages = []
            return
        }
        wmpEndpoints = wallet.connectedWmpEndpoints()
        wmpMessages = wallet.wmpGroupInbox()
        Task { @MainActor in
            await wallet.pollGroupMessages()
            wmpEndpoints = wallet.connectedWmpEndpoints()
            wmpMessages = wallet.wmpGroupInbox()
        }
    }

    func sendWmpGroupReply(backend: String, text: String) {
        guard let wallet else { return }
        Task { @MainActor in
            do {
                try await wallet.replyToGroup(backend: backend, text: text)
                wmpMessages = wallet.wmpGroupInbox()
            } catch {
                setError(error.localizedDescription)
            }
        }
    }

    /// Restore sessions only. Groups deliberately refresh their published
    /// endpoint/message state when the user opens the Groups screen.
    func restoreWmpJoinsIfNeeded() {
        guard !wmpJoinsRestored, let wallet else { return }
        wmpJoinsRestored = true
        let records = wmpJoinStore.load()
        guard !records.isEmpty else { return }
        wmpJoinRestoreJob = Task { @MainActor [weak self, wallet] in
            for record in records {
                if await wallet.resumeWmpJoin(record: record) {
                    guard let self, !Task.isCancelled, self.wallet === wallet else { return }
                    // The resume rotated the token: persist the replacement.
                    self.persistJoinedGroups()
                }
            }
        }
    }

    func persistJoinedGroups() {
        guard let wallet else { return }
        for endpoint in wallet.connectedWmpEndpoints() {
            guard let provider = endpoint.providerUrl,
                  let record = wallet.wmpJoinRecord(provider: provider) else { continue }
            wmpJoinStore.save(record)
        }
    }

}

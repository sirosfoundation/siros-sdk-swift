// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
import SirosTransport

// OID4VCI §10 credential lifecycle notification handling for the wallet facade.
extension SirosWallet {
    /// Handle a `flow_complete` message: persist the issued credentials and,
    /// for each credential that carries a `notification_id`, ask the backend to
    /// forward a `credential_accepted` notification to the issuer.
    ///
    /// The notification send is a no-op if the engine session has been torn down
    /// concurrently (e.g. logout): `WalletEngineSession.sendCredentialNotification`
    /// drops the message when not connected, so a queued `flow_complete` cannot
    /// crash the app. The backend authenticates the notification using ephemeral
    /// issuance state and never stores credential data.
    func handleFlowComplete(msg: FlowCompleteMessage) async {
        if let credentials = msg.credentials {
            for cred in credentials {
                guard let payload = CredentialUtils.parseJwtPayload(cred.credential) else { continue }
                let exp = payload["exp"] as? Int64
                let now = Int64(Date().timeIntervalSince1970)
                if let exp, exp < now { continue }

                lock.lock(); let offer = activeOffer; let vctm = activeVctm; lock.unlock()
                let metadata = offer.flatMap { CredentialUtils.buildMetadata(offer: $0, vctm: vctm, rawCredential: cred.credential) }

                let stored = StoredCredential(
                    id: UUID().uuidString,
                    format: cred.format,
                    raw: cred.credential,
                    metadata: metadata,
                    issuedAt: payload["iat"] as? Int64,
                    expiresAt: exp,
                    notificationId: cred.notificationId
                )
                await credentialStore.save(stored)

                // OID4VCI §10: confirm acceptance to the issuer (via the backend)
                // while the issuance access token is still valid. The backend
                // forwards using ephemeral flow state; nothing is stored there.
                if let notificationId = cred.notificationId {
                    lock.lock(); let notifier = credentialNotifier; lock.unlock()
                    notifier?.sendCredentialNotification(
                        flowId: msg.flowId,
                        notificationId: notificationId,
                        event: CredentialNotificationEvent.accepted
                    )
                }

                lock.lock(); let listener = eventListener; lock.unlock()
                listener?.onCredentialReceived(credential: stored)
            }
        }
        lock.lock(); activeOffer = nil; activeVctm = nil; lock.unlock()

        await persistAndSyncKeystore()

        lock.lock(); let listener = eventListener; lock.unlock()
        listener?.onFlowComplete(flowId: msg.flowId)

        switch state {
        case .flowActive(let userId, let displayName, _, _, _, _),
             .ready(let userId, let displayName, _, _):
            let creds = await credentialStore.getAll()
            setState(.ready(userId: userId, displayName: displayName, credentials: creds))
        default:
            break
        }
    }
}

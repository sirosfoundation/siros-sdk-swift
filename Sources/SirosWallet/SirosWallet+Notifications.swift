// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
import SirosTransport

/// A randomly-generated uint32-range identifier, matching wallet-frontend's
/// `credentialId: number` (privatedata-spec §6) - not a UUID. Cross-client
/// interop (the same encrypted container read by either client) requires
/// this to be a genuine JSON number on the wire, not a string.
///
/// Uses `SystemRandomNumberGenerator` (a CSPRNG on every platform this
/// package targets) rather than `SecRandomCopyBytes`, which is Apple-only -
/// this file has no `#if canImport(CryptoKit)` gate of its own.
func randomUint32Id() -> Int64 {
    var rng = SystemRandomNumberGenerator()
    let value = Int64(UInt32.random(in: 0...UInt32.max, using: &rng))
    return value == 0 ? 1 : value
}

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
        // Tracks whether any credential in this batch actually made it into
        // the store, so a flow that "completes" per the engine but whose
        // only credential(s) failed to parse doesn't get silently reported
        // as success - see storeFailureReason below.
        var storedCount = 0
        var storeFailureReason: String?

        lock.lock(); let offer = activeOffer; let vctm = activeVctm; let attestedKeyIds = activeAttestedKeyIds; lock.unlock()

        // Shared across every copy in this response so the UI can group them
        // into one card (see StoredCredential.batchId) - ALWAYS assigned,
        // even for a single-credential issuance, matching wallet-frontend's
        // useOID4VCIFlow.ts (batchId = Date.now()) exactly: every issuance
        // response is its own batch of at least one, there is no "no batch"
        // sentinel on either client.
        let batchId = Int64(Date().timeIntervalSince1970 * 1000)

        if let credentials = msg.credentials {
            for (index, cred) in credentials.enumerated() {
                if cred.format == "mso_mdoc" {
                    // mso_mdoc credentials are base64url-encoded CBOR (a
                    // DeviceResponse-shaped envelope, per
                    // wallet-frontend#191), never JWT-shaped - the
                    // parseJwtPayload-based validation/expiry/metadata path
                    // below doesn't apply and would always fail, silently
                    // dropping every issued mdoc credential.
                    guard CredentialUtils.parseMdocDocument(cred.credential) != nil else {
                        storeFailureReason = "Received credential could not be read"
                        continue
                    }

                    var metadata: CredentialMetadata?
                    if let off = offer {
                        let mddlSchema = await mddlSchemaFetcher.fetch(
                            issuerUrl: off.credentialIssuerIdentifier,
                            scope: off.credentialConfigurationId,
                            doctype: off.doctype,
                            registryUrl: resolvedRegistryUrl
                        )
                        metadata = CredentialUtils.buildMdocMetadata(offer: off, mddlSchema: mddlSchema)
                    }
                    let stored = StoredCredential(
                        id: randomUint32Id(),
                        format: cred.format,
                        raw: cred.credential,
                        kid: index < (attestedKeyIds?.count ?? 0) ? attestedKeyIds?[index] : nil,
                        metadata: metadata,
                        notificationId: cred.notificationId,
                        credentialIssuerIdentifier: offer?.credentialIssuerIdentifier,
                        credentialConfigurationId: offer?.credentialConfigurationId,
                        batchId: batchId,
                        instanceId: index
                    )
                    await credentialStore.save(stored)
                    storedCount += 1

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
                    continue
                }

                guard let payload = CredentialUtils.parseJwtPayload(cred.credential) else {
                    storeFailureReason = "Received credential could not be read"
                    continue
                }
                let exp = payload["exp"] as? Int64
                let now = Int64(Date().timeIntervalSince1970)
                if let exp, exp < now {
                    storeFailureReason = "Issued credential was already expired"
                    continue
                }

                let metadata = offer.flatMap { CredentialUtils.buildMetadata(offer: $0, vctm: vctm, rawCredential: cred.credential) }

                let stored = StoredCredential(
                    id: randomUint32Id(),
                    format: cred.format,
                    raw: cred.credential,
                    kid: index < (attestedKeyIds?.count ?? 0) ? attestedKeyIds?[index] : nil,
                    metadata: metadata,
                    issuedAt: payload["iat"] as? Int64,
                    expiresAt: exp,
                    notificationId: cred.notificationId,
                    credentialIssuerIdentifier: offer?.credentialIssuerIdentifier,
                    credentialConfigurationId: offer?.credentialConfigurationId,
                    batchId: batchId,
                    instanceId: index
                )
                await credentialStore.save(stored)
                storedCount += 1

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
        lock.lock(); activeOffer = nil; activeVctm = nil; activeAttestedKeyIds = nil; lock.unlock()

        await persistAndSyncKeystore()

        // The engine considers this flow successfully finished, but if it
        // delivered credentials and none of them survived parsing/validation,
        // reporting onFlowComplete here would silently strand the user - the
        // flow "succeeds" with nothing to show for it and no indication
        // anything went wrong. Surface it as a flow error instead so the
        // UI's error handling fires, matching how any other flow failure is
        // handled.
        let expectedCredentials = msg.credentials?.count ?? 0
        lock.lock(); let listener = eventListener; lock.unlock()
        if expectedCredentials > 0 && storedCount == 0 {
            listener?.onFlowError(flowId: msg.flowId, errorMessage: storeFailureReason ?? "Credential could not be processed")
        } else {
            listener?.onFlowComplete(flowId: msg.flowId)
        }

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

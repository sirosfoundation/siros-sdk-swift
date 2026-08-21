// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
import SirosTransport
import SirosKeystore
#if canImport(os)
import os
private let logger = Logger(subsystem: "org.siros.sdk", category: "SirosWallet")
#endif

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
        lock.lock()
        let offer = activeOffer
        let vctm = activeVctm
        let attestedKeyIds = activeAttestedKeyIds
        // A completed flow has no further sign_presentation coming - drop
        // its cached DCQL match results (if any; a no-op for an issuance
        // flow, which never populates this map) so it doesn't linger
        // forever, mirroring Kotlin's identical
        // `pendingMatchResultsByFlow.remove(msg.flowId)` here.
        pendingMatchResultsByFlow.removeValue(forKey: msg.flowId)
        lock.unlock()

        // Shared across every copy in this response so the UI can group them
        // into one card (see StoredCredential.batchId) - ALWAYS assigned,
        // even for a single-credential issuance, matching wallet-frontend's
        // useOID4VCIFlow.ts (batchId = Date.now()) exactly: every issuance
        // response is its own batch of at least one, there is no "no batch"
        // sentinel on either client.
        let batchId = Int64(Date().timeIntervalSince1970 * 1000)

        let (oldBatchId, oldRenewedClaims) = await snapshotRenewalSourceBatch()
        let wasRenewal = oldBatchId != nil

        // Tracks whether any credential in this batch actually made it into
        // the store, so a flow that "completes" per the engine but whose
        // only credential(s) failed to parse doesn't get silently reported
        // as success - see storeFailureReason below.
        var storedCount = 0
        var storeFailureReason: String?
        if let credentials = msg.credentials {
            for (index, cred) in credentials.enumerated() {
                let outcome = await storeIssuedCredential(
                    cred, index: index, flowId: msg.flowId, offer: offer, vctm: vctm,
                    attestedKeyIds: attestedKeyIds, batchId: batchId
                )
                if outcome.stored { storedCount += 1 }
                if let reason = outcome.failureReason { storeFailureReason = reason }
            }
        }

        // Only now that the new batch is confirmed stored is it safe to
        // delete the one it supersedes - deleting it any earlier (e.g.
        // right after snapshotting, before knowing whether the renewal's
        // credential(s) actually parsed/validated) would destroy the user's
        // only copy on a failed renewal. See snapshotRenewalSourceBatch's
        // doc comment.
        if storedCount > 0, let oldBatchId {
            await deleteRenewalSourceBatch(oldBatchId)
        }

        await captureRefreshTokenIfPresent(msg: msg, offer: offer, batchId: batchId)
        await notifyRenewalAttributeDiffIfNeeded(wasRenewal: wasRenewal, oldClaims: oldRenewedClaims, batchId: batchId)

        // Terminal path for this issuance - see `resetIssuanceGuards()`.
        // Also clears `pendingRenewalSourceBatchId` (see its own clearing in
        // `resetIssuanceGuards()`), whether this renewal attempt succeeded
        // or failed - either way the attempt is over.
        resetIssuanceGuards()

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
            listener?.onFlowError(flowId: msg.flowId, errorMessage: storeFailureReason ?? "Credential could not be processed", redirectUri: nil)
        } else {
            listener?.onFlowComplete(flowId: msg.flowId, redirectUri: msg.redirectUri)
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

    // Credential re-issuance/renewal plan (Phase 2): if this flow_complete is
    // a renewal's, peek at (but do NOT yet delete) the batch it's about to
    // supersede - just note its id and snapshot its claims (for the
    // attribute diff once the new batch is stored). Deleting it is
    // `deleteRenewalSourceBatch`'s job, and MUST only happen once the new
    // batch has actually been stored successfully (see handleFlowComplete):
    // deleting it here, unconditionally, would mean a renewal whose returned
    // credential(s) all fail to parse/validate destroys the user's only copy
    // of the credential instead of leaving it in place - a real data-loss
    // bug a Copilot review caught on this exact function.
    private func snapshotRenewalSourceBatch() async -> (oldBatchId: Int64?, oldClaims: [DisplayClaim]?) {
        lock.lock(); let renewalSourceBatchId = pendingRenewalSourceBatchId; lock.unlock()
        guard let oldBatchId = renewalSourceBatchId else { return (nil, nil) }
        let existing = await credentialStore.getAll()
        let oldRenewedClaims = existing
            .first(where: { $0.batchId == oldBatchId && $0.instanceId == 0 })
            .map { CredentialUtils.extractClaims($0) }
        return (oldBatchId, oldRenewedClaims)
    }

    // Delete `oldBatchId`'s credential entries AND its privatedata
    // refresh_token entry (per privatedata-spec §6.2 - a stale entry
    // pointing at a no-longer-existing batch must not linger) now that the
    // batch that supersedes it is confirmed stored - see
    // `snapshotRenewalSourceBatch`'s doc comment for why this must not run
    // any earlier.
    private func deleteRenewalSourceBatch(_ oldBatchId: Int64) async {
        let existing = await credentialStore.getAll()
        for cred in existing where cred.batchId == oldBatchId {
            await credentialStore.delete(cred.id)
        }
        await removeCredentialRefreshToken(batchId: oldBatchId)
    }

    private func storeIssuedCredential(
        _ cred: CredentialResult,
        index: Int,
        flowId: String,
        offer: CredentialOffer?,
        vctm: Vctm?,
        attestedKeyIds: [String]?,
        batchId: Int64
    ) async -> (stored: Bool, failureReason: String?) {
        if cred.format == "mso_mdoc" {
            // mso_mdoc credentials are base64url-encoded CBOR (a
            // DeviceResponse-shaped envelope, per wallet-frontend#191), never
            // JWT-shaped - the parseJwtPayload-based validation/expiry/
            // metadata path below doesn't apply and would always fail,
            // silently dropping every issued mdoc credential.
            guard let mdocDocument = CredentialUtils.parseMdocDocument(cred.credential) else {
                return (false, "Received credential could not be read")
            }

            // VICAL issuer-trust (ISO 18013-5 Annex C): defensive check on
            // the newly-issued credential's issuerAuth, surfaced via logging
            // only - not a blocking gate, same convention as
            // evaluateReaderTrust's remote/local-fallback reader-trust check
            // at presentation time (see evaluateIssuerTrust's doc comment).
            if let issuerTrust = await verifyAndEvaluateIssuerTrust(mdocDocument.issuerSigned.issuerAuth, docType: mdocDocument.docType) {
                #if canImport(os)
                logger.info("mdoc issuer trust for docType=\(mdocDocument.docType, privacy: .public): trusted=\(issuerTrust.trusted, privacy: .public) reason=\(issuerTrust.reason ?? "", privacy: .public)")
                #endif
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
            notifyCredentialAccepted(cred, flowId: flowId, stored: stored)
            return (true, nil)
        }

        guard let payload = CredentialUtils.parseJwtPayload(cred.credential) else {
            return (false, "Received credential could not be read")
        }
        let exp = payload["exp"] as? Int64
        let now = Int64(Date().timeIntervalSince1970)
        if let exp, exp < now {
            return (false, "Issued credential was already expired")
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

        // OID4VCI §10: confirm acceptance to the issuer (via the backend)
        // while the issuance access token is still valid. The backend
        // forwards using ephemeral flow state; nothing is stored there.
        notifyCredentialAccepted(cred, flowId: flowId, stored: stored)
        return (true, nil)
    }

    private func notifyCredentialAccepted(_ cred: CredentialResult, flowId: String, stored: StoredCredential) {
        if let notificationId = cred.notificationId {
            lock.lock(); let notifier = credentialNotifier; lock.unlock()
            notifier?.sendCredentialNotification(
                flowId: flowId,
                notificationId: notificationId,
                event: CredentialNotificationEvent.accepted
            )
        }

        lock.lock(); let listener = eventListener; lock.unlock()
        listener?.onCredentialReceived(credential: stored)
    }

    // Credential re-issuance/renewal plan (Phase 2): durably capture this
    // batch's refresh_token + DPoP key in privatedata
    // (S.credentialRefreshTokens - see setCredentialRefreshToken's doc
    // comment) so renewCredential() can use it later, including after an app
    // restart or on a different device sharing this account.
    //
    // `offer` (activeOffer) is best-effort display metadata - on a renewal
    // it's rebuilt by re-fetching issuer metadata (see renewCredential's doc
    // comment) and is left nil if that fetch fails. Falling back to
    // `msg.credentialIssuer`/`msg.selectedCredentialConfigurationId` (which
    // the engine always sends alongside `refreshToken`) means a flaky
    // metadata fetch doesn't also silently break the next renewal by never
    // storing its refresh_token at all.
    private func captureRefreshTokenIfPresent(msg: FlowCompleteMessage, offer: CredentialOffer?, batchId: Int64) async {
        guard let token = msg.refreshToken else { return }
        guard let issuerIdentifier = offer?.credentialIssuerIdentifier ?? msg.credentialIssuer,
              let configId = offer?.credentialConfigurationId ?? msg.selectedCredentialConfigurationId else { return }
        await setCredentialRefreshToken(
            batchId: batchId,
            entry: CredentialRefreshTokenEntry(
                refreshToken: token,
                dpopJwk: msg.dpopJwk,
                credentialIssuerIdentifier: issuerIdentifier,
                credentialConfigurationId: configId
            )
        )
    }

    // AttributeDiffService-equivalent (ISSU_59): if this was a renewal,
    // compare the new batch's claims against the old one's - a silent
    // renewal only stays silent when nothing actually changed. See
    // onCredentialRenewedWithAttributeDiff's doc comment for why this fires
    // in addition to (not instead of) onCredentialReceived.
    private func notifyRenewalAttributeDiffIfNeeded(wasRenewal: Bool, oldClaims: [DisplayClaim]?, batchId: Int64) async {
        guard wasRenewal, let oldClaims else { return }
        let allNow = await credentialStore.getAll()
        guard let newRepresentative = allNow.first(where: { $0.batchId == batchId && $0.instanceId == 0 }) else { return }
        let diff = CredentialUtils.computeAttributeDiff(before: oldClaims, after: CredentialUtils.extractClaims(newRepresentative))
        guard diff.hasChanges else { return }
        lock.lock(); let listener = eventListener; lock.unlock()
        listener?.onCredentialRenewedWithAttributeDiff(credential: newRepresentative, diff: diff)
    }
}

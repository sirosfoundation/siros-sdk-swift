// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
import SirosKeystore
import SirosTransport

extension SirosWallet {
    /// `wmp.flow.complete` for an issuance or presentation. A wallet-encrypted issuance is paired and stored exactly
    /// like the WebSocket's `flow_complete`; a plain completion that carries a credential entry without its value
    /// is refused whole, as on the WebSocket, rather than reported as a success.
    func handleWmpFlowComplete(flowId: String, result: AnyCodable?) async {
        if flowAlreadyEnded(flowId) { return }          // a late completion does not revive a failed or cancelled flow
        lock.lock(); let offeredKey = offeredResponseKeyFlows.contains(flowId); lock.unlock()
        if offeredKey, !Self.claimsEncryptedResponse(result) {
            let ids = result?.objectValue?["credentials"]?.arrayValue?.compactMap { $0.objectValue?["notification_id"]?.stringValue } ?? []
            await refusePlainCompletion(flowId: flowId, notificationIds: ids)
            return
        }
        // A relayed `credential_metadata` carrying a superseded secret-bearing member: refused before anything is
        // stored, as on the WebSocket (`LEGACY_SECRET_MEMBER`).
        if case .object_(let members)? = result?.objectValue?["credential_metadata"],
           members.keys.contains(where: { CredentialDisplayMetadata.prohibitedMembers.contains($0) }) {
            let ids = result?.objectValue?["credentials"]?.arrayValue?.compactMap { $0.objectValue?["notification_id"]?.stringValue } ?? []
            await refusePlainCompletion(
                flowId: flowId, notificationIds: ids,
                message: "The issuer's response carries a superseded secret member (LEGACY_SECRET_MEMBER)"
            )
            return
        }
        // Encrypted-to-the-wallet issuance: same pairing as the WebSocket's flow_complete.
        if Self.claimsEncryptedResponse(result) {
            guard let message = Self.encryptedFlowComplete(flowId: flowId, result: result) else {
                // Encrypted but unreadable: an error, not a plain completion that drops what was decrypted.
                let decrypted = takeDecryptedCredentialResponses(flowId: flowId)
                await rejectDecryptedCompletion(flowId: flowId, responses: decrypted, message: "The completion could not be read")
                return
            }
            // A WMP completion has no wire start tag: it is processed under the issuance epoch captured when its
            // flow first asked for the response key. Without one the issuance cannot be established, and the
            // gate would drop the completion silently AFTER the decrypted responses are gone - so refuse it here.
            lock.lock(); let epoch = wmpFlowIssuanceEpochs.removeValue(forKey: flowId); lock.unlock()
            guard let epoch else {
                let decrypted = takeDecryptedCredentialResponses(flowId: flowId)
                await rejectDecryptedCompletion(
                    flowId: flowId, responses: decrypted, message: "The completion's issuance could not be established"
                )
                return
            }
            var tagged = message
            tagged.startTag = epoch
            await handleFlowComplete(msg: tagged)
            return
        }
        // siros-wallet-core's oid4vci completion is a single `credential` member
        // beside the renewal relay and the notification members - the Rust
        // engine's shape (the engine holds the response-encryption key itself and
        // delivers the credential in the clear over the wallet↔engine channel, so
        // there is no decrypt-your-own-response path). Everything else is the
        // presentation completion set ({presented}, {declined}, …), which stores nothing.
        if result?.objectValue?["credential"] != nil {
            await handleWmpIssuanceComplete(flowId: flowId, result: result)
            return
        }
        if let entries = result?.objectValue?["credentials"]?.arrayValue,
           entries.contains(where: { ($0.objectValue?["credential"]?.stringValue ?? "").isEmpty }) {
            await failIssuanceLocally(flowId: flowId, message: "The issuer's credential did not arrive")
            return
        }
        // Terminal path for this issuance over the WMP transport too - see `resetIssuanceGuards()`.
        resetIssuanceGuards()
        cancelTransactionTasks(flowId: flowId)
        eventListener?.onFlowComplete(flowId: flowId, redirectUri: nil)
    }

    /// An OID4VCI completion on the WMP path (siros-wallet-core): what remains is
    /// the legacy completion path's storage sequence, leaner for the parts this engine
    /// does server-side - trust: the engine fails untrusted issuers at its PDP port
    /// (a completion IS the trust verdict); blind issuance: the engine holds the
    /// response-encryption key itself, so there is no key offered and no decrypt ask.
    ///
    /// The renewal capture, the superseded batch, the per-format validation and
    /// storage, the §10 notification (the FLOW form on this engine -
    /// `wmp.credential.notification` is go-wmp's method and does not exist on the
    /// Rust engine), the guard resets and the state return are the legacy path's,
    /// reused one-for-one.
    private func handleWmpIssuanceComplete(flowId: String, result: AnyCodable?) async {
        let members = result?.objectValue ?? [:]
        let credential = members["credential"]?.stringValue ?? ""
        let refreshToken = members["refresh_token"]?.stringValue
        let dpopJwk = members["dpop_jwk"]?.stringValue
        let notificationId = members["notification_id"]?.stringValue
        if credential.isEmpty {
            // deferred=true with no credential is the engine's error path (a
            // deferred credential the issuer never delivered) - reported, not
            // stored as success.
            #if canImport(os)
            logger.error("WMP issuance flow \(flowId) completed with no credential")
            #endif
            resetIssuanceGuards()
            eventListener?.onFlowError(flowId: flowId, errorMessage: "The issuance delivered no credential", redirectUri: nil)
            await returnToReadyState()
            return
        }

        // Snapshot the issuance state this completion belongs to before anything
        // suspends (the legacy completion path's identical rule).
        lock.lock()
        let flowOffer = activeOffer
        let flowVctm = activeVctm
        lock.unlock()
        let batchId = Int64(Date().timeIntervalSince1970 * 1000)
        lock.lock(); let oldBatch = pendingRenewalSourceBatchId; pendingRenewalSourceBatchId = nil; lock.unlock()
        let allCredentials = await credentialStore.getAll()
        let oldRenewedClaims: [DisplayClaim]? = oldBatch.flatMap { oldBatchId -> [DisplayClaim]? in
            allCredentials.first(where: { $0.batchId == oldBatchId && $0.instanceId == 0 })
                .map { CredentialUtils.extractClaims($0) }
        }

        // The credential's format: the offer's configuration is authoritative;
        // the credential's own shape decides when no offer survived (a replay
        // after a later start replaced the shared state).
        let format: String
        if let flowOffer,
           let resolved = try? await fetchIssuerMetadata(issuerUrl: flowOffer.credentialIssuerIdentifier),
           let configured = resolved.credentialConfigurationsSupported[flowOffer.credentialConfigurationId]?.format,
           !configured.isEmpty {
            format = configured
        } else {
            format = (credential.contains(".") || credential.contains("~")) ? "vc+sd-jwt" : "mso_mdoc"
        }

        let built = await wmpBuildStoredCredential(
            format: format,
            raw: credential,
            offer: flowOffer,
            vctm: flowVctm,
            notificationId: notificationId,
            batchId: batchId
        )
        let stored = built.stored
        let storeFailureReason = built.failureReason

        if let stored {
            _ = try? await credentialStore.save(stored)
            eventListener?.onCredentialReceived(credential: stored)
            #if canImport(os)
            logger.info("Stored issued credential format=\(format) batch=\(batchId)")
            #endif
        }

        // The renewal it replaces goes only once a replacement was stored (the
        // legacy rule: a rejected replacement must not leave the wallet with neither batch).
        if let oldBatch, stored != nil {
            for old in allCredentials where old.batchId == oldBatch {
                _ = try? await credentialStore.delete(old.id)
            }
            await removeCredentialRefreshToken(batchId: oldBatch)
            #if canImport(os)
            logger.debug("Replaced renewed credential batch \(oldBatch) with \(batchId)")
            #endif
        }

        // The renewal relay: durably captured for the next renewCredential call.
        if let refreshToken, stored != nil, let flowOffer {
            await setCredentialRefreshToken(
                batchId: batchId,
                entry: CredentialRefreshTokenEntry(
                    refreshToken: refreshToken,
                    dpopJwk: dpopJwk,
                    credentialIssuerIdentifier: flowOffer.credentialIssuerIdentifier,
                    credentialConfigurationId: flowOffer.credentialConfigurationId
                )
            )
        }

        // The attribute-diff report of a silent renewal (ISSU_59).
        if oldBatch != nil, let oldRenewedClaims, let stored {
            let diff = CredentialUtils.computeAttributeDiff(before: oldRenewedClaims, after: CredentialUtils.extractClaims(stored))
            if diff.hasChanges {
                eventListener?.onCredentialRenewedWithAttributeDiff(credential: stored, diff: diff)
            }
        }

        resetIssuanceGuards()
        await persistAndSyncKeystore()

        // OID4VCI §10: tell the issuer the credential was accepted - the FLOW form on
        // this engine (see `wmpSendCredentialNotification`).
        if let stored, let notificationId {
            await wmpSendCredentialNotification(
                flowId: flowId,
                notificationId: notificationId,
                event: "credential_accepted"
            )
        }

        if stored == nil {
            // "Succeeded" with nothing to show for it is a failure to the user:
            // the error path, so the UI's retry fires (the legacy rule).
            let reason = storeFailureReason ?? "Credential could not be processed"
            #if canImport(os)
            logger.error("WMP issuance flow \(flowId) completed but nothing was stored: \(reason)")
            #endif
            eventListener?.onFlowError(flowId: flowId, errorMessage: reason, redirectUri: nil)
        } else {
            eventListener?.onFlowComplete(flowId: flowId, redirectUri: nil)
        }
        await returnToReadyState()
    }

    /// The issued credential as a `StoredCredential` - the per-format
    /// validation and build, extracted from `handleWmpIssuanceComplete`
    /// (its body ran past swiftlint's 120-line bound the day the §10
    /// notification joined; the two branches are one question - "is this
    /// credential storable" - and belong together, away from the
    /// completion orchestration that calls them).
    ///
    /// - The `mso_mdoc` form parses the CBOR (a readable credential is a
    ///   storable one), then builds the `StoredCredential` after the parse
    ///   (the doctype names the MDDL schema to fetch).
    /// - The SD-JWT form parses the payload, verifies the issued type and
    ///   the VCT integrity, and builds the stored credential over the
    ///   (possibly refreshed) VCTM.
    ///
    /// - Returns: the built credential (`nil` on any validation failure)
    ///   and the user-facing failure reason (set only when `stored` is
    ///   `nil` - a build that succeeded has no failure to report).
    private func wmpBuildStoredCredential(
        format: String,
        raw: String,
        offer: CredentialOffer?,
        vctm: Vctm?,
        notificationId: String?,
        batchId: Int64
    ) async -> (stored: StoredCredential?, failureReason: String?) {
        if format == "mso_mdoc" {
            var parsedMdoc: DocumentMdoc?
            do {
                guard let bytes = CredentialUtils.base64UrlDecode(raw) else {
                    throw NSError(domain: "org.siros.sdk", code: 1, userInfo: [NSLocalizedDescriptionKey: "base64url"])
                }
                parsedMdoc = try MdocCbor.parseStoredCredential([UInt8](bytes))
            } catch {
                #if canImport(os)
                logger.warning("The issued mdoc credential could not be read: \(error.localizedDescription)")
                #endif
                return (nil, "Received credential could not be read")
            }
            // The mdoc branch builds the StoredCredential after the parse (the
            // doctype names the MDDL schema to fetch).
            var mdocMetadata: CredentialMetadata?
            if let offer {
                let schema = await mddlSchemaFetcher.fetch(
                    issuerUrl: offer.credentialIssuerIdentifier,
                    scope: offer.credentialConfigurationId,
                    doctype: parsedMdoc?.docType,
                    registryUrl: resolvedRegistryUrl
                )
                mdocMetadata = CredentialUtils.buildMdocMetadata(offer: offer, mddlSchema: schema)
            }
            return (StoredCredential(
                id: randomUint32Id(),
                format: format,
                raw: raw,
                metadata: mdocMetadata,
                notificationId: notificationId,
                credentialIssuerIdentifier: offer?.credentialIssuerIdentifier,
                credentialConfigurationId: offer?.credentialConfigurationId,
                batchId: batchId,
                instanceId: 0
            ), nil)
        }
        let payload = CredentialUtils.parseJwtPayload(raw)
        if payload == nil {
            return (nil, "Received credential could not be read")
        }
        if let reason = verifyIssuedType(format: format, raw: raw) {
            return (nil, reason)
        }
        let integrity = await verifyVctIntegrity(
            format: format, payload: payload ?? [:],
            offer: offer, document: activeVctmDocument
        )
        if let reason = integrity.reason {
            return (nil, reason)
        }
        // The stored credential, format-validated.
        return (StoredCredential(
            id: randomUint32Id(),
            format: format,
            raw: raw,
            metadata: offer.map { current in
                CredentialUtils.buildMetadata(
                    offer: current,
                    vctm: integrity.refreshed?.vctm ?? vctm,
                    rawCredential: raw
                )
            },
            issuedAt: (payload?["iat"] as? NSNumber)?.int64Value,
            expiresAt: (payload?["exp"] as? NSNumber)?.int64Value,
            notificationId: notificationId,
            credentialIssuerIdentifier: offer?.credentialIssuerIdentifier,
            credentialConfigurationId: offer?.credentialConfigurationId,
            batchId: batchId,
            instanceId: 0
        ), nil)
    }

    /// A credential lifecycle notification as a FLOW - siros-wallet-core's
    /// `credential_notification` (OpenID4x 3.4; the legacy `wmp.credential.notification`
    /// METHOD is go-wmp's and does not exist on the Rust engine). Best-effort like its
    /// legacy counterpart: a failure is logged, the flow it belongs to is already over.
    private func wmpSendCredentialNotification(flowId: String, notificationId: String, event: String) async {
        lock.lock(); let peer = wmpPeer; lock.unlock()
        guard let peer else { return }
        let params = AnyCodable.object_([
            "issuance_flow_id": .string(flowId),
            "notification_id": .string(notificationId),
            "event": .string(event),
        ])
        do {
            _ = try await peer.startFlow(
                flowType: "credential_notification",
                flowId: wmpNewFlowId(),
                params: params
            )
        } catch {
            #if canImport(os)
            logger.warning("Sending the credential notification for flow \(flowId) failed: \(error.localizedDescription)")
            #endif
        }
    }

    /// Back to Ready from a flow's end - the credentials re-read from the store, the user/display names kept.
    private func returnToReadyState() async {
        let creds = await credentialStore.getAll()
        lock.lock()
        let current = _state
        var reset: WalletState?
        if case .flowActive(let userId, let displayName, _, _, _, _) = current {
            reset = .ready(userId: userId, displayName: displayName, credentials: creds)
        } else if case .ready(let userId, let displayName, _, _) = current {
            reset = .ready(userId: userId, displayName: displayName, credentials: creds)
        }
        if let reset { _state = reset }
        lock.unlock()
    }
}

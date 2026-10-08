// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
import SirosKeystore

// Credential listing, deletion and proximity presentation, moved out of
// `SirosWallet.swift` unchanged to keep that file under the file-length limit.
extension SirosWallet {

    /// Get credentials, optionally including expired.
    public func getCredentials(includeExpired: Bool = false) async -> [StoredCredential] {
        let all = await credentialStore.getAll()
        if includeExpired { return all }
        let now = Int64(Date().timeIntervalSince1970)
        return all.filter { $0.expiresAt == nil || $0.expiresAt! > now }
    }

    /// Delete a credential by ID and sync to backend.
    public func deleteCredential(_ credentialId: Int64) async {
        let deletedBatchId = await credentialStore.getAll().first { $0.id == credentialId }?.batchId
        await credentialStore.delete(credentialId)
        // A deleted id can be reused (review finding) - an unrelated
        // credential later assigned this same id must not read back the
        // deleted one's cached status.
        credentialStatusCache.remove(credentialId)
        // If that was the last instance of its batch, its refresh_token
        // entry (if any) is now orphaned - privatedata-spec §6.2 requires
        // it not linger pointing at a batch that no longer exists.
        if let batchId = deletedBatchId {
            let remaining = await credentialStore.getAll()
            if !remaining.contains(where: { $0.batchId == batchId }) {
                await removeCredentialRefreshToken(batchId: batchId)
            }
        }
        if case .ready(let userId, let displayName, _, _) = state {
            let creds = await credentialStore.getAll()
            setState(.ready(userId: userId, displayName: displayName, credentials: creds))
        }
        await persistAndSyncKeystore()
    }

    /// Sign an mDoc DeviceResponse for an ISO 18013-5 proximity (BLE)
    /// presentation - the local, engine-free counterpart to the redirect/
    /// DC-API presentation paths (`handleSignRequest`/wallet-managed-protocol
    /// sign handling above), since proximity presentation has no
    /// wallet-backend/engine round trip at all: the reader IS the
    /// counterpart, connected directly over BLE.
    ///
    /// - Parameters:
    ///   - credentialId: the `StoredCredential.id` of the mdoc credential to present.
    ///   - disclosedClaims: element identifiers to disclose (see `DeviceRequestParser.DocRequest.disclosedClaims`).
    ///   - sessionTranscriptBytes: the proximity `SessionTranscript` bytes, from `ProximitySessionTranscript.build`.
    /// - Returns: CBOR-encoded DeviceResponse bytes.
    public func signMdocPresentationForProximity(
        credentialId: Int64,
        disclosedClaims: [String]?,
        sessionTranscriptBytes: Data
    ) async throws -> Data {
        guard let credential = await credentialStore.getById(credentialId) else {
            throw SirosError.wallet(message: "Credential not found: \(credentialId)")
        }
        let allInstances = await credentialStore.getAll().filter { $0.batchId == credential.batchId }
        let eligible = eligibleInstances(from: allInstances)
        guard eligible.contains(where: { $0.id == credentialId }) else {
            throw SirosError.wallet(message: "No eligible copies of this credential remain - renew it to get more")
        }
        guard let credBytes = CredentialUtils.base64UrlDecode(credential.raw) else {
            throw SirosError.wallet(message: "Credential \(credentialId) has malformed base64url raw data")
        }
        let response = try await keystore.signMdocPresentationForProximity(
            credentialBytes: credBytes,
            disclosedClaims: disclosedClaims,
            sessionTranscriptBytes: sessionTranscriptBytes,
            kid: credential.kid
        )
        await recordPresentation(PresentationRecord(
            id: randomUint32Id(),
            flowId: "proximity-\(UUID().uuidString)",
            credentialIds: [credentialId],
            credentialNames: [credential.metadata?.name].compactMap { $0 },
            requestedClaims: disclosedClaims ?? [],
            timestamp: Int64(Date().timeIntervalSince1970 * 1000)
        ))
        return response
    }
}

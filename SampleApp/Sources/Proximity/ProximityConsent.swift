// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials

/// One credential "type" as the user should see it: every `StoredCredential`
/// instance sharing a `StoredCredential.batchId` is the SAME credential from
/// a batch issuance (see `CredentialUtils.groupForDisplay`'s doc comment for
/// why - each instance is bound to its own device key purely for
/// unlinkability, not a distinct credential the user chose to hold multiple
/// of). The consent dialog must offer one choice per family, never one per
/// raw instance, or a 5-instance batch reads as "you have 5 driver's
/// licenses."
///
/// Ported from the Kotlin sample app's `ProximityConsent.kt`.
struct CredentialFamily: Equatable {
    /// The instance shown to the user for display (matches
    /// `CredentialUtils.groupForDisplay`'s convention of the `instanceId == 0` member).
    let representative: StoredCredential
    /// Every instance in this batch - `BlePeripheralServer`/`BleCentralClient`
    /// pick one of these to actually sign with once the family is approved.
    let instances: [StoredCredential]
}

/// Groups credentials into one `CredentialFamily` per `StoredCredential.batchId`.
func groupIntoFamilies(_ credentials: [StoredCredential]) -> [CredentialFamily] {
    var byBatch: [Int64: [StoredCredential]] = [:]
    for credential in credentials {
        byBatch[credential.batchId, default: []].append(credential)
    }
    return byBatch.values.map { members in
        CredentialFamily(
            representative: members.first(where: { $0.instanceId == 0 }) ?? members[0],
            instances: members
        )
    }
}

/// The user's answer to a `RequestProximityConsent` prompt.
enum ProximityConsentResult {
    case approved(CredentialFamily)
    case denied
}

/// Asks the user to approve a proximity presentation before it's signed and
/// sent - shared by `BlePeripheralServer` and `BleCentralClient` so both BLE
/// roles go through the same UI, implemented by `ProximityEngagementScreen`
/// as an async bridge to a SwiftUI consent sheet (mirrors Kotlin's
/// `suspendCancellableCoroutine` bridge to a Compose `AlertDialog` using
/// Swift's `withCheckedContinuation` instead).
///
/// - Parameters:
///   - docType: the requested document type.
///   - requestedClaims: the flattened element identifiers the reader asked for.
///   - matchingFamilies: every credential family whose docType matches
///     (never empty - callers only invoke this once at least one match
///     exists; see `CredentialFamily` for why this is families, not raw
///     instances), for the user to choose among if there's more than one
///     (e.g. the same docType from two different issuers).
typealias RequestProximityConsent = (
    _ docType: String,
    _ requestedClaims: [String],
    _ matchingFamilies: [CredentialFamily]
) async -> ProximityConsentResult

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Result of deactivating the wallet (`POST
/// /user/session/instances/revoke-all`) or revoking its last instance.
///
/// The backend records the revocation before it erases the data, so a call can
/// legitimately end with the instances revoked and the erasure unfinished
/// (`complete == false`, after `409 ERASURE_INCOMPLETE` survived the client's
/// retry budget). The wallet is deactivated either way - an administrator
/// finishes the cascade through the admin API - so a caller should forget its
/// local account in both cases and use `complete` only to decide what to tell
/// the user.
public struct DeactivationOutcome: Sendable, Equatable {
    /// How many instances this call revoked. A repeated (retry) call answers 0.
    public let revoked: Int
    /// True when the backend confirmed the erasure with a `200`.
    public let complete: Bool

    public init(revoked: Int, complete: Bool) {
        self.revoked = revoked
        self.complete = complete
    }
}

/// Backend error code for a `409` whose status change stands but whose erasure
/// must be retried (SID-AUTH-06, go-wallet-backend#319).
public let errorErasureIncomplete = "ERASURE_INCOMPLETE"

/// Backend error code for a `credential_id` that is not one of the caller's own
/// passkeys.
public let errorCredentialNotOwned = "CREDENTIAL_NOT_OWNED"

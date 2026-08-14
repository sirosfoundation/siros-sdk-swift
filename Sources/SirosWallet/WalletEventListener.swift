// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials

/// Context provided when a verifier requests credential presentation.
public struct PresentationRequest: Sendable {
    public var verifierName: String?
    /// Trust evaluation result with full metadata. Nil if trust was not evaluated.
    public var trustResult: TrustResult?
    public var candidates: [StoredCredential]
    public var requestedClaims: [[String]]

    public init(verifierName: String? = nil, trustResult: TrustResult? = nil, candidates: [StoredCredential], requestedClaims: [[String]] = []) {
        self.verifierName = verifierName
        self.trustResult = trustResult
        self.candidates = candidates
        self.requestedClaims = requestedClaims
    }
}

/// Callback protocol for wallet events that require user interaction.
///
/// Implement this and pass it to `SirosWallet.setEventListener()`.
public protocol WalletEventListener: AnyObject, Sendable {
    /// A verifier has requested credentials. Return the IDs the user consented to share.
    /// Return an empty list to cancel the presentation.
    func onCredentialSelectionRequired(request: PresentationRequest) async -> [Int64]

    /// A new credential has been received from an issuer.
    func onCredentialReceived(credential: StoredCredential)

    /// Called when a flow completes.
    ///
    /// - Parameter redirectUri: For an OID4VP `direct_post.jwt` presentation,
    ///   some verifiers (e.g. verifier.multipaz.org) return a `redirect_uri`
    ///   in their response so the user's browser/session can be returned to
    ///   the verifier's own page to see the result. When present, open it
    ///   (e.g. via `UIApplication.shared.open`), matching
    ///   `onAuthorizationRequired`'s pattern. Nil when the verifier didn't
    ///   return one (also true for every OID4VCI issuance completion).
    func onFlowComplete(flowId: String, redirectUri: String?)

    /// Called when a flow fails.
    ///
    /// - Parameter redirectUri: Some verifiers return a `redirect_uri` even
    ///   from their error-response endpoint (e.g. when the user declines an
    ///   OID4VP presentation) - see `onFlowComplete`'s equivalent parameter.
    ///   Nil unless the verifier provided one.
    func onFlowError(flowId: String, errorMessage: String, redirectUri: String?)

    /// An issuer requires user authorization (OAuth consent).
    func onAuthorizationRequired(flowId: String, authorizationUrl: String, redirectUri: String, state: String)

    /// An issuer requires a transaction code (PIN).
    /// Return the PIN value, or nil to cancel.
    func onTxCodeRequired(flowId: String, description: String?) -> String?

    /// The current session could not be silently refreshed and is no longer
    /// valid - e.g. the engine WebSocket's token refresh failed before a
    /// reconnect, or repeated REST calls were rejected as unauthenticated.
    /// `SirosWallet` has already logged out by the time this fires. Unlike
    /// `onFlowError` (a specific flow's failure, session otherwise fine),
    /// this means the whole session is gone - route the user to the login
    /// screen rather than surfacing a generic error message.
    func onReauthenticationRequired()

    /// A credential batch was renewed (credential re-issuance/renewal plan,
    /// Phase 2, `AttributeDiffService`-equivalent, ISSU_59) and at least one
    /// claim differs from the batch it replaced. The renewal's own network
    /// round-trip was silent (no user interaction), but ISSU_59 mandates
    /// notifying the user of any claim change - the app should surface this
    /// (e.g. wallet-frontend #73's consent/notification popup) even though
    /// `onCredentialReceived` already fired for the new credential.
    ///
    /// Not called when a renewal completes with identical claims (the fully
    /// silent case per plan §4.4) - only when `CredentialAttributeDiff.hasChanges`
    /// is true.
    func onCredentialRenewedWithAttributeDiff(credential: StoredCredential, diff: CredentialAttributeDiff)

    /// A credential batch's eligible (unused) instance count has dropped to
    /// or below its renew threshold (credential re-issuance/renewal plan
    /// §4.3/wallet-frontend #72 parity - EUDI ARF ISSU_50/54's proactive
    /// renewal trigger). The app should surface this as a near-expiry
    /// banner/nudge (Phase 3 UX, not yet built here) rather than waiting for
    /// the reactive fully-exhausted case. Fires at most once per drop below
    /// threshold per `SirosWallet.recordPresentation` call - not repeated on
    /// every recomposition.
    func onCredentialNearExpiry(credential: StoredCredential, eligibleRemaining: Int, threshold: Int)
}

/// Default implementations for optional callbacks.
public extension WalletEventListener {
    func onCredentialReceived(credential: StoredCredential) {}
    func onFlowComplete(flowId: String, redirectUri: String?) {}
    func onFlowError(flowId: String, errorMessage: String, redirectUri: String?) {}
    func onAuthorizationRequired(flowId: String, authorizationUrl: String, redirectUri: String, state: String) {}
    func onTxCodeRequired(flowId: String, description: String?) -> String? { nil }
    func onReauthenticationRequired() {
        // No-op by default: implementers only need to override this if they
        // want to route the user to a login screen on forced logout.
    }
    func onCredentialRenewedWithAttributeDiff(credential: StoredCredential, diff: CredentialAttributeDiff) {}
    func onCredentialNearExpiry(credential: StoredCredential, eligibleRemaining: Int, threshold: Int) {}
}

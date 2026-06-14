// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials

/// Context provided when a verifier requests credential presentation.
public struct PresentationRequest: Sendable {
    public var verifierName: String?
    public var candidates: [StoredCredential]
    public var requestedClaims: [[String]]

    public init(verifierName: String? = nil, candidates: [StoredCredential], requestedClaims: [[String]] = []) {
        self.verifierName = verifierName
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
    func onCredentialSelectionRequired(request: PresentationRequest) async -> [String]

    /// A new credential has been received from an issuer.
    func onCredentialReceived(credential: StoredCredential)

    /// Called when a flow completes.
    func onFlowComplete(flowId: String)

    /// Called when a flow fails.
    func onFlowError(flowId: String, errorMessage: String)

    /// An issuer requires user authorization (OAuth consent).
    func onAuthorizationRequired(flowId: String, authorizationUrl: String, redirectUri: String, state: String)

    /// An issuer requires a transaction code (PIN).
    /// Return the PIN value, or nil to cancel.
    func onTxCodeRequired(flowId: String, description: String?) -> String?
}

/// Default implementations for optional callbacks.
public extension WalletEventListener {
    func onCredentialReceived(credential: StoredCredential) {}
    func onFlowComplete(flowId: String) {}
    func onFlowError(flowId: String, errorMessage: String) {}
    func onAuthorizationRequired(flowId: String, authorizationUrl: String, redirectUri: String, state: String) {}
    func onTxCodeRequired(flowId: String, description: String?) -> String? { nil }
}

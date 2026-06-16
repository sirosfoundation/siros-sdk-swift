// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Result of an identity verification session.
///
/// The primary output is a `credentialOfferURI` that can be passed directly to
/// ``SirosWallet/startIssuance(offerUri:)`` to accept the issued credential.
public struct IDVResult: Sendable, Equatable {
    /// OID4VCI credential offer URI (e.g. `openid-credential-offer://...`).
    public let credentialOfferURI: String

    /// Opaque transaction ID for audit/support purposes. Provider-specific.
    public let transactionId: String?

    public init(credentialOfferURI: String, transactionId: String? = nil) {
        self.credentialOfferURI = credentialOfferURI
        self.transactionId = transactionId
    }
}

/// Errors that can occur during identity verification.
public enum IDVError: Error, Sendable {
    /// The user cancelled the verification flow.
    case cancelled
    /// The provider is not available on this device (e.g. no camera).
    case unavailable(reason: String)
    /// Liveness check failed.
    case livenessFailed(message: String)
    /// Document scan or face-match failed.
    case verificationFailed(message: String)
    /// Network or backend error.
    case networkError(underlying: Error)
    /// Provider-specific error.
    case providerError(code: String, message: String)
}

/// Plugin protocol for identity verification (document + liveness).
///
/// Implement this for any IDV vendor (FaceTec, iProov, Regula, Onfido, etc.).
/// The implementation manages its own capture UI and backend communication.
///
/// ## Contract
///
/// - ``startVerification(presentingViewController:)`` must present vendor-specific
///   UI (camera, document capture) and drive the full verification flow.
/// - On success, return an ``IDVResult`` containing the credential offer URI that
///   the backend issued after successful identity proofing.
/// - On failure/cancellation, throw an appropriate ``IDVError``.
///
/// ## Example
///
/// ```swift
/// let provider = FaceTecIDVProvider(apiUrl: "https://ft.example.com", deviceKey: "...")
/// try await wallet.verifyIdentityAndIssue(provider: provider, from: viewController)
/// ```
///
/// ## Thread Safety
///
/// Implementations must be safe to call from any actor context. UI presentation
/// should be dispatched to the main actor internally.
public protocol IdentityVerificationProvider: AnyObject, Sendable {
    /// Human-readable name of the provider (e.g. "FaceTec", "iProov").
    var name: String { get }

    /// Whether this provider is available on the current device.
    ///
    /// Check for camera availability, SDK initialization status, etc.
    func isAvailable() async -> Bool

    /// Start the identity verification flow.
    ///
    /// The implementation should:
    /// 1. Present its own capture UI (face scan, document photos)
    /// 2. Communicate with its backend to perform liveness/document checks
    /// 3. Trigger credential issuance on the backend
    /// 4. Return the resulting credential offer URI
    ///
    /// - Parameter presentingViewController: The UIViewController to present from.
    ///   Implementations should cast to `UIViewController` internally.
    /// - Throws: ``IDVError`` on failure or cancellation.
    /// - Returns: An ``IDVResult`` containing the credential offer URI.
    func startVerification(presentingViewController: Any) async throws -> IDVResult
}

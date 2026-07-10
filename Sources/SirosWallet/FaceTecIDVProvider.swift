// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// FaceTec biometric capture delegate.
///
/// Implements ``BiometricCaptureDelegate`` by wrapping the FaceTec mobile SDK.
/// The actual HTTP communication is handled by ``RemoteIDVClient``.
///
/// ## Setup
///
/// ```swift
/// let client = RemoteIDVClient(config: .init(serverUrl: "...", authToken: "..."))
/// let delegate = FaceTecCaptureDelegate()
/// let provider = RemoteIDVProvider(client: client, delegate: delegate)
/// try await wallet.verifyIdentityAndIssue(provider: provider, presentingViewController: vc)
/// ```
public final class FaceTecCaptureDelegate: @unchecked Sendable, BiometricCaptureDelegate {

    public var name: String { "FaceTec" }

    public init() {}

    public func isAvailable() async -> Bool {
        NSClassFromString("FaceTecSDK") != nil
    }

    public func captureLiveness(presentingViewController: Any, sessionToken: String) async throws -> [String: Any] {
        // TODO: Implement with FaceTec SDK
        // 1. Initialize FaceTec SDK if needed
        // 2. Create FaceTecSession, capture FaceScan
        // 3. Return: ["faceScan": ..., "auditTrailImage": ..., "lowQualityAuditTrailImage": ...]
        throw IDVError.unavailable(reason: "FaceTec SDK not linked. Add FaceTec framework and implement captureLiveness().")
    }

    public func captureDocument(presentingViewController: Any, sessionToken: String, livenessSessionId: String) async throws -> [String: Any] {
        // TODO: Implement with FaceTec SDK
        // 1. Create FaceTecIDScanSession, capture document
        // 2. Return: ["idScanFrontImage": ..., "livenessSessionId": livenessSessionId]
        throw IDVError.unavailable(reason: "FaceTec SDK not linked. Add FaceTec framework and implement captureDocument().")
    }
}

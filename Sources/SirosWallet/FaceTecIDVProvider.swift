// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// FaceTec biometric capture delegate.
///
/// Implements ``BiometricCaptureDelegate`` by wrapping the FaceTec mobile SDK.
/// The actual HTTP communication is handled by ``RemoteIDVClient``.
///
/// ## FaceTec SDK Dependency
///
/// The FaceTec SDK XCFramework is distributed via a private SPM package
/// configured in CI secrets (`FACETEC_PACKAGE_URL`).
/// See the project's Package.swift for dependency setup.
///
/// ## Usage
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
        // FaceTec SDK integration point:
        // 1. Initialize FaceTec SDK (FaceTec.sdk.initializeInProductionMode(...))
        // 2. Create FaceTecSession, capture FaceScan via delegate
        // 3. Return: ["faceScan": ..., "auditTrailImage": ..., "lowQualityAuditTrailImage": ...]
        //
        // To implement: link FaceTecSDK.xcframework and replace this throw.
        throw IDVError.unavailable(reason: "FaceTec SDK not linked. Add FaceTecSDK.xcframework to your app target.")
    }

    public func captureDocument(presentingViewController: Any, sessionToken: String, livenessSessionId: String) async throws -> [String: Any] {
        // FaceTec SDK integration point:
        // 1. Create FaceTecIDScanSession, capture document via delegate
        // 2. Return: ["idScanFrontImage": ..., "livenessSessionId": livenessSessionId]
        //
        // To implement: link FaceTecSDK.xcframework and replace this throw.
        throw IDVError.unavailable(reason: "FaceTec SDK not linked. Add FaceTecSDK.xcframework to your app target.")
    }
}

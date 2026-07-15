// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(UIKit)
import UIKit
#endif
#if canImport(FaceTecSDK)
import FaceTecSDK
#endif

/// FaceTec biometric capture delegate.
///
/// Implements ``BiometricCaptureDelegate`` by wrapping the FaceTec mobile SDK
/// using the FaceScanProcessor/IDScanProcessor pattern. The captured biometric
/// data (faceScan, auditTrailImages) is passed to ``RemoteIDVClient`` which
/// uploads it to the IDV backend for server-side processing.
///
/// When FaceTecSDK is not linked, all methods throw ``IDVError/unavailable``.
public final class FaceTecCaptureDelegate: @unchecked Sendable, BiometricCaptureDelegate {

    public var name: String { "FaceTec" }

    public init() {}

    public func isAvailable() async -> Bool {
        #if canImport(FaceTecSDK)
        return FaceTec.sdk.getStatus() == .initialized
        #else
        return false
        #endif
    }

    public func captureLiveness(presentingViewController: Any, sessionToken: String) async throws -> [String: Any] {
        #if canImport(FaceTecSDK) && canImport(UIKit)
        guard let viewController = presentingViewController as? UIViewController else {
            throw IDVError.unavailable(reason: "presentingViewController must be a UIViewController")
        }

        return try await withCheckedThrowingContinuation { continuation in
            let processor = LivenessSessionProcessor(
                sessionToken: sessionToken,
                continuation: continuation
            )
            DispatchQueue.main.async {
                let sessionVC = FaceTec.sdk.createSessionVC(
                    faceScanProcessorDelegate: processor,
                    sessionToken: sessionToken
                )
                viewController.present(sessionVC, animated: true)
            }
        }
        #else
        throw IDVError.unavailable(reason: "FaceTec SDK not linked. Add FaceTecSDK.xcframework to your app target.")
        #endif
    }

    public func captureDocument(presentingViewController: Any, sessionToken: String, livenessSessionId: String) async throws -> [String: Any] {
        #if canImport(FaceTecSDK) && canImport(UIKit)
        guard let viewController = presentingViewController as? UIViewController else {
            throw IDVError.unavailable(reason: "presentingViewController must be a UIViewController")
        }

        return try await withCheckedThrowingContinuation { continuation in
            let processor = DocumentScanProcessor(
                sessionToken: sessionToken,
                livenessSessionId: livenessSessionId,
                continuation: continuation
            )
            DispatchQueue.main.async {
                let sessionVC = FaceTec.sdk.createSessionVC(
                    idScanProcessorDelegate: processor,
                    sessionToken: sessionToken
                )
                viewController.present(sessionVC, animated: true)
            }
        }
        #else
        throw IDVError.unavailable(reason: "FaceTec SDK not linked. Add FaceTecSDK.xcframework to your app target.")
        #endif
    }
}

// MARK: - FaceTec Session Processors

#if canImport(FaceTecSDK) && canImport(UIKit)

/// Handles FaceTec liveness (FaceScan) capture via the FaceScanProcessor delegate.
private final class LivenessSessionProcessor: NSObject, FaceTecFaceScanProcessorDelegate {
    private let sessionToken: String
    private var continuation: CheckedContinuation<[String: Any], Error>?

    init(sessionToken: String, continuation: CheckedContinuation<[String: Any], Error>) {
        self.sessionToken = sessionToken
        self.continuation = continuation
        super.init()
    }

    func processSessionWhileFaceTecSDKWaits(
        sessionResult: FaceTecSessionResult,
        faceScanResultCallback: FaceTecFaceScanResultCallback
    ) {
        guard sessionResult.status == .sessionCompletedSuccessfully else {
            let reason = "FaceTec liveness session ended with status: \(sessionResult.status.rawValue)"
            continuation?.resume(throwing: IDVError.cancelled(reason: reason))
            continuation = nil
            faceScanResultCallback.onFaceScanResultCancel()
            return
        }

        // Extract biometric data for upload to IDV backend
        let payload: [String: Any] = [
            "faceScan": sessionResult.faceScanBase64 ?? "",
            "auditTrailImage": sessionResult.auditTrailCompressedBase64?.first ?? "",
            "lowQualityAuditTrailImage": sessionResult.lowQualityAuditTrailCompressedBase64?.first ?? "",
            "sessionId": sessionResult.sessionId ?? "",
        ]

        continuation?.resume(returning: payload)
        continuation = nil
        // Signal SDK we're done (server-side processing happens via RemoteIDVClient)
        faceScanResultCallback.onFaceScanGoToNextStep(scanResultBlob: "")
    }

    func onFaceTecSDKCompletelyDone() {
        if let cont = continuation {
            cont.resume(throwing: IDVError.cancelled(reason: "FaceTec liveness session dismissed by user"))
            continuation = nil
        }
    }
}

/// Handles FaceTec document (ID scan) capture via the IDScanProcessor delegate.
private final class DocumentScanProcessor: NSObject, FaceTecIDScanProcessorDelegate {
    private let sessionToken: String
    private let livenessSessionId: String
    private var continuation: CheckedContinuation<[String: Any], Error>?

    init(sessionToken: String, livenessSessionId: String, continuation: CheckedContinuation<[String: Any], Error>) {
        self.sessionToken = sessionToken
        self.livenessSessionId = livenessSessionId
        self.continuation = continuation
        super.init()
    }

    func processIDScanWhileFaceTecSDKWaits(
        idScanResult: FaceTecIDScanResult,
        idScanResultCallback: FaceTecIDScanResultCallback
    ) {
        guard idScanResult.status == .success else {
            let reason = "FaceTec ID scan ended with status: \(idScanResult.status.rawValue)"
            continuation?.resume(throwing: IDVError.cancelled(reason: reason))
            continuation = nil
            idScanResultCallback.onIDScanResultCancel()
            return
        }

        let payload: [String: Any] = [
            "idScanFrontImage": idScanResult.frontImagesCompressedBase64?.first ?? "",
            "idScanBackImage": idScanResult.backImagesCompressedBase64?.first ?? "",
            "livenessSessionId": livenessSessionId,
            "sessionId": idScanResult.sessionId ?? "",
        ]

        continuation?.resume(returning: payload)
        continuation = nil
        idScanResultCallback.onIDScanResultGoToNextStep(scanResultBlob: "")
    }

    func onFaceTecSDKCompletelyDone() {
        if let cont = continuation {
            cont.resume(throwing: IDVError.cancelled(reason: "FaceTec ID scan dismissed by user"))
            continuation = nil
        }
    }
}

#endif

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// FaceTec identity verification provider for iOS.
///
/// Wraps the FaceTec mobile SDK and facetec-api server to perform
/// liveness detection + document verification, returning a
/// credential offer URI for OID4VCI issuance.
///
/// ## Prerequisites
///
/// 1. Add the FaceTec SDK via CocoaPods or SPM
/// 2. Initialize with your facetec-api server URL:
///    ```swift
///    let idvProvider = FaceTecIDVProvider(
///        serverUrl: "https://idv.example.com",
///        authToken: "Bearer <access-token>"
///    )
///    try await wallet.verifyIdentityAndIssue(provider: idvProvider, presentingViewController: vc)
///    ```
///
/// ## Flow
///
/// 1. Get session token from facetec-api
/// 2. FaceTec SDK captures liveness (FaceScan)
/// 3. Send FaceScan to facetec-api → livenessSessionId
/// 4. FaceTec SDK captures document (ID scan)
/// 5. Send document + livenessSessionId → credentialOfferURI
/// 6. Return IDVResult for OID4VCI issuance
public final class FaceTecIDVProvider: @unchecked Sendable, IdentityVerificationProvider {

    /// Base URL of the facetec-api server.
    private let serverUrl: String
    /// Authorization header value.
    private let authToken: String
    /// URL session for HTTP calls.
    private let session: URLSession

    public var name: String { "FaceTec" }

    public init(serverUrl: String, authToken: String, session: URLSession = .shared) {
        self.serverUrl = serverUrl.hasSuffix("/") ? String(serverUrl.dropLast()) : serverUrl
        self.authToken = authToken
        self.session = session
    }

    public func isAvailable() async -> Bool {
        // Check if FaceTec framework is available at runtime
        return NSClassFromString("FaceTecSDK") != nil
    }

    public func startVerification(presentingViewController: Any) async throws -> IDVResult {
        // Step 1: Get session token
        let sessionToken = try await getSessionToken()

        // Steps 2-5: FaceTec SDK UI flow
        // The FaceTec SDK presents its own UI from the given view controller.
        // Once implemented, it will:
        // 1. Capture liveness → submit to /v1/liveness → livenessSessionId
        // 2. Capture document → submit to /v1/id-scan → credentialOfferURI

        _ = sessionToken
        throw IDVError.unavailable(reason: "FaceTec SDK not yet linked. " +
            "Add FaceTec framework dependency and implement capture flow. " +
            "Use submitLiveness() and submitIDScan() from FaceTec callbacks.")
    }

    // MARK: - Public API for FaceTec SDK callbacks

    /// Get a session token for initializing the FaceTec SDK.
    public func getSessionToken() async throws -> String {
        guard let url = URL(string: "\(serverUrl)/v1/session-token") else {
            throw IDVError.networkError(underlying: URLError(.badURL))
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(authToken, forHTTPHeaderField: "Authorization")
        request.httpBody = "{}".data(using: .utf8)

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw IDVError.networkError(underlying: URLError(.badServerResponse))
        }

        let decoded = try JSONDecoder().decode(SessionTokenResponse.self, from: data)
        return decoded.sessionToken
    }

    /// Submit a liveness FaceScan to the facetec-api server.
    ///
    /// Call this from the FaceTec SDK delegate after a successful liveness session.
    ///
    /// - Parameters:
    ///   - faceScan: Base64-encoded FaceScan data from FaceTec SDK.
    ///   - auditTrailImage: Base64-encoded audit trail image.
    ///   - lowQualityAuditTrailImage: Base64-encoded low quality audit trail.
    /// - Returns: `livenessSessionId` for use in the subsequent ID scan call.
    public func submitLiveness(
        faceScan: String,
        auditTrailImage: String,
        lowQualityAuditTrailImage: String
    ) async throws -> String {
        guard let url = URL(string: "\(serverUrl)/v1/liveness") else {
            throw IDVError.networkError(underlying: URLError(.badURL))
        }

        let body = LivenessScanRequest(
            faceScan: faceScan,
            auditTrailImage: auditTrailImage,
            lowQualityAuditTrailImage: lowQualityAuditTrailImage
        )

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(authToken, forHTTPHeaderField: "Authorization")
        request.httpBody = try JSONEncoder().encode(body)

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw IDVError.networkError(underlying: URLError(.badServerResponse))
        }

        if http.statusCode == 422 {
            throw IDVError.livenessFailed(message: String(data: data, encoding: .utf8) ?? "Liveness check failed")
        }
        guard http.statusCode == 200 else {
            throw IDVError.networkError(underlying: URLError(.badServerResponse))
        }

        let decoded = try JSONDecoder().decode(LivenessResponse.self, from: data)
        return decoded.livenessSessionId
    }

    /// Submit an ID scan to the facetec-api server.
    ///
    /// Call this from the FaceTec SDK delegate after a successful ID scan session.
    ///
    /// - Parameters:
    ///   - idScanFrontImage: Base64-encoded front of document.
    ///   - idScanBackImage: Base64-encoded back of document (optional).
    ///   - livenessSessionId: From the previous `submitLiveness()` call.
    /// - Returns: `IDScanResult` with `credentialOfferURI` for OID4VCI issuance.
    public func submitIDScan(
        idScanFrontImage: String,
        idScanBackImage: String? = nil,
        livenessSessionId: String
    ) async throws -> IDScanResult {
        guard let url = URL(string: "\(serverUrl)/v1/id-scan") else {
            throw IDVError.networkError(underlying: URLError(.badURL))
        }

        let body = IDScanRequest(
            idScanFrontImage: idScanFrontImage,
            idScanBackImage: idScanBackImage,
            livenessSessionId: livenessSessionId
        )

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(authToken, forHTTPHeaderField: "Authorization")
        request.httpBody = try JSONEncoder().encode(body)

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw IDVError.networkError(underlying: URLError(.badServerResponse))
        }

        if http.statusCode == 422 {
            throw IDVError.verificationFailed(message: String(data: data, encoding: .utf8) ?? "ID verification failed")
        }
        guard http.statusCode == 200 else {
            throw IDVError.networkError(underlying: URLError(.badServerResponse))
        }

        return try JSONDecoder().decode(IDScanResult.self, from: data)
    }

    // MARK: - Data types

    private struct SessionTokenResponse: Decodable {
        let sessionToken: String
    }

    private struct LivenessScanRequest: Encodable {
        let faceScan: String
        let auditTrailImage: String
        let lowQualityAuditTrailImage: String
    }

    private struct LivenessResponse: Decodable {
        let livenessSessionId: String
    }

    private struct IDScanRequest: Encodable {
        let idScanFrontImage: String
        let idScanBackImage: String?
        let livenessSessionId: String
    }

    /// Result of a successful ID scan + credential issuance.
    public struct IDScanResult: Decodable, Sendable {
        public let transactionId: String
        public let credentialOfferURI: String
    }
}

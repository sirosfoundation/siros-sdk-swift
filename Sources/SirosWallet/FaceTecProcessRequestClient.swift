// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// facetec-api's answer to one `/process-request` call.
struct ProcessRequestResponse: Sendable, Equatable {
    /// Opaque FaceTec Server response, handed back to the FaceTec SDK.
    let responseBlob: String
    /// Set once facetec-api has issued a credential for the session.
    var credentialOfferURI: String?
    /// facetec-api's transaction ID for the issued credential, if any.
    var transactionId: String?
    /// Set when the scan completed but facetec-api refused to issue, e.g.
    /// `nfc_skipped` or `policy_rejected` (see ``IDVError/init(refusalCode:message:)``).
    var credentialIssueErrorCode: String?
    /// facetec-api's human-readable reason for the refusal, if any.
    var credentialIssueError: String?
}

/// Why a process-request call could not be used. The messages deliberately
/// leave out the response body: it can echo request data, and these errors end
/// up in logs.
enum ProcessRequestFailure: Error, Equatable, CustomStringConvertible {
    case httpStatus(Int)
    case notJson
    case noResponseBlob
    case notHttp

    var description: String {
        switch self {
        case .httpStatus(let status): return "process-request failed with HTTP \(status)"
        case .notJson: return "process-request returned a body that is not JSON"
        case .noResponseBlob: return "process-request response has no responseBlob"
        case .notHttp: return "process-request got no HTTP response"
        }
    }
}

/// Posts FaceTec 10 session request blobs to facetec-api's `/process-request`.
struct FaceTecProcessRequestClient: Sendable {
    typealias Transport = @Sendable (URLRequest) async throws -> (Data, URLResponse)

    private let config: FaceTecIDVConfig
    private let transport: Transport

    init(config: FaceTecIDVConfig, transport: @escaping Transport = { try await URLSession.shared.data(for: $0) }) {
        self.config = config
        self.transport = transport
    }

    /// - Throws: ``ProcessRequestFailure``, or whatever the transport threw. The
    ///   relay turns any of these into an aborted FaceTec session.
    func post(requestBlob: String, externalDatabaseRefID: String) async throws -> ProcessRequestResponse {
        var request = URLRequest(url: config.processRequestUrl, timeoutInterval: config.requestTimeout)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(config.authToken, forHTTPHeaderField: "Authorization")
        request.httpBody = try JSONSerialization.data(withJSONObject: [
            "requestBlob": requestBlob,
            "externalDatabaseRefID": externalDatabaseRefID,
        ])

        let (data, response) = try await transport(request)
        guard let http = response as? HTTPURLResponse else { throw ProcessRequestFailure.notHttp }
        guard (200..<300).contains(http.statusCode) else { throw ProcessRequestFailure.httpStatus(http.statusCode) }
        guard let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
            throw ProcessRequestFailure.notJson
        }
        guard let responseBlob = json["responseBlob"] as? String, !responseBlob.isEmpty else {
            throw ProcessRequestFailure.noResponseBlob
        }

        func nonBlank(_ key: String) -> String? {
            guard let value = json[key] as? String, !value.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
            return value
        }
        return ProcessRequestResponse(
            responseBlob: responseBlob,
            credentialOfferURI: nonBlank("credentialOfferURI"),
            transactionId: nonBlank("transactionId"),
            credentialIssueErrorCode: nonBlank("credentialIssueErrorCode"),
            credentialIssueError: nonBlank("credentialIssueError")
        )
    }
}

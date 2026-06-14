// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosCredentials

/// Type alias for an injectable HTTP function used by BackendApiClient.
/// Parameters: method, URL, headers, optional body. Returns: response data.
public typealias HttpFunction = @Sendable (String, URL, [String: String], Data?) async throws -> Data

/// Authenticated HTTP client for the wallet backend REST API.
///
/// Requires a valid `appToken` (JWT) obtained from `WebAuthnAuthClient.login()`
/// or `WebAuthnAuthClient.register()`.
public final class BackendApiClient: @unchecked Sendable {

    private let baseUrl: String
    private let tenantId: String
    private let httpFn: HttpFunction
    private let lock = NSLock()
    private var _appToken: String?

    /// Create a client with a custom HTTP function (for testing).
    public init(
        baseUrl: String,
        tenantId: String = "default",
        httpFn: @escaping HttpFunction
    ) {
        self.baseUrl = baseUrl
        self.tenantId = tenantId
        self.httpFn = httpFn
    }

    #if !os(Linux)
    /// Create a client using URLSession for HTTP.
    public convenience init(baseUrl: String, tenantId: String = "default") {
        self.init(baseUrl: baseUrl, tenantId: tenantId) { method, url, headers, body in
            var request = URLRequest(url: url)
            request.httpMethod = method
            request.httpBody = body
            for (key, value) in headers {
                request.setValue(value, forHTTPHeaderField: key)
            }
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse else {
                throw SirosError.network(message: "Invalid response")
            }
            guard (200..<300).contains(httpResponse.statusCode) else {
                let bodyStr = String(data: data, encoding: .utf8) ?? ""
                throw SirosError.backendApi(
                    code: httpResponse.statusCode,
                    message: "API request failed: \(httpResponse.statusCode)",
                    body: bodyStr
                )
            }
            return data
        }
    }
    #endif

    public func setAppToken(_ token: String) {
        lock.lock()
        defer { lock.unlock() }
        _appToken = token
    }

    // MARK: - API endpoints

    /// GET /user/session/account-info
    public func getAccountInfo() async throws -> [String: Any] {
        try await get("/user/session/account-info")
    }

    /// GET /storage/vc — list all credentials
    public func getCredentials() async throws -> [String: Any] {
        try await get("/storage/vc")
    }

    /// POST /storage/vc — store a credential
    public func storeCredential(_ credential: [String: Any]) async throws -> [String: Any] {
        try await post("/storage/vc", body: credential)
    }

    /// GET /storage/vc/:id
    public func getCredential(id: String) async throws -> [String: Any] {
        try await get("/storage/vc/\(id)")
    }

    /// DELETE /storage/vc/:id
    public func deleteCredential(id: String) async throws -> [String: Any] {
        try await delete("/storage/vc/\(id)")
    }

    /// GET /issuer/all — list registered issuers
    public func getIssuers() async throws -> Any {
        try await getRaw("/issuer/all")
    }

    /// GET /issuer/:id/metadata
    public func getIssuerMetadata(id: Int) async throws -> [String: Any] {
        try await get("/issuer/\(id)/metadata")
    }

    /// GET /verifier/all — list registered verifiers
    public func getVerifiers() async throws -> [String: Any] {
        try await get("/verifier/all")
    }

    /// GET /user/session/private-data
    public func getPrivateData() async throws -> [String: Any] {
        try await get("/user/session/private-data")
    }

    /// POST /user/session/private-data
    public func updatePrivateData(_ data: [String: Any]) async throws -> [String: Any] {
        try await post("/user/session/private-data", body: data)
    }

    /// GET /health
    public func healthCheck() async throws -> [String: Any] {
        try await get("/health")
    }

    /// GET /api/v1/tenants/:id/config
    public func getTenantConfig() async throws -> [String: Any] {
        try await get("/api/v1/tenants/\(tenantId)/config")
    }

    /// POST /v1/evaluate — AuthZEN trust evaluation
    public func evaluateTrust(_ requestBody: [String: Any]) async throws -> [String: Any] {
        try await post("/v1/evaluate", body: requestBody)
    }

    /// POST /user/session/refresh — refresh appToken
    public func refreshSession(refreshToken: String) async throws -> [String: Any] {
        try await post("/user/session/refresh", body: ["refreshToken": refreshToken])
    }

    // MARK: - HTTP primitives

    private func get(_ path: String) async throws -> [String: Any] {
        let data = try await request("GET", path: path)
        return try parseJsonObject(data)
    }

    private func getRaw(_ path: String) async throws -> Any {
        let data = try await request("GET", path: path)
        return try JSONSerialization.jsonObject(with: data)
    }

    private func post(_ path: String, body: [String: Any]) async throws -> [String: Any] {
        let bodyData = try JSONSerialization.data(withJSONObject: body)
        let data = try await request("POST", path: path, body: bodyData)
        return try parseJsonObject(data)
    }

    private func delete(_ path: String) async throws -> [String: Any] {
        let data = try await request("DELETE", path: path)
        return try parseJsonObject(data)
    }

    private func request(_ method: String, path: String, body: Data? = nil) async throws -> Data {
        guard let url = URL(string: "\(baseUrl)\(path)") else {
            throw SirosError.network(message: "Invalid URL: \(baseUrl)\(path)")
        }
        var headers: [String: String] = [
            "X-Tenant-ID": tenantId,
            "Content-Type": "application/json",
        ]
        if let token = currentAppToken() {
            headers["Authorization"] = "Bearer \(token)"
        }
        return try await httpFn(method, url, headers, body)
    }

    private func currentAppToken() -> String? {
        lock.lock()
        defer { lock.unlock() }
        return _appToken
    }

    private func parseJsonObject(_ data: Data) throws -> [String: Any] {
        if data.isEmpty {
            return [:]
        }
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return [:]
        }
        return json
    }
}

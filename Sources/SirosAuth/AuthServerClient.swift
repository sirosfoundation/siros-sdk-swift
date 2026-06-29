// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosCredentials

// MARK: - Response Models

/// Result of a successful login via the AS.
public struct LoginFinishResult: Codable, Sendable {
    public let uuid: String
    public let displayName: String
    public let tenantId: String
}

/// Result of a successful registration via the AS.
public struct RegisterFinishResult: Codable, Sendable {
    public let uuid: String
    public let displayName: String
    public let tenantId: String
}

// MARK: - AuthServerClient

/// HTTP client for the new Authorization Server endpoints.
///
/// Handles passkey login/register flows via `/auth/passkey/` and token
/// requests via `/auth/token`. Uses session cookies for authentication
/// (set by the AS on successful login/register).
///
/// Mirrors the TypeScript `AuthServerClient` from wallet-frontend PR 177.
public final class AuthServerClient: @unchecked Sendable {

    private let baseUrl: String
    private let tenantId: String
    private let httpFn: @Sendable (String, URL, [String: String], Data?) async throws -> Data
    private let cache = TokenCache()

    /// Create a client with a custom HTTP function (for testing / custom networking).
    ///
    /// The `httpFn` receives `(method, url, headers, body)` and returns the response body.
    /// It MUST handle cookie storage for session cookies to work.
    public init(
        baseUrl: String,
        tenantId: String = "default",
        httpFn: @escaping @Sendable (String, URL, [String: String], Data?) async throws -> Data
    ) {
        self.baseUrl = baseUrl
        self.tenantId = tenantId
        self.httpFn = httpFn
    }

    #if !os(Linux)
    /// Create a client using a shared URLSession with cookie storage.
    public convenience init(baseUrl: String, tenantId: String = "default") {
        let config = URLSessionConfiguration.default
        config.httpCookieAcceptPolicy = .always
        config.httpCookieStorage = HTTPCookieStorage.shared
        let session = URLSession(configuration: config)

        self.init(baseUrl: baseUrl, tenantId: tenantId) { method, url, headers, body in
            var request = URLRequest(url: url)
            request.httpMethod = method
            request.httpBody = body
            for (key, value) in headers {
                request.setValue(value, forHTTPHeaderField: key)
            }
            let (data, response) = try await session.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse,
                  (200..<300).contains(httpResponse.statusCode) else {
                let code = (response as? HTTPURLResponse)?.statusCode ?? 0
                let bodyStr = String(data: data, encoding: .utf8) ?? ""
                throw SirosError.backendApi(code: code, message: "AS request failed: \(code)", body: bodyStr)
            }
            return data
        }
    }
    #endif

    // MARK: - Passkey Login

    /// Begin a passkey login flow.
    ///
    /// - Parameter oidcIdToken: Optional OIDC ID token for pre-authenticated login.
    /// - Returns: Parsed challenge response with `challengeId` and `getOptions`.
    public func loginBegin(oidcIdToken: String? = nil) async throws -> [String: Any] {
        var headers = defaultHeaders()
        if let token = oidcIdToken {
            headers["Authorization"] = "Bearer \(token)"
        }
        let response = try await post(path: "/auth/passkey/login/begin", body: [:], headers: headers)
        return TaggedBinary.decode(response)
    }

    /// Finish a passkey login flow.
    ///
    /// - Parameters:
    ///   - challengeId: The challenge ID from loginBegin.
    ///   - credential: The serialized WebAuthn credential assertion.
    ///   - oidcIdToken: Optional OIDC ID token.
    /// - Returns: Login result with `uuid`, `displayName`, `tenantId`.
    public func loginFinish(
        challengeId: String,
        credential: [String: Any],
        oidcIdToken: String? = nil
    ) async throws -> LoginFinishResult {
        var headers = defaultHeaders()
        if let token = oidcIdToken {
            headers["Authorization"] = "Bearer \(token)"
        }
        let body: [String: Any] = [
            "challengeId": challengeId,
            "credential": credential,
        ]
        let response = try await post(path: "/auth/passkey/login/finish", body: body, headers: headers)
        let data = try JSONSerialization.data(withJSONObject: response)
        return try JSONDecoder().decode(LoginFinishResult.self, from: data)
    }

    // MARK: - Passkey Registration

    /// Begin a passkey registration flow.
    ///
    /// - Parameters:
    ///   - inviteCode: Optional invite code for gated registration.
    ///   - oidcIdToken: Optional OIDC ID token for pre-authenticated registration.
    /// - Returns: Parsed challenge response with `challengeId` and `createOptions`.
    public func registerBegin(
        inviteCode: String? = nil,
        oidcIdToken: String? = nil
    ) async throws -> [String: Any] {
        var headers = defaultHeaders()
        if let token = oidcIdToken {
            headers["Authorization"] = "Bearer \(token)"
        }
        var body: [String: Any] = ["tenantId": tenantId]
        if let code = inviteCode {
            body["inviteCode"] = code
        }
        let response = try await post(path: "/auth/passkey/register/begin", body: body, headers: headers)
        return TaggedBinary.decode(response)
    }

    /// Finish a passkey registration flow.
    ///
    /// - Parameters:
    ///   - challengeId: The challenge ID from registerBegin.
    ///   - credential: The serialized WebAuthn credential attestation.
    ///   - displayName: Display name for the new user.
    ///   - privateData: Optional initial private data (encrypted keystore).
    ///   - oidcIdToken: Optional OIDC ID token.
    /// - Returns: Registration result with `uuid`, `displayName`, `tenantId`.
    public func registerFinish(
        challengeId: String,
        credential: [String: Any],
        displayName: String,
        privateData: Any? = nil,
        oidcIdToken: String? = nil
    ) async throws -> RegisterFinishResult {
        var headers = defaultHeaders()
        if let token = oidcIdToken {
            headers["Authorization"] = "Bearer \(token)"
        }
        var body: [String: Any] = [
            "challengeId": challengeId,
            "displayName": displayName,
            "credential": credential,
        ]
        if let pd = privateData {
            body["privateData"] = pd
        }
        let response = try await post(path: "/auth/passkey/register/finish", body: body, headers: headers)
        let data = try JSONSerialization.data(withJSONObject: response)
        return try JSONDecoder().decode(RegisterFinishResult.self, from: data)
    }

    // MARK: - Token Endpoint

    /// Request an access token from the AS token endpoint.
    /// Caches tokens and returns cached ones if not expired.
    ///
    /// - Parameters:
    ///   - aud: Target audience (e.g., "wallet-backend").
    ///   - tac: Token Access Control string (e.g., "rwlid").
    /// - Returns: Parsed `AccessToken` with claims.
    public func requestAccessToken(aud: String, tac: String? = nil) async throws -> AccessToken {
        let key = "\(tenantId)::\(aud)::\(tac ?? "")"

        // Check cache
        if let cached = await cache.get(key), !cached.isExpired() {
            return cached
        }

        var body: [String: Any] = [
            "aud": aud,
            "tenant_id": tenantId,
        ]
        if let tac = tac {
            body["tac"] = tac
        }
        let response = try await post(
            path: "/auth/token",
            body: body,
            headers: ["X-Token-Mode": "session"]
        )
        let data = try JSONSerialization.data(withJSONObject: response)
        let tokenResponse = try JSONDecoder().decode(TokenResponse.self, from: data)
        let token = try AccessToken(jwt: tokenResponse.accessToken)

        await cache.set(key, token)

        return token
    }

    // MARK: - Logout

    /// End the current session.
    public func logout() async throws {
        guard let url = URL(string: "\(baseUrl)/auth/session") else {
            throw SirosError.auth(message: "Invalid URL")
        }
        _ = try await httpFn("DELETE", url, [:], nil)
        await cache.clear()
    }

    // MARK: - Private

    private func defaultHeaders() -> [String: String] {
        [
            "X-Token-Mode": "session",
            "X-Tenant-ID": tenantId,
        ]
    }

    private func post(
        path: String,
        body: [String: Any],
        headers: [String: String] = [:]
    ) async throws -> [String: Any] {
        guard let url = URL(string: "\(baseUrl)\(path)") else {
            throw SirosError.auth(message: "Invalid URL: \(baseUrl)\(path)")
        }
        var allHeaders = headers
        allHeaders["Content-Type"] = "application/json"
        let bodyData = try JSONSerialization.data(withJSONObject: body)
        let responseData = try await httpFn("POST", url, allHeaders, bodyData)
        guard let json = try JSONSerialization.jsonObject(with: responseData) as? [String: Any] else {
            throw SirosError.auth(message: "Invalid JSON response")
        }
        return json
    }
}

// MARK: - Token Cache

/// Actor-isolated cache for access tokens.
private actor TokenCache {
    private var tokens: [String: AccessToken] = [:]

    func get(_ key: String) -> AccessToken? { tokens[key] }
    func set(_ key: String, _ token: AccessToken) { tokens[key] = token }
    func clear() { tokens.removeAll() }
}

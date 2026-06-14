// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosCredentials

/// Handles WebAuthn registration/login flows against the wallet backend REST API.
/// Coordinates between the backend challenge endpoints and the `AuthProvider` for
/// credential creation/assertion.
public final class WebAuthnAuthClient: @unchecked Sendable {

    private let baseUrl: String
    private let tenantId: String
    private let authProvider: AuthProvider
    private let httpPost: @Sendable (URL, Data) async throws -> Data

    /// Create a client with a custom HTTP function (for testing).
    public init(
        baseUrl: String,
        tenantId: String = "default",
        authProvider: AuthProvider,
        httpPost: @escaping @Sendable (URL, Data) async throws -> Data
    ) {
        self.baseUrl = baseUrl
        self.tenantId = tenantId
        self.authProvider = authProvider
        self.httpPost = httpPost
    }

    #if !os(Linux)
    /// Create a client using URLSession for HTTP.
    public convenience init(
        baseUrl: String,
        tenantId: String = "default",
        authProvider: AuthProvider
    ) {
        self.init(baseUrl: baseUrl, tenantId: tenantId, authProvider: authProvider) { url, body in
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.httpBody = body
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse, (200..<300).contains(httpResponse.statusCode) else {
                let code = (response as? HTTPURLResponse)?.statusCode ?? 0
                throw SirosError.auth(message: "Auth request failed: \(code)")
            }
            return data
        }
    }
    #endif

    /// Register a new user with WebAuthn. Returns an authenticated session.
    public func register(displayName: String, prfSalt: Data? = nil) async throws -> AuthSession {
        // Step 1: Get registration challenge from backend
        let challengeResponse = try await post(
            path: "/user/register-webauthn-begin",
            body: ["displayName": displayName]
        )

        let options = TaggedBinary.decode(challengeResponse)
        let challengeId = options["challengeId"] as? String

        // Find publicKey in various locations the backend might place it
        let publicKey: [String: Any]
        if let createOpts = options["createOptions"] as? [String: Any],
           let pk = createOpts["publicKey"] as? [String: Any] {
            publicKey = pk
        } else if let getOpts = options["getOptions"] as? [String: Any],
                  let pk = getOpts["publicKey"] as? [String: Any] {
            publicKey = pk
        } else if let pk = options["publicKey"] as? [String: Any] {
            publicKey = pk
        } else {
            throw SirosError.auth(message: "Missing publicKey in registration challenge")
        }

        let rp = publicKey["rp"] as? [String: Any]
        guard let rpId = rp?["id"] as? String else {
            throw SirosError.auth(message: "Missing rp.id")
        }
        let rpName = rp?["name"] as? String ?? rpId
        guard let challengeStr = publicKey["challenge"] as? String else {
            throw SirosError.auth(message: "Missing challenge")
        }
        let challenge = Self.base64UrlDecode(challengeStr)
        guard let user = publicKey["user"] as? [String: Any],
              let userIdStr = user["id"] as? String else {
            throw SirosError.auth(message: "Missing user.id")
        }
        let userId = Self.base64UrlDecode(userIdStr)
        let userName = user["name"] as? String ?? displayName

        // Step 2: Create credential via AuthProvider
        let result = try await authProvider.register(options: RegisterOptions(
            rpId: rpId,
            rpName: rpName,
            userId: userId,
            userName: userName,
            userDisplayName: displayName,
            challenge: challenge,
            prfSalt: prfSalt
        ))

        // Step 3: Complete registration with backend
        var finishBody: [String: Any] = [
            "credential": [
                "id": Self.base64UrlEncode(result.credentialId),
                "rawId": Self.base64UrlEncode(result.credentialId),
                "type": "public-key",
                "response": [
                    "attestationObject": Self.base64UrlEncode(result.attestationObject),
                    "clientDataJSON": Self.base64UrlEncode(result.clientDataJSON),
                ],
            ],
        ]
        if let cid = challengeId {
            finishBody["challengeId"] = cid
        }

        let sessionResponse = try await post(path: "/user/register-webauthn-finish", body: finishBody)
        return try decodeSession(sessionResponse)
    }

    /// Authenticate an existing user with WebAuthn. Returns an authenticated session.
    public func login(prfSalt: Data? = nil) async throws -> AuthSession {
        // Step 1: Get login challenge
        let challengeResponse = try await post(path: "/user/login-webauthn-begin", body: [:])
        let options = TaggedBinary.decode(challengeResponse)
        let challengeId = options["challengeId"] as? String

        let publicKey: [String: Any]
        if let getOpts = options["getOptions"] as? [String: Any],
           let pk = getOpts["publicKey"] as? [String: Any] {
            publicKey = pk
        } else if let pk = options["publicKey"] as? [String: Any] {
            publicKey = pk
        } else {
            throw SirosError.auth(message: "Missing publicKey in login challenge")
        }

        guard let rpId = publicKey["rpId"] as? String else {
            throw SirosError.auth(message: "Missing rpId")
        }
        guard let challengeStr = publicKey["challenge"] as? String else {
            throw SirosError.auth(message: "Missing challenge")
        }
        let challenge = Self.base64UrlDecode(challengeStr)

        // Step 2: Authenticate via AuthProvider
        let result = try await authProvider.authenticate(options: AuthenticateOptions(
            rpId: rpId,
            challenge: challenge,
            prfSalt: prfSalt
        ))

        // Step 3: Complete login with backend
        var responseDict: [String: Any] = [
            "authenticatorData": Self.base64UrlEncode(result.authenticatorData),
            "clientDataJSON": Self.base64UrlEncode(result.clientDataJSON),
            "signature": Self.base64UrlEncode(result.signature),
        ]
        if let uh = result.userHandle {
            responseDict["userHandle"] = Self.base64UrlEncode(uh)
        }

        var finishBody: [String: Any] = [
            "credential": [
                "id": Self.base64UrlEncode(result.credentialId),
                "rawId": Self.base64UrlEncode(result.credentialId),
                "type": "public-key",
                "response": responseDict,
            ],
        ]
        if let cid = challengeId {
            finishBody["challengeId"] = cid
        }

        let sessionResponse = try await post(path: "/user/login-webauthn-finish", body: finishBody)
        return try decodeSession(sessionResponse)
    }

    // MARK: - Private

    private func post(path: String, body: [String: Any]) async throws -> [String: Any] {
        guard let url = URL(string: "\(baseUrl)\(path)") else {
            throw SirosError.auth(message: "Invalid URL: \(baseUrl)\(path)")
        }
        let bodyData = try JSONSerialization.data(withJSONObject: body)
        let responseData = try await httpPost(url, bodyData)
        guard let json = try JSONSerialization.jsonObject(with: responseData) as? [String: Any] else {
            throw SirosError.auth(message: "Invalid JSON response")
        }
        return json
    }

    private func decodeSession(_ dict: [String: Any]) throws -> AuthSession {
        let data = try JSONSerialization.data(withJSONObject: dict)
        return try JSONDecoder().decode(AuthSession.self, from: data)
    }

    // MARK: - Base64URL

    public static func base64UrlEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public static func base64UrlDecode(_ string: String) -> Data {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder != 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        return Data(base64Encoded: base64) ?? Data()
    }
}

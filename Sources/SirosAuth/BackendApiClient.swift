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

    private var _authTokens: AuthTokens?

    /// Configure this client to use `AuthTokens` for automatic token management.
    /// When set, `setAppToken` is ignored and tokens are obtained from the AS.
    public func setAuthTokens(_ tokens: AuthTokens) {
        lock.lock()
        defer { lock.unlock() }
        _authTokens = tokens
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

    /// POST /v1/resolve — resolve an issuer through the backend's AuthZEN
    /// endpoint, which returns its metadata already authenticated together
    /// with a decision about the issuer's registration.
    ///
    /// Unlike `getIssuerMetadata(id:)` this works for any issuer URL, not only
    /// the ones registered with this wallet's own backend, and unlike a direct
    /// well-known fetch the document arrives verified rather than merely
    /// downloaded.
    public func resolveIssuer(
        issuerUrl: String,
        credentialTypes: [String] = []
    ) async throws -> [String: Any] {
        var body: [String: Any] = [
            "subject_id": issuerUrl,
            "subject_type": "url",
            "resource_type": "credential_issuer",
        ]
        if !credentialTypes.isEmpty {
            body["credential_types"] = credentialTypes
        }
        return try await post("/v1/resolve", body: body)
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

    // MARK: - Wallet Provider endpoints

    /// POST /wallet-provider/key-attestation/generate — request a key attestation JWT.
    /// - Parameters:
    ///   - jwks: Array of JWK dictionaries for the keys to attest.
    ///   - nonce: OpenID4VCI nonce from the issuer.
    ///   - securityProperties: Optional security properties dictionary for KA claims (CS-04 §7.1.3).
    ///   - credentialIssuer: Optional target issuer URL - binds the KA's `aud` claim,
    ///     preventing a KA minted for one issuer from being replayed against another.
    ///   - walletInstanceId: Optional WIA JWK Thumbprint (`cnf.jkt`) identifying this
    ///     wallet instance, sent as `wallet_instance_id` - lets the backend's KA trust
    ///     gate look up this instance's recorded `attestation_source` and lift its
    ///     `security_properties` clamp when it's genuinely native-attested. Omitted
    ///     when nil/empty.
    /// - Returns: Key attestation JWT string.
    public func requestKeyAttestation(
        jwks: [[String: Any]],
        nonce: String,
        securityProperties: [String: Any]? = nil,
        credentialIssuer: String? = nil,
        walletInstanceId: String? = nil
    ) async throws -> String {
        var openid4vci: [String: Any] = ["nonce": nonce]
        if let issuer = credentialIssuer, !issuer.isEmpty {
            openid4vci["credential_issuer"] = issuer
        }
        var body: [String: Any] = [
            "jwks": jwks,
            "openid4vci": openid4vci,
        ]
        if let props = securityProperties {
            body["security_properties"] = props
        }
        // The WIA's JWK-thumbprint identity (`cnf.jkt`) - lets the backend's
        // KA trust gate look up this wallet instance's own recorded
        // attestation_source and lift the K3 clamp when it's genuinely
        // native-attested. Omitted whenever the caller has no such WIA.
        if let id = walletInstanceId, !id.isEmpty {
            body["wallet_instance_id"] = id
        }
        let result = try await post("/wallet-provider/key-attestation/generate", body: body)
        guard let attestation = result["key_attestation"] as? String else {
            throw SirosError.backendApi(code: 0, message: "Missing key_attestation in response", body: "")
        }
        return attestation
    }

    /// POST /wallet-provider/wia/challenge — request a WIA challenge nonce.
    /// - Returns: Dictionary with "challenge" and "expires_at" keys.
    public func requestWIAChallenge() async throws -> [String: Any] {
        try await post("/wallet-provider/wia/challenge", body: [:])
    }

    /// POST /wallet-provider/wia/generate — generate a Wallet Instance Attestation.
    /// - Parameters:
    ///   - pop: WIA-PoP JWT (typ: oauth-client-attestation-pop+jwt).
    ///   - challenge: The challenge nonce from requestWIAChallenge().
    ///   - nativeAttestation: Optional platform attestation evidence.
    /// - Returns: WIA JWT string.
    /// - Parameters:
    ///   - clientId: this wallet's OAuth client_id (e.g. its redirect_uri, per
    ///     OID4VCI's unregistered-client convention) - embedded as the WIA JWT's
    ///     `sub` claim. draft-ietf-oauth-attestation-based-client-auth-10 requires
    ///     "the sub claim MUST specify client_id value of the OAuth Client";
    ///     omitting this falls back to the instance identifier (jkt) server-side.
    public func generateWIA(
        pop: String,
        challenge: String,
        clientId: String? = nil,
        nativeAttestation: [String: Any]? = nil
    ) async throws -> String {
        var body: [String: Any] = [
            "pop": pop,
            "challenge": challenge,
        ]
        if let clientId, !clientId.isEmpty {
            body["client_id"] = clientId
        }
        if let native = nativeAttestation {
            body["native_attestation"] = native
        }
        let result = try await post("/wallet-provider/wia/generate", body: body)
        guard let wia = result["wallet_instance_attestation"] as? String else {
            throw SirosError.backendApi(code: 0, message: "Missing wallet_instance_attestation in response", body: "")
        }
        return wia
    }

    /// POST /wallet-provider/fido2-attestation/register — register a FIDO2/CTAP2
    /// hardware-key attestation once, at key-creation time, so the backend can
    /// durably mark the wallet instance as hardware-key-attested (see
    /// `FIDO2AttestationService` in go-wallet-backend). Throws `SirosError.backendApi`
    /// if the backend rejects the attestation (e.g. untrusted AAGUID/chain) or the
    /// feature isn't enabled.
    /// - Parameters:
    ///   - walletInstanceId: The WIA JWK Thumbprint (`cnf.jkt`) this key belongs to.
    ///   - attestationObject: The raw CTAP2 makeCredential attestation object
    ///     (siros-wscd-manager's `AttestationChain.certificates[0]`).
    ///   - clientDataHash: The 32-byte hash the attestation signature was computed
    ///     over (`AttestationChain.clientDataHash`).
    public func registerFido2Attestation(
        walletInstanceId: String,
        attestationObject: Data,
        clientDataHash: Data
    ) async throws {
        let body: [String: Any] = [
            "wallet_instance_id": walletInstanceId,
            "attestation_object": WebAuthnAuthClient.base64UrlEncode(attestationObject),
            "client_data_hash": WebAuthnAuthClient.base64UrlEncode(clientDataHash),
        ]
        _ = try await post("/wallet-provider/fido2-attestation/register", body: body)
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
        let tokens = currentAuthTokens()
        if let tokens {
            let token = try await tokens.ensureBackendToken()
            headers["Authorization"] = "Bearer \(token.raw)"
        } else if let token = currentAppToken() {
            headers["Authorization"] = "Bearer \(token)"
        }
        do {
            return try await httpFn(method, url, headers, body)
        } catch {
            // A 401 here means the backend token itself was rejected (expired/
            // revoked/session invalidated server-side) - `AuthTokens.
            // registerTokenRejection` was previously never called from
            // anywhere (dead code), so repeated silent 401s never triggered
            // `onSessionRejected`/a forced logout, leaving a stale session
            // looking "connected" indefinitely. Only applies to the
            // `AuthTokens`-managed path: the legacy bare `appToken` path has
            // no `AuthTokens` instance to register against.
            if let tokens, case let SirosError.backendApi(code, _, _) = error, code == 401 {
                tokens.registerTokenRejection(AuthTokens.tokenBackend)
            }
            throw error
        }
    }

    private func currentAppToken() -> String? {
        lock.lock()
        defer { lock.unlock() }
        return _appToken
    }

    private func currentAuthTokens() -> AuthTokens? {
        lock.lock()
        defer { lock.unlock() }
        return _authTokens
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

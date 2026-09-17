// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosAuth

final class AuthServerClientTests: XCTestCase {

    private var mockServer: MockHttpServer!
    private var client: AuthServerClient!

    override func setUp() {
        mockServer = MockHttpServer()
        client = AuthServerClient(
            baseUrl: "https://auth.example.com",
            tenantId: "test-tenant",
            httpFn: mockServer.httpFunction
        )
    }

    private func buildJwt(_ payload: String) -> String {
        let header = Data(#"{"alg":"RS256","typ":"JWT"}"#.utf8).base64URLEncoded
        let body = Data(payload.utf8).base64URLEncoded
        let sig = Data("fake".utf8).base64URLEncoded
        return "\(header).\(body).\(sig)"
    }

    // MARK: - loginBegin

    func testLoginBeginSendsCorrectRequest() async throws {
        mockServer.enqueue("""
        {"challengeId":"c1","getOptions":{"publicKey":{"rpId":"example.com","challenge":"AAAA"}}}
        """)

        let response = try await client.loginBegin()
        XCTAssertEqual(response["challengeId"] as? String, "c1")

        let req = mockServer.requests.first!
        XCTAssertEqual(req.method, "POST")
        XCTAssertEqual(req.path, "/auth/passkey/login/begin")
        XCTAssertEqual(req.headers["X-Token-Mode"], "session")
        XCTAssertEqual(req.headers["X-Tenant-ID"], "test-tenant")
    }

    func testLoginBeginWithOidcToken() async throws {
        mockServer.enqueue("""
        {"challengeId":"c1","getOptions":{"publicKey":{}}}
        """)

        _ = try await client.loginBegin(oidcIdToken: "my-oidc-token")
        let req = mockServer.requests.first!
        XCTAssertEqual(req.headers["Authorization"], "Bearer my-oidc-token")
    }

    // MARK: - loginFinish

    func testLoginFinishReturnsParsedResult() async throws {
        mockServer.enqueue("""
        {"uuid":"u1","displayName":"Alice","tenantId":"t1"}
        """)

        let credential: [String: Any] = ["id": "cred-1", "type": "public-key"]
        let result = try await client.loginFinish(challengeId: "ch-1", credential: credential)
        XCTAssertEqual(result.uuid, "u1")
        XCTAssertEqual(result.displayName, "Alice")
        XCTAssertEqual(result.tenantId, "t1")

        let req = mockServer.requests.first!
        XCTAssertEqual(req.path, "/auth/passkey/login/finish")
    }

    // MARK: - registerBegin

    func testRegisterBeginSendsTenantAndInvite() async throws {
        mockServer.enqueue("""
        {"challengeId":"c2","createOptions":{"publicKey":{}}}
        """)

        _ = try await client.registerBegin(inviteCode: "inv-123")
        let req = mockServer.requests.first!
        XCTAssertEqual(req.path, "/auth/passkey/register/begin")
        let bodyStr = String(data: req.body ?? Data(), encoding: .utf8) ?? ""
        XCTAssertTrue(bodyStr.contains("inv-123"))
        XCTAssertTrue(bodyStr.contains("test-tenant"))
    }

    // MARK: - registerFinish

    func testRegisterFinishReturnsParsedResult() async throws {
        mockServer.enqueue("""
        {"uuid":"u2","displayName":"Bob","tenantId":"t1"}
        """)

        let credential: [String: Any] = ["id": "cred-1", "type": "public-key"]
        let result = try await client.registerFinish(
            challengeId: "ch-2",
            credential: credential,
            displayName: "Bob"
        )
        XCTAssertEqual(result.uuid, "u2")
        XCTAssertEqual(result.displayName, "Bob")

        let req = mockServer.requests.first!
        XCTAssertEqual(req.path, "/auth/passkey/register/finish")
    }

    // MARK: - requestAccessToken

    func testRequestAccessTokenReturnsParsed() async throws {
        let exp = Int(Date().timeIntervalSince1970) + 3600
        let jwt = buildJwt("""
        {"sub":"u","aud":"wallet-backend","tenant_id":"t1","tac":"rwl","acr":"urn:siros:acr:passkey","exp":\(exp)}
        """)

        mockServer.enqueue("""
        {"access_token":"\(jwt)","token_type":"Bearer","expires_in":3600}
        """)

        let token = try await client.requestAccessToken(aud: "wallet-backend", tac: "rwl")
        XCTAssertEqual(token.aud, "wallet-backend")
        XCTAssertEqual(token.sub, "u")

        let req = mockServer.requests.first!
        XCTAssertEqual(req.path, "/auth/token")
        let bodyStr = String(data: req.body ?? Data(), encoding: .utf8) ?? ""
        XCTAssertTrue(bodyStr.contains("wallet-backend"))
        XCTAssertTrue(bodyStr.contains("rwl"))
    }

    func testRequestAccessTokenCachesResult() async throws {
        let exp = Int(Date().timeIntervalSince1970) + 3600
        let jwt = buildJwt("""
        {"sub":"u","aud":"wb","tenant_id":"t","tac":"r","acr":"urn:siros:acr:passkey","exp":\(exp)}
        """)

        mockServer.enqueue("""
        {"access_token":"\(jwt)","token_type":"Bearer","expires_in":3600}
        """)

        let token1 = try await client.requestAccessToken(aud: "wb", tac: "r")
        let token2 = try await client.requestAccessToken(aud: "wb", tac: "r")
        // Only 1 request should have been made
        XCTAssertEqual(mockServer.requests.count, 1)
        XCTAssertEqual(token1.raw, token2.raw)
    }

    // MARK: - logout

    func testLogoutSendsDelete() async throws {
        mockServer.enqueue("{}")  // logout response (ignored)

        try await client.logout()
        let req = mockServer.requests.first!
        XCTAssertEqual(req.method, "DELETE")
        XCTAssertEqual(req.path, "/auth/session")
    }
}

// MARK: - Base64URL Helper

private extension Data {
    var base64URLEncoded: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

extension AuthServerClientTests {
    /// A token minted before a lifecycle cut-off is refused with 401 however
    /// fresh it looks, so the SDK's re-login must not be served one out of
    /// cache. `clearTokenCache()` drops them without ending the session the
    /// way `logout()` would.
    func testClearTokenCacheForcesTheNextRequestToMintAgain() async throws {
        var mintCount = 0
        let client = AuthServerClient(baseUrl: "https://as.example.invalid", tenantId: "default") { _, url, _, _ in
            guard url.path == "/auth/token" else {
                XCTFail("unexpected \(url.path)")
                return Data("{}".utf8)
            }
            mintCount += 1
            // exp far in the future, so the cache would happily serve it again
            let claims = #"{"sub":"u","aud":"wallet-backend","tenant_id":"default","tac":"rwlid","exp":4102444800}"#
            let b64 = Data(claims.utf8).base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
            let jwt = "e30.\(b64).sig"
            return Data(#"{"access_token":"\#(jwt)","token_type":"Bearer","expires_in":3600}"#.utf8)
        }

        _ = try await client.requestAccessToken(aud: "wallet-backend", tac: "rwlid")
        _ = try await client.requestAccessToken(aud: "wallet-backend", tac: "rwlid")
        XCTAssertEqual(mintCount, 1, "the second call is served from cache")

        await client.clearTokenCache()
        _ = try await client.requestAccessToken(aud: "wallet-backend", tac: "rwlid")
        XCTAssertEqual(mintCount, 2, "after clearTokenCache the token is minted again")
    }

    /// `clearTokenCache()` is called to drop a pre-cut-off token, but the
    /// request that minted it may still be in flight - `requestAccessToken`
    /// caches after its network call returns. Storing it then would put the
    /// refused token straight back for the session that replaced it.
    func testATokenMintedBeforeClearTokenCacheIsNotCachedAfterIt() async throws {
        var mintCount = 0
        var clearDuringRequest: (() async -> Void)?
        let client = AuthServerClient(
            baseUrl: "https://as.example.invalid",
            tenantId: "default"
        ) { _, _, _, _ in
            mintCount += 1
            await clearDuringRequest?()
            return try Self.tokenResponse()
        }
        clearDuringRequest = { await client.clearTokenCache() }

        _ = try await client.requestAccessToken(aud: "wallet-backend", tac: "rwlid")
        XCTAssertEqual(mintCount, 1)

        clearDuringRequest = nil
        _ = try await client.requestAccessToken(aud: "wallet-backend", tac: "rwlid")
        XCTAssertEqual(
            mintCount, 2,
            "the token minted before the clear was not cached, so a fresh one is minted"
        )
    }

    /// An unexpired `access_token` response body.
    private static func tokenResponse() throws -> Data {
        let exp = Int(Date().timeIntervalSince1970) + 3600
        let payload = try JSONSerialization.data(withJSONObject: [
            "exp": exp, "aud": "wallet-backend", "tenant_id": "default", "tac": "rwlid",
        ])
        let b64 = payload.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return try JSONSerialization.data(withJSONObject: [
            "access_token": "eyJhbGciOiJub25lIn0.\(b64).sig",
            "token_type": "Bearer",
            "expires_in": 3600,
        ])
    }
}

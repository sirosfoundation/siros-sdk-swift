// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosAuth

final class BackendApiClientTests: XCTestCase {

    func testGetAccountInfoSendsExpectedHeaders() async throws {
        let server = MockHttpServer()
        server.enqueue("{}")
        let client = BackendApiClient(baseUrl: "https://api.example.com", tenantId: "default", httpFn: server.httpFunction)
        client.setAppToken("token-abc")

        let _ = try await client.getAccountInfo()

        XCTAssertEqual(server.requests.count, 1)
        let req = server.requests[0]
        XCTAssertEqual(req.path, "/user/session/account-info")
        XCTAssertEqual(req.method, "GET")
        XCTAssertEqual(req.headers["X-Tenant-ID"], "default")
        XCTAssertEqual(req.headers["Authorization"], "Bearer token-abc")
    }

    func testUnauthenticatedRequestOmitsAuthorizationHeader() async throws {
        let server = MockHttpServer()
        server.enqueue("{}")
        let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: server.httpFunction)

        let _ = try await client.healthCheck()

        XCTAssertEqual(server.requests[0].path, "/health")
        XCTAssertNil(server.requests[0].headers["Authorization"])
    }

    func testGetIssuersAcceptsArrayPayload() async throws {
        let server = MockHttpServer()
        server.enqueue("[{\"id\": 1, \"visible\": true}]")
        let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: server.httpFunction)

        let issuers = try await client.getIssuers()
        XCTAssertTrue(issuers is [Any])
    }

    func testUpdatePrivateDataPostsJsonBody() async throws {
        let server = MockHttpServer()
        server.enqueue("{}")
        let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: server.httpFunction)
        client.setAppToken("token-xyz")

        let _ = try await client.updatePrivateData(["privateData": "opaque"])

        XCTAssertEqual(server.requests[0].path, "/user/session/private-data")
        XCTAssertEqual(server.requests[0].method, "POST")
        if let body = server.requests[0].body {
            let bodyStr = String(data: body, encoding: .utf8) ?? ""
            XCTAssertTrue(bodyStr.contains("privateData"))
        }
    }

    func testRequestKeyAttestationSendsJwksNonceAndCredentialIssuer() async throws {
        let server = MockHttpServer()
        server.enqueue("{\"key_attestation\": \"signed-jwt\"}")
        let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: server.httpFunction)

        let result = try await client.requestKeyAttestation(
            jwks: [["kty": "EC"]],
            nonce: "nonce-1",
            securityProperties: ["key_storage": ["iso_18045_high"]],
            credentialIssuer: "https://issuer.example.com"
        )

        XCTAssertEqual(result, "signed-jwt")
        let req = server.requests[0]
        XCTAssertEqual(req.path, "/wallet-provider/key-attestation/generate")
        let body = try XCTUnwrap(req.body)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        let jwks = try XCTUnwrap(json["jwks"] as? [[String: Any]])
        XCTAssertEqual(jwks.count, 1)
        let openid4vci = try XCTUnwrap(json["openid4vci"] as? [String: Any])
        XCTAssertEqual(openid4vci["nonce"] as? String, "nonce-1")
        XCTAssertEqual(openid4vci["credential_issuer"] as? String, "https://issuer.example.com")
        let securityProperties = try XCTUnwrap(json["security_properties"] as? [String: Any])
        XCTAssertEqual(securityProperties["key_storage"] as? [String], ["iso_18045_high"])
    }

    func testRequestKeyAttestationOmitsCredentialIssuerWhenNotProvided() async throws {
        let server = MockHttpServer()
        server.enqueue("{\"key_attestation\": \"signed-jwt\"}")
        let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: server.httpFunction)

        let _ = try await client.requestKeyAttestation(jwks: [["kty": "EC"]], nonce: "nonce-1")

        let body = try XCTUnwrap(server.requests[0].body)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        let openid4vci = try XCTUnwrap(json["openid4vci"] as? [String: Any])
        XCTAssertNil(openid4vci["credential_issuer"])
    }

    func testRequestKeyAttestationSendsWalletInstanceIdWhenProvided() async throws {
        let server = MockHttpServer()
        server.enqueue("{\"key_attestation\": \"signed-jwt\"}")
        let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: server.httpFunction)

        let _ = try await client.requestKeyAttestation(
            jwks: [["kty": "EC"]],
            nonce: "nonce-1",
            walletInstanceId: "test-jkt"
        )

        let body = try XCTUnwrap(server.requests[0].body)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(json["wallet_instance_id"] as? String, "test-jkt")
    }

    func testRequestKeyAttestationOmitsWalletInstanceIdWhenNotProvided() async throws {
        let server = MockHttpServer()
        server.enqueue("{\"key_attestation\": \"signed-jwt\"}")
        let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: server.httpFunction)

        let _ = try await client.requestKeyAttestation(jwks: [["kty": "EC"]], nonce: "nonce-1")

        let body = try XCTUnwrap(server.requests[0].body)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertNil(json["wallet_instance_id"])
    }

    func testEvaluateTrustPostsToExpectedEndpoint() async throws {
        let server = MockHttpServer()
        server.enqueue("{\"decision\":true}")
        let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: server.httpFunction)
        client.setAppToken("token-trust")

        let response = try await client.evaluateTrust(["subject": "issuer-123"])

        XCTAssertEqual(server.requests[0].path, "/v1/evaluate")
        XCTAssertEqual(server.requests[0].method, "POST")
        XCTAssertEqual(server.requests[0].headers["Authorization"], "Bearer token-trust")
    }

    func testDeleteCredentialUsesDeleteMethod() async throws {
        let server = MockHttpServer()
        server.enqueue("{}")
        let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: server.httpFunction)

        let _ = try await client.deleteCredential(id: "cred-42")

        XCTAssertEqual(server.requests[0].path, "/storage/vc/cred-42")
        XCTAssertEqual(server.requests[0].method, "DELETE")
    }

    func testTenantConfigUsesTenantSpecificPath() async throws {
        let server = MockHttpServer()
        server.enqueue("{}")
        let client = BackendApiClient(baseUrl: "https://api.example.com", tenantId: "tenant-42", httpFn: server.httpFunction)

        let _ = try await client.getTenantConfig()

        XCTAssertEqual(server.requests[0].path, "/api/v1/tenants/tenant-42/config")
        XCTAssertEqual(server.requests[0].headers["X-Tenant-ID"], "tenant-42")
    }

    func testBlankSuccessBodyReturnsEmptyJsonObject() async throws {
        let server = MockHttpServer()
        server.enqueueData(Data())
        let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: server.httpFunction)

        let response = try await client.healthCheck()
        XCTAssertTrue(response.isEmpty)
    }

    func testRefreshSessionPostsRefreshToken() async throws {
        let server = MockHttpServer()
        server.enqueue("{\"appToken\":\"new-token\"}")
        let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: server.httpFunction)

        let response = try await client.refreshSession(refreshToken: "refresh-abc")

        XCTAssertEqual(server.requests[0].path, "/user/session/refresh")
        XCTAssertEqual(server.requests[0].method, "POST")
        if let body = server.requests[0].body {
            let bodyStr = String(data: body, encoding: .utf8) ?? ""
            XCTAssertTrue(bodyStr.contains("refresh-abc"))
        }
    }
}

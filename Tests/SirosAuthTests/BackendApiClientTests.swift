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

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosAuth

final class WebAuthnAuthClientTests: XCTestCase {

    func testRegisterCallsBeginAndFinishAndReturnsSession() async throws {
        let server = MockHttpServer()
        // Begin response
        server.enqueue("""
        {
          "challengeId": "reg-ch-1",
          "createOptions": {
            "publicKey": {
              "rp": { "id": "example.com", "name": "Example RP" },
              "challenge": "Y2hhbGxlbmdl",
              "user": { "id": "dXNlcjEyMw", "name": "alice" }
            }
          }
        }
        """)
        // Finish response
        server.enqueue("""
        {
          "appToken": "app-token-123",
          "uuid": "user-123",
          "displayName": "Alice",
          "refreshToken": "refresh-abc",
          "tenantId": "default"
        }
        """)

        let fakeProvider = FakeAuthProvider(
            registerResult: RegisterResult(
                credentialId: Data([1, 2, 3]),
                attestationObject: Data("attestation".utf8),
                clientDataJSON: Data("client-data".utf8)
            ),
            authenticateResult: defaultAuthenticateResult()
        )
        let client = WebAuthnAuthClient(
            baseUrl: "https://api.example.com",
            authProvider: fakeProvider,
            httpPost: server.httpPost
        )

        let session = try await client.register(displayName: "Alice")

        XCTAssertEqual(session.appToken, "app-token-123")
        XCTAssertEqual(session.uuid, "user-123")
        XCTAssertNotNil(fakeProvider.lastRegisterOptions)
        XCTAssertEqual(fakeProvider.lastRegisterOptions?.challenge, Data("challenge".utf8))
        XCTAssertEqual(fakeProvider.lastRegisterOptions?.rpId, "example.com")

        XCTAssertEqual(server.requests.count, 2)
        XCTAssertEqual(server.requests[0].path, "/user/register-webauthn-begin")
        XCTAssertEqual(server.requests[1].path, "/user/register-webauthn-finish")
    }

    func testLoginCallsBeginAndFinishAndReturnsSession() async throws {
        let server = MockHttpServer()
        server.enqueue("""
        {
          "challengeId": "login-ch-1",
          "getOptions": {
            "publicKey": {
              "rpId": "example.com",
              "challenge": "bG9naW4tY2hhbGxlbmdl"
            }
          }
        }
        """)
        server.enqueue("""
        {
          "appToken": "app-token-login",
          "uuid": "user-456",
          "displayName": "Bob"
        }
        """)

        let fakeProvider = FakeAuthProvider(
            registerResult: defaultRegisterResult(),
            authenticateResult: defaultAuthenticateResult()
        )
        let client = WebAuthnAuthClient(
            baseUrl: "https://api.example.com",
            authProvider: fakeProvider,
            httpPost: server.httpPost
        )

        let session = try await client.login()

        XCTAssertEqual(session.appToken, "app-token-login")
        XCTAssertEqual(session.uuid, "user-456")
        XCTAssertNotNil(fakeProvider.lastAuthenticateOptions)
        XCTAssertEqual(fakeProvider.lastAuthenticateOptions?.challenge, Data("login-challenge".utf8))

        XCTAssertEqual(server.requests.count, 2)
        XCTAssertEqual(server.requests[0].path, "/user/login-webauthn-begin")
        XCTAssertEqual(server.requests[1].path, "/user/login-webauthn-finish")
    }

    func testRegisterThrowsWhenPublicKeyMissing() async {
        let server = MockHttpServer()
        server.enqueue("{\"challengeId\": \"reg-ch-2\", \"createOptions\": {}}")

        let fakeProvider = FakeAuthProvider(
            registerResult: defaultRegisterResult(),
            authenticateResult: defaultAuthenticateResult()
        )
        let client = WebAuthnAuthClient(
            baseUrl: "https://api.example.com",
            authProvider: fakeProvider,
            httpPost: server.httpPost
        )

        do {
            let _ = try await client.register(displayName: "Alice")
            XCTFail("Expected error for missing publicKey")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("Missing publicKey"))
        }
    }

    func testRegisterUsesPublicKeyFallback() async throws {
        let server = MockHttpServer()
        // publicKey at top level (not inside createOptions)
        server.enqueue("""
        {
          "challengeId": "reg-ch-3",
          "publicKey": {
            "rp": { "id": "example.com" },
            "challenge": "Y2hhbGxlbmdl",
            "user": { "id": "dXNlcjEyMw" }
          }
        }
        """)
        server.enqueue("""
        {
          "appToken": "app-token-fallback",
          "uuid": "user-fallback",
          "displayName": "Alice"
        }
        """)

        let fakeProvider = FakeAuthProvider(
            registerResult: defaultRegisterResult(),
            authenticateResult: defaultAuthenticateResult()
        )
        let client = WebAuthnAuthClient(
            baseUrl: "https://api.example.com",
            authProvider: fakeProvider,
            httpPost: server.httpPost
        )

        let _ = try await client.register(displayName: "Alice", prfSalt: Data("salt-123".utf8))

        XCTAssertEqual(fakeProvider.lastRegisterOptions?.rpId, "example.com")
        // rpName falls back to rpId when rp.name is missing
        XCTAssertEqual(fakeProvider.lastRegisterOptions?.rpName, "example.com")
        // userName falls back to displayName
        XCTAssertEqual(fakeProvider.lastRegisterOptions?.userName, "Alice")
        XCTAssertEqual(fakeProvider.lastRegisterOptions?.prfSalt, Data("salt-123".utf8))
    }

    func testLoginThrowsWhenRpIdMissing() async {
        let server = MockHttpServer()
        server.enqueue("""
        {
          "challengeId": "login-ch-3",
          "publicKey": {
            "challenge": "bG9naW4tY2hhbGxlbmdl"
          }
        }
        """)

        let fakeProvider = FakeAuthProvider(
            registerResult: defaultRegisterResult(),
            authenticateResult: defaultAuthenticateResult()
        )
        let client = WebAuthnAuthClient(
            baseUrl: "https://api.example.com",
            authProvider: fakeProvider,
            httpPost: server.httpPost
        )

        do {
            let _ = try await client.login()
            XCTFail("Expected error for missing rpId")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("Missing rpId"))
        }
    }

    func testLoginWithUserHandle() async throws {
        let server = MockHttpServer()
        server.enqueue("""
        {
          "challengeId": "login-ch-2",
          "publicKey": {
            "rpId": "example.com",
            "challenge": "bG9naW4tY2hhbGxlbmdl"
          }
        }
        """)
        server.enqueue("""
        {
          "appToken": "app-token-login-2",
          "uuid": "user-789",
          "displayName": "Carol",
          "tenantId": "tenant-42"
        }
        """)

        let authResult = AuthenticateResult(
            credentialId: Data([9, 9, 9]),
            authenticatorData: Data("auth-data".utf8),
            clientDataJSON: Data("client-data".utf8),
            signature: Data("sig".utf8),
            userHandle: Data("user-handle".utf8)
        )
        let fakeProvider = FakeAuthProvider(
            registerResult: defaultRegisterResult(),
            authenticateResult: authResult
        )
        let client = WebAuthnAuthClient(
            baseUrl: "https://api.example.com",
            tenantId: "tenant-42",
            authProvider: fakeProvider,
            httpPost: server.httpPost
        )

        let session = try await client.login(prfSalt: Data("salt-xyz".utf8))

        XCTAssertEqual(session.tenantId, "tenant-42")
        XCTAssertEqual(fakeProvider.lastAuthenticateOptions?.prfSalt, Data("salt-xyz".utf8))

        // Verify finish request includes userHandle
        XCTAssertEqual(server.requests.count, 2)
        if let finishBody = server.requests[1].body {
            let bodyStr = String(data: finishBody, encoding: .utf8) ?? ""
            XCTAssertTrue(bodyStr.contains("userHandle"))
        }
    }

    func testTaggedBinaryDecodingInChallenge() async throws {
        let server = MockHttpServer()
        // Challenge returned as tagged binary
        server.enqueue("""
        {
          "challengeId": "reg-ch-4",
          "createOptions": {
            "publicKey": {
              "rp": { "id": "example.com", "name": "Test" },
              "challenge": "Y2hhbGxlbmdl",
              "user": { "id": {"$b64u": "dXNlcjEyMw"}, "name": "alice" }
            }
          }
        }
        """)
        server.enqueue("""
        {
          "appToken": "tok",
          "uuid": "u1"
        }
        """)

        let fakeProvider = FakeAuthProvider(
            registerResult: RegisterResult(
                credentialId: Data([1]),
                attestationObject: Data("att".utf8),
                clientDataJSON: Data("cd".utf8)
            ),
            authenticateResult: defaultAuthenticateResult()
        )
        let client = WebAuthnAuthClient(
            baseUrl: "https://api.example.com",
            authProvider: fakeProvider,
            httpPost: server.httpPost
        )

        let session = try await client.register(displayName: "alice")
        XCTAssertEqual(session.appToken, "tok")
        // The tagged $b64u should have been decoded to the plain string
        XCTAssertNotNil(fakeProvider.lastRegisterOptions)
    }
}

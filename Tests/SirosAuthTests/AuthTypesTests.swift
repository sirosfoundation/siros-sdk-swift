// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosAuth

final class AuthTypesTests: XCTestCase {

    func testAuthSessionCodable() throws {
        let session = AuthSession(
            appToken: "tok-123",
            uuid: "uuid-456",
            displayName: "Alice",
            refreshToken: "refresh-789",
            tenantId: "default"
        )
        let data = try JSONEncoder().encode(session)
        let decoded = try JSONDecoder().decode(AuthSession.self, from: data)
        XCTAssertEqual(decoded.appToken, "tok-123")
        XCTAssertEqual(decoded.uuid, "uuid-456")
        XCTAssertEqual(decoded.displayName, "Alice")
        XCTAssertEqual(decoded.refreshToken, "refresh-789")
        XCTAssertEqual(decoded.tenantId, "default")
    }

    func testAuthSessionDecodesFromJson() throws {
        let json = """
        {
          "appToken": "app-token",
          "uuid": "user-id",
          "displayName": "Test User",
          "did": "did:example:123"
        }
        """
        let session = try JSONDecoder().decode(AuthSession.self, from: Data(json.utf8))
        XCTAssertEqual(session.appToken, "app-token")
        XCTAssertEqual(session.did, "did:example:123")
        XCTAssertNil(session.refreshToken)
    }

    func testAuthSessionEquality() {
        let a = AuthSession(appToken: "t", uuid: "u")
        let b = AuthSession(appToken: "t", uuid: "u")
        let c = AuthSession(appToken: "t", uuid: "v")
        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, c)
    }

    func testRegisterOptionsDefaults() {
        let opts = RegisterOptions(
            rpId: "example.com",
            rpName: "Example",
            userId: Data([1, 2, 3]),
            userName: "alice",
            userDisplayName: "Alice",
            challenge: Data([4, 5, 6])
        )
        XCTAssertEqual(opts.attestation, "none")
        XCTAssertNil(opts.authenticatorSelection)
        XCTAssertNil(opts.prfSalt)
    }

    func testAuthenticateOptionsDefaults() {
        let opts = AuthenticateOptions(
            rpId: "example.com",
            challenge: Data([1, 2, 3])
        )
        XCTAssertEqual(opts.userVerification, "preferred")
        XCTAssertNil(opts.allowCredentials)
        XCTAssertNil(opts.prfSalt)
    }

    func testBase64UrlRoundTrip() {
        let data = Data([0, 1, 2, 0xFF, 0xFE])
        let encoded = WebAuthnAuthClient.base64UrlEncode(data)
        let decoded = WebAuthnAuthClient.base64UrlDecode(encoded)
        XCTAssertEqual(data, decoded)
        XCTAssertFalse(encoded.contains("+"))
        XCTAssertFalse(encoded.contains("/"))
        XCTAssertFalse(encoded.contains("="))
    }
}

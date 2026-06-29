// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosAuth

final class AccessTokenTests: XCTestCase {

    private func buildJwt(_ payload: String) -> String {
        let header = Data(#"{"alg":"RS256","typ":"JWT"}"#.utf8).base64URLEncoded
        let body = Data(payload.utf8).base64URLEncoded
        let sig = Data("fake".utf8).base64URLEncoded
        return "\(header).\(body).\(sig)"
    }

    func testParsesValidToken() throws {
        let exp = Int(Date().timeIntervalSince1970) + 3600
        let jwt = buildJwt("""
        {"sub":"user-123","aud":"wallet-backend","tenant_id":"t1","tac":"rwl","acr":"urn:siros:acr:passkey","exp":\(exp)}
        """)

        let token = try AccessToken(jwt: jwt)
        XCTAssertEqual(token.sub, "user-123")
        XCTAssertEqual(token.aud, "wallet-backend")
        XCTAssertEqual(token.tenantId, "t1")
        XCTAssertEqual(token.tac, [.read, .write, .list])
        XCTAssertEqual(token.acr, .passkey)
        XCTAssertFalse(token.isExpired())
        XCTAssertEqual(token.token(), jwt)
    }

    func testParsesOidcAcr() throws {
        let exp = Int(Date().timeIntervalSince1970) + 3600
        let jwt = buildJwt("""
        {"sub":"u","aud":"a","tenant_id":"t","tac":"r","acr":"urn:siros:acr:oidc","exp":\(exp)}
        """)

        let token = try AccessToken(jwt: jwt)
        XCTAssertEqual(token.acr, .oidc)
    }

    func testExpiredToken() throws {
        let exp = Int(Date().timeIntervalSince1970) - 100
        let jwt = buildJwt("""
        {"sub":"u","aud":"a","tenant_id":"t","tac":"r","acr":"urn:siros:acr:passkey","exp":\(exp)}
        """)

        let token = try AccessToken(jwt: jwt)
        XCTAssertTrue(token.isExpired())
    }

    func testExpiredWithinMargin() throws {
        let exp = Int(Date().timeIntervalSince1970) + 5 // 5 seconds
        let jwt = buildJwt("""
        {"sub":"u","aud":"a","tenant_id":"t","tac":"r","acr":"urn:siros:acr:passkey","exp":\(exp)}
        """)

        let token = try AccessToken(jwt: jwt)
        XCTAssertTrue(token.isExpired()) // 10s margin
    }

    func testInvalidJwtFormat() {
        XCTAssertThrowsError(try AccessToken(jwt: "not-a-jwt"))
    }

    func testAllTacPermissions() throws {
        let exp = Int(Date().timeIntervalSince1970) + 3600
        let jwt = buildJwt("""
        {"sub":"u","aud":"a","tenant_id":"t","tac":"rwlidka","acr":"urn:siros:acr:passkey","exp":\(exp)}
        """)

        let token = try AccessToken(jwt: jwt)
        XCTAssertEqual(token.tac, Set(TacPermission.allCases))
    }
}

final class TacPermissionTests: XCTestCase {
    func testParseBasic() {
        let result = TacPermission.parse("rwl")
        XCTAssertEqual(result, [.read, .write, .list])
    }

    func testParseIgnoresUnknown() {
        let result = TacPermission.parse("rxw")
        XCTAssertEqual(result, [.read, .write])
    }

    func testParseEmpty() {
        XCTAssertEqual(TacPermission.parse(""), Set<TacPermission>())
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

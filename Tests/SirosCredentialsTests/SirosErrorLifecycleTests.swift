// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

/// `SirosError.walletLifecycleRefusal` (SID-AUTH-06, go-wallet-backend#319):
/// the two stable 403 codes a backend returns when passkey login is refused
/// for lifecycle reasons, exposed without adding a `SirosError` case.
final class SirosErrorLifecycleTests: XCTestCase {
    func testRefusalIsReadFromA403Body() {
        let suspended = SirosError.backendApi(code: 403, message: "AS request failed: 403", body: #"{"error":"WALLET_SUSPENDED"}"#)
        XCTAssertEqual(suspended.walletLifecycleRefusal, .suspended)
        let revoked = SirosError.backendApi(code: 403, message: "AS request failed: 403", body: #"{"error":"WALLET_REVOKED","message":"deactivated"}"#)
        XCTAssertEqual(revoked.walletLifecycleRefusal, .revoked)
    }

    func testOtherErrorsAreNotRefusals() {
        XCTAssertNil(SirosError.backendApi(code: 403, message: "", body: #"{"error":"Tenant user must use tenant-scoped login endpoint"}"#).walletLifecycleRefusal)
        XCTAssertNil(SirosError.backendApi(code: 401, message: "", body: #"{"error":"WALLET_REVOKED"}"#).walletLifecycleRefusal, "only a 403 carries a lifecycle refusal")
        XCTAssertNil(SirosError.backendApi(code: 403, message: "", body: "not json").walletLifecycleRefusal)
        XCTAssertNil(SirosError.auth(message: "x").walletLifecycleRefusal)
    }
}

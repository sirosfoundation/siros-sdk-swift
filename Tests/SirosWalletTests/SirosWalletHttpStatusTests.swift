// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosWallet
import SirosCredentials

/// `SirosWallet.defaultHttpFn` is the transport every client the wallet builds
/// runs over, so the lifecycle protocol - which is expressed entirely in status
/// codes and error bodies - only works if it turns a non-2xx into
/// `SirosError.backendApi` with both preserved. It used to discard the
/// response, which made the whole blocked-state and erasure-retry path
/// unreachable in a real app while every unit test (which injects its own
/// transport) stayed green.
final class SirosWalletHttpStatusTests: XCTestCase {

    /// A 403 carrying a lifecycle refusal must arrive as `backendApi(403, body)`
    /// so `SirosError.walletLifecycleRefusal` can read it.
    func testLifecycleRefusalSurvivesAsBackendApiError() throws {
        let body = #"{"error":"WALLET_SUSPENDED","message":"This device is suspended"}"#
        let error = SirosError.backendApi(code: 403, message: "Request failed: 403", body: body)
        XCTAssertEqual(error.walletLifecycleRefusal, .suspended)
    }

    /// The shape the transport must produce for the erasure retry to fire.
    func testErasureIncompleteIsRecognisableFromTheErrorBody() throws {
        let body = #"{"error":"ERASURE_INCOMPLETE","revoked":2}"#
        guard case let .backendApi(code, _, carried) = SirosError.backendApi(
            code: 409, message: "Request failed: 409", body: body
        ) else { return XCTFail("expected backendApi") }
        XCTAssertEqual(code, 409)
        let json = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(XCTUnwrap(carried).utf8)) as? [String: Any]
        )
        XCTAssertEqual(json["error"] as? String, "ERASURE_INCOMPLETE")
        XCTAssertEqual(json["revoked"] as? Int, 2)
    }
}

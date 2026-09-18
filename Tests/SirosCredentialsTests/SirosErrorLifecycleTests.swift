// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

/// `SirosError.walletLifecycleRefusal` (SID-AUTH-06,
/// go-wallet-backend#319/#340): the stable 403 `error`/`scope` pairs a backend
/// returns when passkey login is refused for lifecycle reasons, exposed
/// without adding a `SirosError` case.
final class SirosErrorLifecycleTests: XCTestCase {
    func testRefusalIsReadFromA403Body() {
        let suspended = SirosError.backendApi(code: 403, message: "AS request failed: 403", body: #"{"error":"WALLET_SUSPENDED"}"#)
        XCTAssertEqual(suspended.walletLifecycleRefusal, .suspended)
        let revoked = SirosError.backendApi(code: 403, message: "AS request failed: 403", body: #"{"error":"WALLET_REVOKED","message":"deactivated"}"#)
        XCTAssertEqual(revoked.walletLifecycleRefusal, .revoked)
    }

    /// The wire contract go-wallet-backend#340 added, as
    /// `service.LifecycleRefusalDetails` emits it from both
    /// `internal/api/handlers.go` and `internal/as/passkey.go`: `scope` is what
    /// separates a revoked instance from a deactivated wallet, and the two
    /// share the `WALLET_REVOKED` code.
    func testScopeSeparatesARevokedInstanceFromADeactivatedWallet() {
        let suspendedInstance = SirosError.backendApi(
            code: 403, message: "", body: #"{"error":"WALLET_SUSPENDED","scope":"instance","message":"m"}"#
        )
        XCTAssertEqual(suspendedInstance.walletLifecycleRefusal, .suspended)

        let revokedInstance = SirosError.backendApi(
            code: 403, message: "", body: #"{"error":"WALLET_REVOKED","scope":"instance","message":"m"}"#
        )
        XCTAssertEqual(revokedInstance.walletLifecycleRefusal, .revoked)

        let deactivatedWallet = SirosError.backendApi(
            code: 403, message: "", body: #"{"error":"WALLET_REVOKED","scope":"wallet","message":"m"}"#
        )
        XCTAssertEqual(deactivatedWallet.walletLifecycleRefusal, .deactivated)
    }

    /// No `scope` at all is every deployment until #340 ships, and an
    /// unrecognised one is a backend newer than this SDK. Both MUST resolve
    /// `WALLET_REVOKED` to the per-instance case: that is what today's
    /// behaviour already is, and treating it as a deactivation would forget an
    /// account whose other passkeys still work. The `message` is never
    /// consulted, however deactivation-shaped its prose is.
    func testAbsentOrUnrecognisedScopeFallsBackToThePerInstanceCase() {
        let noScope = SirosError.backendApi(
            code: 403, message: "", body: #"{"error":"WALLET_REVOKED","message":"This wallet was deactivated and erased"}"#
        )
        XCTAssertEqual(noScope.walletLifecycleRefusal, .revoked)
        XCTAssertNil(noScope.serverScope)

        let unknownScope = SirosError.backendApi(
            code: 403, message: "", body: #"{"error":"WALLET_REVOKED","scope":"tenant"}"#
        )
        XCTAssertEqual(unknownScope.walletLifecycleRefusal, .revoked)

        let nonStringScope = SirosError.backendApi(
            code: 403, message: "", body: #"{"error":"WALLET_REVOKED","scope":7}"#
        )
        XCTAssertEqual(nonStringScope.walletLifecycleRefusal, .revoked)

        // A scope the backend never pairs with this code changes nothing
        // either: only `WALLET_REVOKED` can become a deactivation.
        let suspendedAtWalletScope = SirosError.backendApi(
            code: 403, message: "", body: #"{"error":"WALLET_SUSPENDED","scope":"wallet"}"#
        )
        XCTAssertEqual(suspendedAtWalletScope.walletLifecycleRefusal, .suspended)
    }

    /// The one value that costs the user their cached account is matched
    /// exactly as the protocol spells it. A case variant is not the wire
    /// value, so it takes the conservative path like any other unknown.
    func testTheWalletScopeIsMatchedExactly() {
        for variant in ["Wallet", "WALLET", " wallet", "wallet "] {
            let error = SirosError.backendApi(
                code: 403, message: "", body: #"{"error":"WALLET_REVOKED","scope":"\#(variant)"}"#
            )
            XCTAssertEqual(
                error.walletLifecycleRefusal, .revoked,
                "\(variant) is not the wire value \"wallet\" and must not reach .deactivated"
            )
        }
        XCTAssertEqual(
            SirosError.WalletLifecycleRefusal.resolve(errorCode: "WALLET_REVOKED", scope: "WALLET"),
            .revoked
        )
    }

    /// `resolve` is the only supported way to build a refusal from the wire,
    /// and the code alone deliberately cannot reach `.deactivated`.
    func testResolveAndErrorCodesRoundTripTheWireContract() {
        XCTAssertEqual(SirosError.WalletLifecycleRefusal.suspended.errorCode, "WALLET_SUSPENDED")
        XCTAssertEqual(SirosError.WalletLifecycleRefusal.revoked.errorCode, "WALLET_REVOKED")
        XCTAssertEqual(SirosError.WalletLifecycleRefusal.deactivated.errorCode, "WALLET_REVOKED")

        XCTAssertEqual(
            SirosError.WalletLifecycleRefusal.resolve(errorCode: "WALLET_REVOKED", scope: walletLifecycleScopeWallet),
            .deactivated
        )
        XCTAssertEqual(
            SirosError.WalletLifecycleRefusal.resolve(errorCode: "WALLET_REVOKED", scope: walletLifecycleScopeInstance),
            .revoked
        )
        XCTAssertEqual(SirosError.WalletLifecycleRefusal.resolve(errorCode: "WALLET_REVOKED", scope: nil), .revoked)
        XCTAssertNil(SirosError.WalletLifecycleRefusal.resolve(errorCode: "auth_failed", scope: "wallet"))

        // The scope-less initialiser kept for source compatibility resolves
        // the same conservative way.
        XCTAssertEqual(SirosError.WalletLifecycleRefusal(rawValue: "WALLET_REVOKED"), .revoked)
        XCTAssertNil(SirosError.WalletLifecycleRefusal(rawValue: "WALLET_DEACTIVATED"))
    }

    /// The raw `scope` is carried next to `serverMessage` so a host app can see
    /// exactly what the backend said.
    func testServerScopeIsCarriedRaw() {
        XCTAssertEqual(
            SirosError.backendApi(code: 403, message: "", body: #"{"error":"WALLET_REVOKED","scope":"wallet"}"#).serverScope,
            "wallet"
        )
        XCTAssertNil(SirosError.backendApi(code: 403, message: "", body: #"{"error":"WALLET_REVOKED"}"#).serverScope)
        XCTAssertNil(SirosError.auth(message: "x").serverScope)
    }

    func testOtherErrorsAreNotRefusals() {
        XCTAssertNil(SirosError.backendApi(code: 403, message: "", body: #"{"error":"Tenant user must use tenant-scoped login endpoint"}"#).walletLifecycleRefusal)
        XCTAssertNil(SirosError.backendApi(code: 401, message: "", body: #"{"error":"WALLET_REVOKED"}"#).walletLifecycleRefusal, "only a 403 carries a lifecycle refusal")
        XCTAssertNil(SirosError.backendApi(code: 403, message: "", body: "not json").walletLifecycleRefusal)
        XCTAssertNil(SirosError.auth(message: "x").walletLifecycleRefusal)
    }

    /// `apiErrorCode` is how the erasure retry and the passkey-link retry
    /// branch on the backend's stable codes without each re-parsing the body;
    /// unlike `walletLifecycleRefusal` it is not restricted to 403.
    func testApiErrorCodeIsReadFromAnyBackendApiBody() {
        XCTAssertEqual(
            SirosError.backendApi(code: 409, message: "", body: #"{"error":"ERASURE_INCOMPLETE","revoked":2}"#).apiErrorCode,
            "ERASURE_INCOMPLETE"
        )
        XCTAssertEqual(
            SirosError.backendApi(code: 403, message: "", body: #"{"error":"CREDENTIAL_NOT_OWNED"}"#).apiErrorCode,
            "CREDENTIAL_NOT_OWNED"
        )
        XCTAssertNil(SirosError.backendApi(code: 500, message: "", body: "not json").apiErrorCode)
        XCTAssertNil(SirosError.auth(message: "x").apiErrorCode)
    }

    /// The backend's `message` is the explanation written for the user (the
    /// SDK branches on `scope`, not on it), so it is carried separately from
    /// the developer-facing `localizedDescription`.
    func testServerMessageIsCarriedSeparatelyFromTheDiagnostic() {
        let error = SirosError.backendApi(
            code: 403,
            message: "AS request failed: 403",
            body: #"{"error":"WALLET_SUSPENDED","message":"This device is suspended"}"#
        )
        XCTAssertEqual(error.serverMessage, "This device is suspended")
        XCTAssertEqual(error.localizedDescription, "403: AS request failed: 403")
        XCTAssertNil(SirosError.backendApi(code: 403, message: "", body: #"{"error":"WALLET_REVOKED"}"#).serverMessage)
    }
}

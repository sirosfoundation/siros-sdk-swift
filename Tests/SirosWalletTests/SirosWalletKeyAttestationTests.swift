// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosAuth
@testable import SirosWallet

// `SirosWallet.init` requires a real `JweKeystore`, only available where
// CryptoKit is (Apple platforms / CI macOS runner) - matching this test
// target's existing `#if canImport(CryptoKit)` convention.
#if canImport(CryptoKit)

/// Minimal `AuthProvider` stub - `currentWalletInstanceId()` never invokes
/// the authenticator, so all methods simply throw.
private final class StubAuthProvider: AuthProvider, @unchecked Sendable {
    struct NotImplemented: Error {}
    func register(options: RegisterOptions) async throws -> RegisterResult { throw NotImplemented() }
    func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw NotImplemented() }
    func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw NotImplemented() }
}

final class SirosWalletKeyAttestationTests: XCTestCase {

    /// header.{claims}.sig - just enough for `CredentialUtils.parseJwtPayload` to read the payload.
    private func fakeWiaJwt(exp: Int64, jkt: String?, attestationSource: String?) -> String {
        var payload: [String: Any] = ["exp": exp]
        if let jkt { payload["cnf"] = ["jkt": jkt] }
        if let attestationSource { payload["attestation_source"] = attestationSource }
        let json = try! JSONSerialization.data(withJSONObject: payload)
        let b64 = json.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "eyJ.\(b64).sig"
    }

    private func makeWallet() -> SirosWallet {
        let config = WalletConfig(backendUrl: "https://example.invalid")
        let wallet = SirosWallet(config: config, authProvider: StubAuthProvider())
        XCTAssertNotNil(wallet, "wallet should initialise with default keystore on CryptoKit platforms")
        return wallet!
    }

    func testCurrentWalletInstanceIdReturnsJktWhenWiaIsNativeAttested() async {
        let wallet = makeWallet()
        let now = Int64(Date().timeIntervalSince1970)
        wallet.cachedWia = fakeWiaJwt(exp: now + 3600, jkt: "test-jkt", attestationSource: "ios_app_attest")
        wallet.cachedWiaExpiresAt = Int(now + 3600)

        let result = await wallet.currentWalletInstanceId()

        XCTAssertEqual(result, "test-jkt")
    }

    func testCurrentWalletInstanceIdReturnsNilWhenWiaIsNotNativeAttested() async {
        let wallet = makeWallet()
        let now = Int64(Date().timeIntervalSince1970)
        // WIA exists but was never verified as native platform attestation -
        // the backend's KA trust gate wouldn't lift the clamp for it anyway,
        // so walletInstanceId must stay omitted.
        wallet.cachedWia = fakeWiaJwt(exp: now + 3600, jkt: "test-jkt", attestationSource: "backend_attested")
        wallet.cachedWiaExpiresAt = Int(now + 3600)

        let result = await wallet.currentWalletInstanceId()

        XCTAssertNil(result)
    }

    func testCurrentWalletInstanceIdReturnsNilWhenNoWiaAvailable() async {
        let wallet = makeWallet()

        // No cached WIA, no backend session configured to fetch one -
        // ensureWalletInstanceAttestation() falls into its own best-effort
        // nil path.
        let result = await wallet.currentWalletInstanceId()

        XCTAssertNil(result)
    }
}

#endif

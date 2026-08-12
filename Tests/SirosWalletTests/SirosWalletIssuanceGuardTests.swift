// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosAuth
import SirosCredentials
@testable import SirosWallet

// `SirosWallet.init` requires a real `JweKeystore`, only available where
// CryptoKit is (Apple platforms / CI macOS runner) - matching this test
// target's existing `#if canImport(CryptoKit)` convention.
#if canImport(CryptoKit)

/// Minimal `AuthProvider` stub - none of these methods are exercised below.
private final class StubAuthProvider: AuthProvider, @unchecked Sendable {
    struct NotImplemented: Error {}
    func register(options: RegisterOptions) async throws -> RegisterResult { throw NotImplemented() }
    func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw NotImplemented() }
    func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw NotImplemented() }
}

/// Regression tests for the ambient `issuanceInFlight` guard, ported from
/// the Kotlin SDK's `cancelCurrentFlow_clearsIssuanceGuard_whenIssuerNeverReachedFlowActive`
/// (siros-sdk-kotlin commit 1a556d6): a slow/unresponsive issuer (real case:
/// the Geneva 2026 interop test issuer) leaves the wallet in `.ready` for as
/// long as it awaits the engine's first progress message - the engine only
/// assigns (and reports) a flow ID once that first message arrives, so
/// `.flowActive` is never reached during that window. Cancelling in exactly
/// that window used to be a complete no-op (the reset was gated on
/// `.flowActive`), permanently stranding `issuanceInFlight` at `true` and
/// blocking every subsequent issuance attempt until the app process was
/// killed.
///
/// Unlike Kotlin's version of this test (which mocks `WalletEngineSession`
/// via mockk, a JVM bytecode-instrumentation mock that works even on a
/// concrete/final class), this SDK's `WalletEngineSession` is a concrete
/// `final class` that opens a real `URLSessionWebSocketTask` - there is no
/// protocol seam to substitute a fake at, and driving `startIssuanceByOffer`/
/// `startIssuance` through a real engine connection would require an actual
/// reachable backend. So this test drives the guard fields directly
/// (`issuanceInFlight`/`activeOffer` are internal, not `private`, precisely
/// so `@testable import` can do this - matching this file's existing
/// precedent, e.g. `SirosWalletKeyAttestationTests` seeding `cachedWia`
/// directly) rather than through the public issuance-start API, while still
/// exercising the real `cancelCurrentFlow()`/`resetIssuanceGuards()`
/// production code path.
final class SirosWalletIssuanceGuardTests: XCTestCase {

    private func makeWallet() -> SirosWallet {
        let config = WalletConfig(backendUrl: "https://example.invalid")
        let wallet = SirosWallet(config: config, authProvider: StubAuthProvider())
        XCTAssertNotNil(wallet, "wallet should initialise with default keystore on CryptoKit platforms")
        return wallet!
    }

    /// `cancelCurrentFlow()` must clear `issuanceInFlight` even when the
    /// wallet never reached `.flowActive` - simulating the real bug: an
    /// issuance was started (setting the guard and `activeOffer`) but the
    /// issuer never progressed far enough for the engine to report a flow
    /// ID, so the wallet is still sitting in `.ready`.
    func testCancelCurrentFlowClearsIssuanceGuardWhenIssuerNeverReachedFlowActive() {
        let wallet = makeWallet()
        wallet.setState(.ready(userId: "user-1", displayName: "Alice", credentials: []))

        // Simulate what startIssuanceByOffer/startIssuance do at the top of
        // their bodies, before the engine has reported any progress at all.
        wallet.issuanceInFlight = true
        wallet.activeOffer = CredentialOffer(
            credentialConfigurationId: "pid",
            credentialIssuerIdentifier: "https://issuer.invalid",
            credentialName: "PID",
            issuerName: "Issuer"
        )
        XCTAssertTrue(wallet.issuanceInFlight)

        wallet.cancelCurrentFlow()

        XCTAssertFalse(
            wallet.issuanceInFlight,
            "cancelCurrentFlow() must clear issuanceInFlight even when no .flowActive state was ever reached"
        )
        XCTAssertNil(wallet.activeOffer, "cancelCurrentFlow() must clear activeOffer unconditionally too")

        // The real-world consequence of the old bug: startIssuanceByOffer/
        // startIssuance check exactly this field at their top and throw
        // "Another issuance is already in progress" whenever it reads
        // `true`. Simulate a second attempt reaching that check directly -
        // with the guard now cleared, it must fall through instead of
        // throwing.
        if wallet.issuanceInFlight {
            XCTFail("guard must be false so a second issuance attempt is not rejected")
        }
    }

    /// `cancelCurrentFlow()` is a no-op when nothing was ever in flight - it
    /// must not crash or leave any guard field in a surprising state.
    func testCancelCurrentFlowIsNoOpWhenNoIssuanceWasInFlight() {
        let wallet = makeWallet()
        wallet.setState(.ready(userId: "user-1", displayName: "Alice", credentials: []))

        wallet.cancelCurrentFlow()

        XCTAssertFalse(wallet.issuanceInFlight)
        XCTAssertNil(wallet.activeOffer)
    }
}

#endif

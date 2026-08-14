// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosAuth
@testable import SirosCredentials

/// Regression tests for `AuthTokens.registerTokenRejection`'s rejection
/// counting/window logic.
///
/// Found via a user asking "why am I not logged out from the wallet when the
/// token is expired?": `registerTokenRejection` already implemented the
/// right threshold/window logic and already had `onSessionRejected` wired to
/// `SirosWallet.handleReauthenticationRequired()` (see
/// `SirosWallet.swift:461-463`) - but nothing in the SDK ever actually
/// CALLED `registerTokenRejection` (confirmed via a repo-wide grep: the only
/// reference was its own declaration), so a real 401 never accumulated
/// toward it no matter how many times it happened. Fixed by wiring a call
/// into it from both places that see a rejected token:
/// `BackendApiClient.request(_:path:body:)` (a non-2xx/401 REST response)
/// and `WalletEngineSession`'s reconnect path (`refreshTokenOrSignalReauth`,
/// via the new `onTokenRejected` closure threaded in from
/// `SirosWallet.connectEngine`). These tests cover the counting/window logic
/// itself, in isolation from either call site.
final class AuthTokensTests: XCTestCase {

    private func makeTokens() -> AuthTokens {
        let client = AuthServerClient(baseUrl: "https://auth.example.invalid", tenantId: "test") { _, _, _, _ in
            Data("{}".utf8)
        }
        return AuthTokens(authServerClient: client, tenantId: "test")
    }

    func testSingleRejectionDoesNotTriggerSessionRejected() {
        let tokens = makeTokens()
        var rejectedCount = 0
        tokens.onSessionRejected = { rejectedCount += 1 }

        tokens.registerTokenRejection(AuthTokens.tokenBackend)

        XCTAssertEqual(rejectedCount, 0, "a single rejection is below the threshold of 3")
    }

    func testThreeRejectionsWithinWindowTriggersSessionRejected() {
        let tokens = makeTokens()
        var rejectedCount = 0
        tokens.onSessionRejected = { rejectedCount += 1 }

        tokens.registerTokenRejection(AuthTokens.tokenBackend)
        tokens.registerTokenRejection(AuthTokens.tokenBackend)
        XCTAssertEqual(rejectedCount, 0, "must not fire before the 3rd rejection")
        tokens.registerTokenRejection(AuthTokens.tokenBackend)

        XCTAssertEqual(rejectedCount, 1)
    }

    func testRejectionsAreTrackedIndependentlyPerTokenName() {
        // 2 rejections against "backend" and 2 against "anonymous" must NOT
        // combine into a shared count of 4 - each token name has its own
        // independent rejection history.
        let tokens = makeTokens()
        var rejectedCount = 0
        tokens.onSessionRejected = { rejectedCount += 1 }

        tokens.registerTokenRejection(AuthTokens.tokenBackend)
        tokens.registerTokenRejection(AuthTokens.tokenAnonymous)
        tokens.registerTokenRejection(AuthTokens.tokenBackend)
        tokens.registerTokenRejection(AuthTokens.tokenAnonymous)

        XCTAssertEqual(rejectedCount, 0)
    }

    func testRejectionsOutsideWindowDoNotAccumulate() {
        // Exercises the pruning logic directly via the injectable `now`
        // clock (see its doc comment in AuthTokens.swift) rather than
        // actually waiting out the real 60-second window: two rejections
        // happen, then time is advanced past the window, then a third
        // rejection happens - since the first two are now outside the
        // window, this must NOT reach the threshold of 3 (there's only 1
        // rejection inside the window at that point).
        let tokens = makeTokens()
        var rejectedCount = 0
        tokens.onSessionRejected = { rejectedCount += 1 }

        var simulatedNow = Date()
        tokens.now = { simulatedNow }

        tokens.registerTokenRejection(AuthTokens.tokenBackend)
        tokens.registerTokenRejection(AuthTokens.tokenBackend)

        simulatedNow = simulatedNow.addingTimeInterval(61)
        tokens.registerTokenRejection(AuthTokens.tokenBackend)

        XCTAssertEqual(rejectedCount, 0, "the first two rejections aged out of the 60s window, so only 1 remains - below threshold")

        // A 2nd and 3rd rejection now within the new window DO reach the
        // threshold, proving the window logic isn't simply broken/inert.
        tokens.registerTokenRejection(AuthTokens.tokenBackend)
        tokens.registerTokenRejection(AuthTokens.tokenBackend)
        XCTAssertEqual(rejectedCount, 1)
    }

    func testClearResetsRejectionHistory() {
        let tokens = makeTokens()
        var rejectedCount = 0
        tokens.onSessionRejected = { rejectedCount += 1 }

        tokens.registerTokenRejection(AuthTokens.tokenBackend)
        tokens.registerTokenRejection(AuthTokens.tokenBackend)
        tokens.clear()
        tokens.registerTokenRejection(AuthTokens.tokenBackend)

        XCTAssertEqual(rejectedCount, 0, "clear() must reset the rejection count, not just the cached tokens")
    }

    /// Builds an `AuthTokens` whose `AuthServerClient` always fails its
    /// token request with the given HTTP status - the shared shape behind
    /// the three "AS token endpoint 401" tests below.
    private func makeTokensFailingWith(code: Int) -> AuthTokens {
        let client = AuthServerClient(baseUrl: "https://auth.example.invalid", tenantId: "test") { _, _, _, _ in
            throw SirosError.backendApi(code: code, message: "AS request failed: \(code) — /auth/token", body: nil)
        }
        return AuthTokens(authServerClient: client, tenantId: "test")
    }

    /// Covers the gap found live in task #245: a raw "AS request failed 401 -
    /// /auth/token" surfaced with no re-auth flow firing when a user tapped
    /// "add credential" with an expired AS session. Unlike
    /// `registerTokenRejection`'s 3-strikes REST-401 case, a 401 straight
    /// from the AS's own token endpoint is unambiguous and must fire
    /// `onSessionRejected` on the very first occurrence.
    func testFourZeroOneFromAsTokenEndpointTriggersSessionRejectedImmediately() async {
        let tokens = makeTokensFailingWith(code: 401)
        var rejectedCount = 0
        tokens.onSessionRejected = { rejectedCount += 1 }

        do {
            _ = try await tokens.ensureBackendToken()
            XCTFail("expected the AS 401 to propagate")
        } catch {
            // Expected - the original failure still propagates to the caller.
        }

        XCTAssertEqual(rejectedCount, 1)
    }

    func testFourZeroOneFromAsTokenEndpointDuringForceRefreshAlsoTriggersSessionRejected() async {
        let tokens = makeTokensFailingWith(code: 401)
        var rejectedCount = 0
        tokens.onSessionRejected = { rejectedCount += 1 }

        do {
            _ = try await tokens.forceRefreshToken(AuthTokens.tokenBackend)
            XCTFail("expected the AS 401 to propagate")
        } catch {
            // Expected.
        }

        XCTAssertEqual(rejectedCount, 1)
    }

    func testNonFourZeroOneAsTokenFailureDoesNotTriggerSessionRejected() async {
        let tokens = makeTokensFailingWith(code: 500)
        var rejectedCount = 0
        tokens.onSessionRejected = { rejectedCount += 1 }

        do {
            _ = try await tokens.ensureBackendToken()
            XCTFail("expected the AS 500 to propagate")
        } catch {
            // Expected.
        }

        XCTAssertEqual(rejectedCount, 0)
    }
}

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

    /// Pins the backend token's Token Access Control string against what the
    /// wallet instance lifecycle endpoints require (SID-AUTH-06,
    /// go-wallet-backend#319): `l` to list instances, `w` to suspend or
    /// reactivate one, `d` to revoke one or to deactivate the wallet. The SDK
    /// mints `rwlid` and so needs no new token kind - this test is what keeps
    /// a future narrowing of the TAC from silently breaking the Devices screen.
    func testBackendTokenTacCoversTheWalletInstanceLifecycleEndpoints() throws {
        let tac = try XCTUnwrap(AuthTokens.manifest["backend"]).tac
        XCTAssertTrue(tac.contains("l"), "list instances needs 'l' in \(tac)")
        XCTAssertTrue(tac.contains("w"), "suspend/reactivate needs 'w' in \(tac)")
        XCTAssertTrue(tac.contains("d"), "revoke and revoke-all need 'd' in \(tac)")
    }

    /// `ensureToken` releases its lock while it awaits the AS, so a request
    /// issued before a lifecycle cut-off can land after the clear the cut-off
    /// triggered. Caching it then would hand the replacement session a token
    /// the backend has already refused - the very thing the clear was for.
    ///
    /// The token is still returned to its own caller; it just is not kept. If
    /// `AuthTokens` kept it, the second `ensureBackendToken()` below would be
    /// served from its cache and never reach the AS at all.
    func testATokenMintedBeforeAClearIsNotCachedForTheSessionThatReplacedIt() async throws {
        let server = StubTokenServer()
        let client = server.asClient
        let tokens = AuthTokens(authServerClient: client, tenantId: "default")
        // Both caches cleared while the request is in flight - exactly what
        // `SirosWallet.reloginAfterCutOff` does on a concurrent re-login.
        server.onRequest = { tokens.clear(); await client.clearTokenCache() }

        _ = try await tokens.ensureBackendToken()
        XCTAssertEqual(server.requestCount, 1, "the in-flight request itself completes normally")

        server.onRequest = nil
        _ = try await tokens.ensureBackendToken()
        XCTAssertEqual(
            server.requestCount, 2,
            "the superseded token was cached by neither layer, so the next caller mints a fresh one"
        )
    }

    // MARK: - The tenant-bound engine kind (W10, engine-parity.md §8)

    /// The manifest's engine kind: the audience and the TAC the WMP engine's
    /// flow-start gate enforces (read for OID4VP, insert for OID4VCI), and
    /// the pseudonymous flag - the token carries a rotating pseudonym, not
    /// the user, so it is not the anonymous kind either (which carries no
    /// subject at all).
    func testTenantTokenIsThePseudonymousEngineKind() throws {
        let kind = try XCTUnwrap(AuthTokens.manifest[AuthTokens.tokenWmpEngine])
        XCTAssertEqual(kind.aud, "wallet-engine")
        XCTAssertTrue(kind.tac.contains("r"), "OID4VP's flow gate needs 'r' in \(kind.tac)")
        XCTAssertTrue(kind.tac.contains("i"), "OID4VCI's flow gate needs 'i' in \(kind.tac)")
        XCTAssertTrue(kind.pseudonymous, "the kind is pseudonymous: a rotating pseudonym, not the user")
        XCTAssertFalse(kind.anonymous, "the kind is not the anonymous one: the token carries a subject (the pseudonym)")
    }

    /// The tenant kind mints through the AS's `pseudonymous` request - the
    /// wire shape the go-wallet-backend kind answers (a real session behind
    /// the mint, a fresh pseudonym per mint) - and never through the
    /// anonymous or plain access-token forms.
    func testEnsureTenantTokenMintsThePseudonymousRequest() async throws {
        let server = StubTokenServer()
        let recorder = RequestRecorder()
        server.onBody = { recorder.append($0) }
        let tokens = AuthTokens(authServerClient: server.asClient, tenantId: "default")

        _ = try await tokens.ensureTenantToken()
        _ = try await tokens.ensureTenantToken()

        let bodies = recorder.bodies
        XCTAssertEqual(bodies.count, 1, "the second ensure is served from the cache, not the AS")
        let body = try XCTUnwrap(bodies.first)
        XCTAssertEqual(body["pseudonymous"] as? Bool, true, "the wire kind is the AS's pseudonymous one")
        XCTAssertNil(body["anonymous"], "never the anonymous kind: the token carries a subject")
        XCTAssertEqual(body["aud"] as? String, "wallet-engine")
    }

    /// A force-refresh of the tenant kind re-mints - the pseudonym rotates
    /// per mint, which is the point of the kind. The re-mint needs BOTH
    /// caches cleared (the `AuthTokens` cache by `forceRefreshToken`, the
    /// client's own by `clearTokenCache`) - exactly the pair
    /// `SirosWallet.reloginAfterCutOff` clears on a lifecycle cut-off.
    func testForceRefreshTenantTokenMintsAfresh() async throws {
        let server = StubTokenServer()
        let recorder = RequestRecorder()
        server.onBody = { recorder.append($0) }
        let client = server.asClient
        let tokens = AuthTokens(authServerClient: client, tenantId: "default")

        _ = try await tokens.ensureTenantToken()
        await client.clearTokenCache()
        _ = try await tokens.forceRefreshToken(AuthTokens.tokenWmpEngine)

        XCTAssertEqual(recorder.bodies.count, 2, "both caches cleared: the refresh mints a fresh pseudonym")
    }
}

/// A minimal `AuthServerClient` that answers `/auth/token` with a freshly
/// minted, unexpired token and can run a hook while the "request" is in
/// flight.
private final class StubTokenServer: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    var onRequest: (@Sendable () async -> Void)?
    /// Observed with each request's parsed body (the `pseudonymous`/
    /// `anonymous` kind flags are what the wire-contract tests read).
    var onBody: (@Sendable ([String: Any]) -> Void)?
    var requestCount: Int { lock.lock(); defer { lock.unlock() }; return count }

    lazy var asClient: AuthServerClient = AuthServerClient(
        baseUrl: "https://as.example.invalid",
        tenantId: "default"
    ) { [self] _, _, _, body in
        self.lock.lock(); self.count += 1; self.lock.unlock()
        if let body, let parsed = try? JSONSerialization.jsonObject(with: body) as? [String: Any] {
            self.onBody?(parsed)
        }
        await self.onRequest?()
        let exp = Int(Date().timeIntervalSince1970) + 3600
        let payload = try JSONSerialization.data(withJSONObject: [
            "exp": exp, "aud": "wallet-backend", "tenant_id": "default", "tac": "rwlid",
        ])
        let b64 = payload.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let jwt = "eyJhbGciOiJub25lIn0.\(b64).sig"
        return try JSONSerialization.data(withJSONObject: [
            "access_token": jwt, "token_type": "Bearer", "expires_in": 3600,
        ])
    }
}

/// A thread-safe observer for the request bodies `StubTokenServer` sees.
private final class RequestRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [[String: Any]] = []
    var bodies: [[String: Any]] {
        lock.lock(); defer { lock.unlock() }
        return recorded
    }
    func append(_ body: [String: Any]) {
        lock.lock(); defer { lock.unlock() }
        recorded.append(body)
    }
}

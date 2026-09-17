// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosAuth
import SirosCredentials
import SirosKeystore
@testable import SirosWallet

/// Wallet instance lifecycle (SID-AUTH-06, go-wallet-backend#319) at the
/// facade: the blocked state, forget-on-revoked, the once-only re-login guard,
/// `isThisDevice`, and the `DeactivationOutcome` a deactivation reports.
///
/// Uses a stub `KeystoreManager` (like `SirosWalletRegistryUrlTests`) so it
/// runs identically on Linux and Apple platforms, without CryptoKit.
private final class StubAuthProvider: AuthProvider, @unchecked Sendable {
    struct NotImplemented: Error {}
    func register(options: RegisterOptions) async throws -> RegisterResult { throw NotImplemented() }
    func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw NotImplemented() }
    func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw NotImplemented() }
}

private final class StubKeystoreManager: KeystoreManager, @unchecked Sendable {
    var isUnlocked: Bool { true }
    func unlock(prfOutput: Data, encryptedContainer: Data, hkdfSalt: Data, hkdfInfo: Data) async throws {}
    func lock() {}
    func generateKey(algorithm: String) async throws -> String { "key" }
    func sign(keyId: String, payload: Data, algorithm: String) async throws -> Data { Data() }
    func generateProof(audience: String, nonce: String, freshKey: Bool) async throws -> String { "proof" }
    func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String { "" }
    func signVpToken(credential: String, disclosedClaims: [String]?, nonce: String, audience: String, kid: String?) async throws -> String { "" }
    func exportEncryptedContainer() async throws -> Data { Data() }
    func listKeys() -> [KeyInfo] { [] }
    func saveCredential(id: Int64, json: String) async throws {}
    func getCredential(id: Int64) async throws -> String? { nil }
    func getAllCredentials() async throws -> [Int64: String] { [:] }
    func deleteCredential(id: Int64) async throws {}
    func clearCredentials() async throws {}
    func savePresentationRecord(id: Int64, json: String) async throws {}
    func getAllPresentationRecords() async throws -> [Int64: String] { [:] }
    func clearPresentationRecords() async throws {}
    func generateKeypairs(count: Int) async throws -> [KeypairInfo] { [] }
}

/// Minimal queued-response HTTP stub (the `SirosAuthTests` MockHttpServer
/// lives in another test target).
private final class StubHttpServer: @unchecked Sendable {
    private let lock = NSLock()
    private var responses: [Result<Data, Error>] = []
    private(set) var requestCount = 0

    func enqueue(_ json: String) {
        lock.lock(); responses.append(.success(Data(json.utf8))); lock.unlock()
    }

    func enqueueFailure(code: Int, body: String) {
        lock.lock()
        responses.append(.failure(SirosError.backendApi(code: code, message: "API request failed: \(code)", body: body)))
        lock.unlock()
    }

    struct Exhausted: Error {}

    var httpFunction: @Sendable (String, URL, [String: String], Data?) async throws -> Data {
        { [weak self] _, _, _, _ in
            guard let self else { throw Exhausted() }
            self.lock.lock()
            self.requestCount += 1
            guard !self.responses.isEmpty else { self.lock.unlock(); throw Exhausted() }
            let next = self.responses.removeFirst()
            self.lock.unlock()
            return try next.get()
        }
    }
}

/// Records the two lifecycle callbacks under test.
private final class RecordingListener: WalletEventListener, @unchecked Sendable {
    var reauthenticationRequired = false
    var blocked: (reason: SirosError.WalletLifecycleRefusal, message: String?)?
    func onCredentialSelectionRequired(request: PresentationRequest) async -> [Int64] { [] }
    func onReauthenticationRequired() { reauthenticationRequired = true }
    func onWalletLifecycleBlocked(reason: SirosError.WalletLifecycleRefusal, message: String?) {
        blocked = (reason, message)
    }
}

final class SirosWalletLifecycleTests: XCTestCase {

    private func makeWallet(
        registry: AccountRegistry = AccountRegistry.inMemory(),
        sessionStore: SessionStoreProtocol = InMemorySessionStore()
    ) -> SirosWallet {
        let config = WalletConfig(backendUrl: "https://wallet.example.invalid")
        let wallet = SirosWallet(
            config: config,
            authProvider: StubAuthProvider(),
            sessionStore: sessionStore,
            keystore: StubKeystoreManager(),
            accountRegistry: registry
        )
        XCTAssertNotNil(wallet)
        return wallet!
    }

    private func seededRegistry() -> AccountRegistry {
        let registry = AccountRegistry.inMemory()
        let account = CachedAccount(
            userId: "user-1",
            tenantId: "default",
            displayName: "Alice",
            backendUrl: "https://wallet.example.invalid",
            passkeys: [CachedPasskey(credentialId: "cred-1", prfSalt: "c2FsdA==")]
        )
        registry.upsertAccount(account)
        registry.activeAccountId = account.accountId
        return registry
    }

    /// header.{claims}.sig - just enough for `CredentialUtils.parseJwtPayload`.
    private func fakeWiaJwt(exp: Int, jkt: String) -> String {
        let json = try! JSONSerialization.data(withJSONObject: ["exp": exp, "cnf": ["jkt": jkt]])
        let b64 = json.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "eyJ.\(b64).sig"
    }

    private func seedWia(_ wallet: SirosWallet, jkt: String) {
        let exp = Int(Date().timeIntervalSince1970) + 3600
        wallet.cachedWia = fakeWiaJwt(exp: exp, jkt: jkt)
        wallet.cachedWiaExpiresAt = exp
    }

    // MARK: - The blocked state

    /// A login refused with `403 WALLET_SUSPENDED` is a state, not an error:
    /// the instance can be reactivated from another device, so the cached
    /// account stays on the login screen and nothing local is lost.
    func testSuspendedRefusalKeepsTheCachedAccount() {
        let registry = seededRegistry()
        let wallet = makeWallet(registry: registry)
        let listener = RecordingListener()
        wallet.setEventListener(listener)

        let handled = wallet.handleLifecycleRefusal(SirosError.backendApi(
            code: 403,
            message: "AS request failed: 403",
            body: #"{"error":"WALLET_SUSPENDED","message":"This device is suspended"}"#
        ))

        XCTAssertTrue(handled)
        guard case let .lifecycleBlocked(reason, message, accounts) = wallet.state else {
            return XCTFail("expected .lifecycleBlocked, got \(wallet.state)")
        }
        XCTAssertEqual(reason, .suspended)
        XCTAssertEqual(message, "This device is suspended")
        XCTAssertEqual(accounts.count, 1, "a suspended instance keeps its cached account")
        XCTAssertEqual(registry.listLoginableAccounts().count, 1)
        XCTAssertEqual(listener.blocked?.reason, .suspended)
        XCTAssertEqual(listener.blocked?.message, "This device is suspended")
    }

    /// `WALLET_REVOKED` means the wallet was deactivated and its server-side
    /// data erased - that passkey can never log in to this tenant again, so
    /// the cached account is forgotten rather than left on the login screen as
    /// a door that is bricked shut.
    func testRevokedRefusalForgetsTheCachedAccount() {
        let registry = seededRegistry()
        let wallet = makeWallet(registry: registry)

        let handled = wallet.handleLifecycleRefusal(SirosError.backendApi(
            code: 403,
            message: "AS request failed: 403",
            body: #"{"error":"WALLET_REVOKED","message":"This wallet was deactivated"}"#
        ))

        XCTAssertTrue(handled)
        guard case let .lifecycleBlocked(reason, _, accounts) = wallet.state else {
            return XCTFail("expected .lifecycleBlocked, got \(wallet.state)")
        }
        XCTAssertEqual(reason, .revoked)
        XCTAssertTrue(accounts.isEmpty)
        XCTAssertTrue(registry.listLoginableAccounts().isEmpty, "a revoked wallet's account is forgotten")
    }

    /// Everything that is not one of the two lifecycle codes keeps the
    /// existing error path, untouched.
    func testOtherFailuresAreNotLifecycleRefusals() {
        let wallet = makeWallet(registry: seededRegistry())

        XCTAssertFalse(wallet.handleLifecycleRefusal(SirosError.backendApi(
            code: 401, message: "AS request failed: 401", body: #"{"error":"auth_failed"}"#
        )))
        XCTAssertFalse(wallet.handleLifecycleRefusal(SirosError.network(message: "offline")))
        if case .lifecycleBlocked = wallet.state {
            XCTFail("a non-lifecycle failure must not enter the blocked state")
        }
    }

    // MARK: - One re-login, never a loop

    /// The guard behind the single self-driven re-login: while one is running,
    /// the 401s it may itself provoke cannot start another.
    func testSelfDrivenReloginHappensOnlyOnceAtATime() {
        let wallet = makeWallet()

        XCTAssertTrue(wallet.beginSelfDrivenRelogin())
        XCTAssertFalse(wallet.beginSelfDrivenRelogin(), "a second signal must not start another re-login")
        wallet.endSelfDrivenRelogin()
        XCTAssertTrue(wallet.beginSelfDrivenRelogin(), "a later cut-off may be handled again")
    }

    // MARK: - This device

    /// The facade marks the row that is this installation by comparing the
    /// backend's instance ids to the instance-key thumbprint it already sends
    /// as `wallet_instance_id` (the WIA's `cnf.jkt`).
    func testListWalletInstancesMarksThisDeviceFromTheInstanceKeyThumbprint() async throws {
        let wallet = makeWallet()
        seedWia(wallet, jkt: "jkt-self")
        let server = StubHttpServer()
        server.enqueue(#"{"instances":[{"id":"jkt-self","status":"active"},{"id":"jkt-other","status":"suspended"}]}"#)
        let client = BackendApiClient(baseUrl: "https://wallet.example.invalid", httpFn: server.httpFunction)
        client.setAppToken("t")
        wallet.apiClient = client

        let instances = try await wallet.listWalletInstances()

        XCTAssertEqual(wallet.thisInstanceId, "jkt-self")
        XCTAssertEqual(instances.count, 2)
        XCTAssertTrue(try XCTUnwrap(instances.first { $0.id == "jkt-self" }).isThisDevice)
        XCTAssertFalse(try XCTUnwrap(instances.first { $0.id == "jkt-other" }).isThisDevice)
        // The thumbprint was already known, so no attestation round trip.
        XCTAssertEqual(server.requestCount, 1)
    }

    func testThisInstanceIdIsNilWithoutAWia() {
        XCTAssertNil(makeWallet().thisInstanceId)
    }

    // MARK: - The cut-off re-login

    /// An authorization server that refuses every login with one lifecycle
    /// code, and counts how many times it was asked.
    private func refusingAuthServer(_ code: String, message: String) -> (AuthServerClient, () -> Int) {
        let counter = Counter()
        let body = "{\"error\":\"\(code)\",\"message\":\"\(message)\"}"
        let client = AuthServerClient(baseUrl: "https://wallet.example.invalid", tenantId: "default") { _, url, _, _ in
            // Count only the login attempts: `logout()` posts to this same
            // client on its way through the blocked state, and that is not a
            // second attempt at logging in.
            if url.path.hasSuffix("/login/begin") { counter.increment() }
            throw SirosError.backendApi(code: 403, message: "AS request failed: 403", body: body)
        }
        return (client, { counter.value })
    }

    private final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var count = 0
        func increment() { lock.lock(); count += 1; lock.unlock() }
        var value: Int { lock.lock(); defer { lock.unlock() }; return count }
    }

    /// Every status write records a cut-off, and the acting token's exemption
    /// does not reach `POST /auth/token` or an engine flow start - so the
    /// facade re-logs in rather than letting the next flow discover it as a
    /// 401. Suspending this device's own instance therefore ends in
    /// `.lifecycleBlocked(reason: .suspended, ...)`, which is the truthful
    /// state.
    func testSuspendingThisDeviceRelogsInAndLandsInTheBlockedState() async throws {
        let registry = seededRegistry()
        let wallet = makeWallet(registry: registry)
        let (asClient, loginAttempts) = refusingAuthServer("WALLET_SUSPENDED", message: "This device is suspended")
        wallet.authServerClient = asClient
        let server = StubHttpServer()
        server.enqueue(#"{"id":"jkt-self","status":"suspended"}"#)
        let client = BackendApiClient(baseUrl: "https://wallet.example.invalid", httpFn: server.httpFunction)
        client.setAppToken("t")
        wallet.apiClient = client

        let updated = try await wallet.setWalletInstanceStatus(
            instanceId: "jkt-self", status: .suspended, reason: "lost phone"
        )

        XCTAssertEqual(updated.status, .suspended)
        XCTAssertEqual(loginAttempts(), 1, "exactly one self-driven re-login, never a loop")
        guard case let .lifecycleBlocked(reason, message, _) = wallet.state else {
            return XCTFail("expected .lifecycleBlocked, got \(wallet.state)")
        }
        XCTAssertEqual(reason, .suspended)
        XCTAssertEqual(message, "This device is suspended")
        XCTAssertEqual(registry.listLoginableAccounts().count, 1, "a suspended instance keeps its account")
    }

    /// The token cut-off: after a lifecycle change made elsewhere every
    /// request is refused with 401, the SDK's reauthentication signal fires,
    /// and the SDK itself attempts exactly one login - which the AS refuses
    /// with the lifecycle code. The host's own hook still fires, so apps that
    /// drive their own prompt see no change in ordering.
    func testReauthenticationSignalDrivesOneReloginIntoTheBlockedState() async throws {
        let registry = seededRegistry()
        let wallet = makeWallet(registry: registry)
        let listener = RecordingListener()
        wallet.setEventListener(listener)
        let (asClient, loginAttempts) = refusingAuthServer("WALLET_REVOKED", message: "This wallet was deactivated")
        wallet.authServerClient = asClient

        wallet.handleReauthenticationRequired()
        // The attempt runs in a detached Task; wait for it to settle.
        try await waitUntil { loginAttempts() == 1 && !wallet.reloginInProgress }

        XCTAssertTrue(listener.reauthenticationRequired, "the host hook still fires")
        XCTAssertEqual(loginAttempts(), 1)
        XCTAssertEqual(listener.blocked?.reason, .revoked)
        guard case .lifecycleBlocked(.revoked, _, _) = wallet.state else {
            return XCTFail("expected .lifecycleBlocked(.revoked), got \(wallet.state)")
        }
        XCTAssertTrue(registry.listLoginableAccounts().isEmpty, "a revoked wallet's account is forgotten")
    }

    /// Exactly once, never a loop: the 401s the re-login's own requests may
    /// provoke re-enter the same signal, and must not start a second attempt.
    func testARepeatedReauthenticationSignalDoesNotStartASecondRelogin() async throws {
        let wallet = makeWallet(registry: seededRegistry())
        let (asClient, loginAttempts) = refusingAuthServer("WALLET_SUSPENDED", message: "suspended")
        wallet.authServerClient = asClient

        wallet.handleReauthenticationRequired()
        wallet.handleReauthenticationRequired()
        try await waitUntil { !wallet.reloginInProgress && loginAttempts() >= 1 }

        XCTAssertEqual(loginAttempts(), 1)
    }

    private func waitUntil(
        timeout: TimeInterval = 5,
        _ condition: @escaping () -> Bool
    ) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if condition() { return }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTFail("condition not met within \(timeout)s")
    }

    // MARK: - Deactivation

    /// `deactivateWallet` reports what the backend actually did and forgets the
    /// local account - the vault it decrypts no longer exists.
    func testDeactivateWalletReportsTheOutcomeAndForgetsTheAccount() async throws {
        let registry = seededRegistry()
        let wallet = makeWallet(registry: registry)
        let server = StubHttpServer()
        server.enqueue(#"{"revoked":2}"#)
        let client = BackendApiClient(baseUrl: "https://wallet.example.invalid", httpFn: server.httpFunction)
        client.setAppToken("t")
        wallet.apiClient = client

        let outcome = try await wallet.deactivateWallet(reason: "device stolen")

        XCTAssertEqual(outcome, DeactivationOutcome(revoked: 2, complete: true))
        XCTAssertTrue(registry.listLoginableAccounts().isEmpty)
    }

    /// An erasure the backend could not finish still deactivated the wallet -
    /// the revocations stand and the keys are gone or going - so the local
    /// account is forgotten either way; `complete` is only what the app tells
    /// the user.
    func testDeactivateWalletForgetsTheAccountEvenWhenTheErasureIsIncomplete() async throws {
        let registry = seededRegistry()
        let wallet = makeWallet(registry: registry)
        let server = StubHttpServer()
        for _ in 0..<5 {
            server.enqueueFailure(code: 409, body: #"{"error":"ERASURE_INCOMPLETE","revoked":2}"#)
        }
        let client = BackendApiClient(
            baseUrl: "https://wallet.example.invalid",
            tenantId: "default",
            erasureRetryDelays: [0, 0, 0, 0],
            httpFn: server.httpFunction
        )
        client.setAppToken("t")
        wallet.apiClient = client

        let outcome = try await wallet.deactivateWallet()

        XCTAssertEqual(outcome, DeactivationOutcome(revoked: 2, complete: false))
        XCTAssertEqual(server.requestCount, 5)
        XCTAssertTrue(registry.listLoginableAccounts().isEmpty)
    }
}

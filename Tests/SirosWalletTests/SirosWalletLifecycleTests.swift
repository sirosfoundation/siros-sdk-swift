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
    // The WIA-generation path signs a PoP with the instance key; the protocol's
    // default implementation throws, which would make
    // `ensureWalletInstanceAttestation()` bail before ever reaching the
    // request under test.
    func generateKeyProof(
        keyId: String, typ: String, issuer: String, audience: String, extraClaims: [String: String]
    ) async throws -> String { "pop.jwt" }
}

/// Minimal queued-response HTTP stub (the `SirosAuthTests` MockHttpServer
/// lives in another test target).
private final class StubHttpServer: @unchecked Sendable {
    private let lock = NSLock()
    private var responses: [Result<Data, Error>] = []
    private(set) var requestCount = 0
    /// Parsed JSON body of each request, in order.
    private(set) var bodies: [[String: Any]?] = []

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
        { [weak self] _, _, _, body in
            guard let self else { throw Exhausted() }
            self.lock.lock()
            self.requestCount += 1
            self.bodies.append(body.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] })
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
    func testSuspendedRefusalKeepsTheCachedAccount()async {
        let registry = seededRegistry()
        let wallet = makeWallet(registry: registry)
        let listener = RecordingListener()
        wallet.setEventListener(listener)
        wallet.setState(.ready(userId: "user-1", displayName: "Alice", credentials: []))

        let handled = await wallet.handleLifecycleRefusal(SirosError.backendApi(
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

    /// `WALLET_REVOKED` does **not** mean the wallet was erased: the backend
    /// returns it for the login gate of a single revoked instance too, and the
    /// user's other devices keep working. Only the human-readable message
    /// tells the two apart, so the SDK keeps the cached account - forgetting it
    /// on a per-instance revocation would destroy the other passkeys that
    /// still work.
    func testRevokedRefusalKeepsTheCachedAccount()async {
        let registry = seededRegistry()
        let wallet = makeWallet(registry: registry)
        wallet.setState(.ready(userId: "user-1", displayName: "Alice", credentials: []))

        let handled = await wallet.handleLifecycleRefusal(SirosError.backendApi(
            code: 403,
            message: "AS request failed: 403",
            body: #"{"error":"WALLET_REVOKED","message":"This device was removed"}"#
        ))

        XCTAssertTrue(handled)
        guard case let .lifecycleBlocked(reason, message, accounts) = wallet.state else {
            return XCTFail("expected .lifecycleBlocked, got \(wallet.state)")
        }
        XCTAssertEqual(reason, .revoked)
        XCTAssertEqual(message, "This device was removed")
        XCTAssertEqual(accounts.count, 1)
        XCTAssertEqual(
            registry.listLoginableAccounts().count, 1,
            "the account survives: a revoked instance is not necessarily a deactivated wallet"
        )
    }

    /// A suspended instance is reactivated from another device and the app
    /// retries `login()`, which reuses the same AS session cookie. An
    /// unawaited `DELETE /auth/session` scheduled by the block could land
    /// after that retry's `loginFinish` and invalidate the session it had just
    /// established - so the blocked path tears down locally and never asks the
    /// AS to end a session the backend has already refused.
    func testALifecycleBlockDoesNotEndTheServerSession() async throws {
        let wallet = makeWallet(registry: seededRegistry())
        let server = RecordingAuthServer()
        wallet.authServerClient = server.client
        wallet.setState(.ready(userId: "user-1", displayName: "Alice", credentials: []))

        _ = await wallet.handleLifecycleRefusal(SirosError.backendApi(
            code: 403, message: "", body: #"{"error":"WALLET_SUSPENDED"}"#
        ))
        // Whatever the blocked path scheduled has had every chance to run.
        try await Task.sleep(nanoseconds: 100_000_000)

        XCTAssertEqual(
            server.deletedSessions, 0,
            "no DELETE /auth/session may race the retry the user is about to make"
        )

        // The contrast: an explicit logout does end the server session.
        wallet.logout()
        try await Task.sleep(nanoseconds: 100_000_000)
        XCTAssertEqual(server.deletedSessions, 1)
    }

    /// Counts `DELETE /auth/session` calls.
    private final class RecordingAuthServer: @unchecked Sendable {
        private let lock = NSLock()
        private var deletes = 0
        var deletedSessions: Int { lock.lock(); defer { lock.unlock() }; return deletes }

        lazy var client: AuthServerClient = AuthServerClient(
            baseUrl: "https://wallet.example.invalid",
            tenantId: "default"
        ) { [self] method, url, _, _ in
            if method == "DELETE", url.path.hasSuffix("/auth/session") {
                self.lock.lock(); self.deletes += 1; self.lock.unlock()
            }
            return Data("{}".utf8)
        }
    }

    /// Everything that is not one of the two lifecycle codes keeps the
    /// existing error path, untouched.
    func testOtherFailuresAreNotLifecycleRefusals()async {
        let wallet = makeWallet(registry: seededRegistry())

        let plain401 = await wallet.handleLifecycleRefusal(SirosError.backendApi(
            code: 401, message: "AS request failed: 401", body: #"{"error":"auth_failed"}"#
        ))
        XCTAssertFalse(plain401)
        let offline = await wallet.handleLifecycleRefusal(SirosError.network(message: "offline"))
        XCTAssertFalse(offline)
        if case .lifecycleBlocked = wallet.state {
            XCTFail("a non-lifecycle failure must not enter the blocked state")
        }
    }

    // MARK: - One re-login, never a loop

    /// Once per session, not once per call. Requests issued before a cut-off
    /// complete long after it and each of their 401s re-enters the signal, so
    /// releasing the in-progress flag must not re-open the door for the same
    /// session - only a new session may be cut off again.
    func testSelfDrivenReloginHappensOncePerSession() {
        let wallet = makeWallet()
        wallet.setState(.ready(userId: "user-1", displayName: "Alice", credentials: []))

        XCTAssertNotNil(wallet.beginSelfDrivenRelogin())
        XCTAssertNil(wallet.beginSelfDrivenRelogin(), "a second signal must not start another re-login")
        wallet.endSelfDrivenRelogin()
        XCTAssertNil(
            wallet.beginSelfDrivenRelogin(),
            "a late 401 from the session already handled must not start a second re-login"
        )

        // A new session - a successful login bumps the generation - may be cut
        // off in its own right.
        wallet.bumpSessionGeneration()
        XCTAssertNotNil(wallet.beginSelfDrivenRelogin(), "a cut-off on the new session is handled")
    }

    /// There is nothing to replace once the session is gone, and a silent
    /// WebAuthn prompt after an explicit logout would be the wrong answer.
    func testNoSelfDrivenReloginWithoutASessionToReplace() {
        let wallet = makeWallet()

        wallet.setState(.disconnected())
        XCTAssertNil(wallet.beginSelfDrivenRelogin())
        wallet.bumpSessionGeneration()
        wallet.setState(.error(message: "boom"))
        XCTAssertNil(wallet.beginSelfDrivenRelogin())
        wallet.bumpSessionGeneration()
        wallet.setState(.lifecycleBlocked(reason: .suspended, message: nil))
        XCTAssertNil(wallet.beginSelfDrivenRelogin())
    }

    /// `destroy()` leaves the state alone - a destroyed wallet is not a
    /// logged-out one - so the generation bump on its own would still let a
    /// reauthentication signal from a task still unwinding pass the guard and
    /// log back in after the host tore the wallet down.
    func testNoSelfDrivenReloginAfterDestroy() {
        let wallet = makeWallet()
        wallet.setState(.ready(userId: "user-1", displayName: "Alice", credentials: []))
        wallet.destroy()

        XCTAssertNil(wallet.beginSelfDrivenRelogin())
    }

    /// `.connecting` is also where the initial `login()` and `resumeSession()`
    /// sit before their own setup finishes, and a 401 from `/auth/token` fires
    /// the signal immediately - a second ceremony started underneath the first
    /// would race its state, its API client and its keystore.
    func testConnectingIsNotAReplaceableSession() {
        let wallet = makeWallet()
        wallet.setState(.connecting)

        XCTAssertNil(wallet.beginSelfDrivenRelogin())
    }

    /// The teardown a re-login performs awaits the old session's WMP peer and
    /// token caches; a logout landing in that window must abandon the attempt
    /// rather than resurrect the session the user just ended.
    func testReloginAbandonsWhenTheSessionItReplacedIsAlreadyGone() async throws {
        let wallet = makeWallet(registry: seededRegistry())
        let (asClient, loginAttempts) = refusingAuthServer("WALLET_SUSPENDED", message: "suspended")
        wallet.authServerClient = asClient
        wallet.setState(.ready(userId: "user-1", displayName: "Alice", credentials: []))
        let generation = try XCTUnwrap(wallet.beginSelfDrivenRelogin())

        // What logout()/destroy() do to the generation, landing while the
        // re-login is between claiming the signal and reaching login().
        wallet.bumpSessionGeneration()
        await wallet.reloginAfterCutOff(replacing: generation)
        wallet.endSelfDrivenRelogin()

        XCTAssertEqual(loginAttempts(), 0, "no login is attempted for a session that is already gone")
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
        wallet.setState(.ready(userId: "user-1", displayName: "Alice", credentials: []))

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
        wallet.setState(.ready(userId: "user-1", displayName: "Alice", credentials: []))

        wallet.handleReauthenticationRequired()
        // The attempt runs in a detached Task; wait for it to settle.
        try await waitUntil { loginAttempts() == 1 && !wallet.reloginInProgress }

        XCTAssertTrue(listener.reauthenticationRequired, "the host hook still fires")
        XCTAssertEqual(loginAttempts(), 1)
        XCTAssertEqual(listener.blocked?.reason, .revoked)
        guard case .lifecycleBlocked(.revoked, _, _) = wallet.state else {
            return XCTFail("expected .lifecycleBlocked(.revoked), got \(wallet.state)")
        }
        XCTAssertEqual(
            registry.listLoginableAccounts().count, 1,
            "the account survives a WALLET_REVOKED: it may be one instance, not the whole wallet"
        )
    }

    /// Exactly once, never a loop: the 401s the re-login's own requests may
    /// provoke re-enter the same signal, and must not start a second attempt.
    func testARepeatedReauthenticationSignalDoesNotStartASecondRelogin() async throws {
        let wallet = makeWallet(registry: seededRegistry())
        let (asClient, loginAttempts) = refusingAuthServer("WALLET_SUSPENDED", message: "suspended")
        wallet.authServerClient = asClient
        wallet.setState(.ready(userId: "user-1", displayName: "Alice", credentials: []))

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

    // MARK: - The passkey link at WIA generation

    /// A `credential_id` the backend refuses as not the caller's own would, if
    /// the SDK gave up, leave this instance with no attestation at all - and
    /// the first link recorded for an instance wins, so guessing another id
    /// could lock the real passkey out of the per-device gate for good. Retry
    /// once without the link and drop the stale id.
    func testWiaGenerationRetriesWithoutThePasskeyLinkWhenTheBackendRefusesIt() async throws {
        let sessionStore = InMemorySessionStore()
        // The store is account-scoped: nothing can be written to it before an
        // account is active (the same reason `login()` scopes it before it
        // records the passkey link).
        sessionStore.activeAccountId = "default:user-1"
        sessionStore.credentialId = "stale-passkey"
        let wallet = makeWallet(sessionStore: sessionStore)
        let server = StubHttpServer()
        server.enqueue(#"{"challenge":"chal-1"}"#)                                       // WIA challenge
        server.enqueueFailure(code: 403, body: #"{"error":"CREDENTIAL_NOT_OWNED"}"#)     // with the stale link
        server.enqueue(#"{"wallet_instance_attestation":"wia.jwt"}"#)                    // retry without it
        let client = BackendApiClient(baseUrl: "https://wallet.example.invalid", httpFn: server.httpFunction)
        client.setAppToken("t")
        wallet.apiClient = client

        let wia = await wallet.ensureWalletInstanceAttestation()

        XCTAssertEqual(wia, "wia.jwt")
        XCTAssertNil(sessionStore.credentialId, "the stale link is dropped, never replaced with a guess")
        XCTAssertEqual(server.requestCount, 3)
        XCTAssertEqual(server.bodies[1]?["credential_id"] as? String, "stale-passkey")
        XCTAssertNil(server.bodies[2]?["credential_id"], "the retry must not carry the refused link")
    }

    /// The happy path, and the reason the link exists at all: the passkey this
    /// installation logs in with is what the backend binds the instance to, so
    /// suspending the instance also refuses that passkey at login.
    func testWiaGenerationSendsTheRecordedPasskeyLink() async throws {
        let sessionStore = InMemorySessionStore()
        sessionStore.activeAccountId = "default:user-1"
        sessionStore.credentialId = "pk-1"
        let wallet = makeWallet(sessionStore: sessionStore)
        let server = StubHttpServer()
        server.enqueue(#"{"challenge":"chal-1"}"#)
        server.enqueue(#"{"wallet_instance_attestation":"wia.jwt"}"#)
        let client = BackendApiClient(baseUrl: "https://wallet.example.invalid", httpFn: server.httpFunction)
        client.setAppToken("t")
        wallet.apiClient = client

        let wia = await wallet.ensureWalletInstanceAttestation()

        XCTAssertEqual(wia, "wia.jwt")
        XCTAssertEqual(sessionStore.credentialId, "pk-1", "a link the backend accepted is kept")
        XCTAssertEqual(server.requestCount, 2)
        XCTAssertEqual(server.bodies[1]?["credential_id"] as? String, "pk-1")
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

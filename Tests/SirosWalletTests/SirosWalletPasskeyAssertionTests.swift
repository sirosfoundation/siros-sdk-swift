// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosAuth
import SirosCredentials
@testable import SirosWallet

// `SirosWallet.init` requires a real `JweKeystore`, only available where
// CryptoKit is (Apple platforms / CI macOS runner) - matching this test
// target's existing `#if canImport(CryptoKit)` convention.
#if canImport(CryptoKit)

/// Records every call so the tests can assert on ordering and arguments.
private final class RecordingAuthProvider: AuthProvider, @unchecked Sendable {
    struct NotImplemented: Error {}
    struct PrfUnsupported: Error {}

    let credentialId = Data("cred-id-bytes".utf8)
    /// PRF the authenticate() ceremony itself yields, if any.
    var ceremonyPrf: PrfOutput?
    /// What a separate getPrfOutput() ceremony does: nil = throw PrfUnsupported.
    var separatePrf: PrfOutput?

    private(set) var authenticateCalls = 0
    private(set) var lastAuthenticateOptions: AuthenticateOptions?
    private(set) var getPrfCalls: [(credentialId: Data, salt: Data)] = []

    func register(options: RegisterOptions) async throws -> RegisterResult { throw NotImplemented() }

    func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult {
        authenticateCalls += 1
        lastAuthenticateOptions = options
        return AuthenticateResult(
            credentialId: credentialId,
            authenticatorData: Data("authData".utf8),
            clientDataJSON: Data("clientData".utf8),
            signature: Data("sig".utf8),
            userHandle: nil,
            prfOutput: ceremonyPrf
        )
    }

    func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput {
        getPrfCalls.append((credentialId, salt))
        guard let separatePrf else { throw PrfUnsupported() }
        return separatePrf
    }
}

/// A fake auth server: answers `login/begin` with a well-formed challenge and
/// records every path it is POSTed to.
private final class FakeAuthServer: @unchecked Sendable {
    var postedPaths: [String] = []

    func makeClient() -> AuthServerClient {
        AuthServerClient(baseUrl: "https://as.example.invalid", tenantId: "default") { [self] _, url, _, _ in
            self.postedPaths.append(url.path)
            switch url.path {
            case "/auth/passkey/login/begin":
                let challenge = SirosWallet.b64UrlEncode(Data("challenge-bytes".utf8))
                let json: [String: Any] = [
                    "challengeId": "challenge-1",
                    "getOptions": ["publicKey": ["rpId": "as.example.invalid", "challenge": challenge]],
                ]
                return try JSONSerialization.data(withJSONObject: json)
            default:
                XCTFail("unexpected request to \(url.path)")
                return Data("{}".utf8)
            }
        }
    }
}

/// Regression tests for `SirosWallet.performPasskeyAssertion`, the sequence
/// `login()` and `unlockKeystore()` share and the point at which PRF
/// resolution fails closed. The invariant under test: when the authenticator
/// yields no PRF and `getPrfOutput` throws, the helper throws BEFORE returning
/// the material `loginFinish` needs, so neither caller can complete a
/// server-side login for a session this side can never unlock.
///
/// `login()`/`unlockKeystore()` themselves are not driven end to end here:
/// they read the wallet's private `authServerClient`, built over a real
/// network `httpFn`, and there is no seam to substitute a fake at. The helper
/// takes its client as a parameter precisely so this boundary can be tested.
final class SirosWalletPasskeyAssertionTests: XCTestCase {

    private func makeWallet(authProvider: AuthProvider, sessionStore: InMemorySessionStore) -> SirosWallet {
        let config = WalletConfig(backendUrl: "https://example.invalid")
        let wallet = SirosWallet(
            config: config, authProvider: authProvider, sessionStore: sessionStore,
            accountRegistry: .inMemory()
        )
        XCTAssertNotNil(wallet, "wallet should initialise with default keystore on CryptoKit platforms")
        return wallet!
    }

    func testPrfFailureThrowsAfterAssertionAndBeforeAnyFinish() async {
        let provider = RecordingAuthProvider()
        provider.ceremonyPrf = nil
        provider.separatePrf = nil // getPrfOutput fails closed
        let server = FakeAuthServer()
        let wallet = makeWallet(authProvider: provider, sessionStore: InMemorySessionStore())

        do {
            _ = try await wallet.performPasskeyAssertion(asClient: server.makeClient())
            XCTFail("expected PRF failure to propagate")
        } catch is RecordingAuthProvider.PrfUnsupported {
            // expected
        } catch {
            XCTFail("unexpected error \(error)")
        }

        XCTAssertEqual(provider.authenticateCalls, 1, "the passkey ceremony itself ran")
        XCTAssertEqual(provider.getPrfCalls.count, 1, "a separate PRF ceremony was attempted")
        XCTAssertEqual(
            server.postedPaths, ["/auth/passkey/login/begin"],
            "only login/begin may reach the server; no finish request is ever sent"
        )
    }

    func testCeremonyPrfIsPreferredOverSeparateCeremony() async throws {
        let provider = RecordingAuthProvider()
        provider.ceremonyPrf = PrfOutput(first: Data("from-ceremony".utf8))
        provider.separatePrf = PrfOutput(first: Data("should-not-be-used".utf8))
        let server = FakeAuthServer()
        let wallet = makeWallet(authProvider: provider, sessionStore: InMemorySessionStore())

        let assertion = try await wallet.performPasskeyAssertion(asClient: server.makeClient())

        XCTAssertEqual(assertion.prfOutput.first, Data("from-ceremony".utf8))
        XCTAssertTrue(provider.getPrfCalls.isEmpty, "no redundant second ceremony when the assertion carried PRF")
        XCTAssertEqual(assertion.challengeId, "challenge-1")
        XCTAssertEqual(assertion.credential["id"] as? String, SirosWallet.b64UrlEncode(provider.credentialId))
        XCTAssertEqual(server.postedPaths, ["/auth/passkey/login/begin"])
    }

    func testSeparatePrfCeremonyUsesRealCredentialIdAndStoredSalt() async throws {
        let provider = RecordingAuthProvider()
        provider.ceremonyPrf = nil
        provider.separatePrf = PrfOutput(first: Data("from-separate".utf8))
        let server = FakeAuthServer()
        let sessionStore = InMemorySessionStore()
        sessionStore.activeAccountId = "default:test-user"
        let storedSalt = Data(repeating: 0x5a, count: 32)
        sessionStore.prfSalt = SirosWallet.b64Encode(storedSalt)
        let wallet = makeWallet(authProvider: provider, sessionStore: sessionStore)

        let assertion = try await wallet.performPasskeyAssertion(asClient: server.makeClient())

        XCTAssertEqual(assertion.prfOutput.first, Data("from-separate".utf8))
        XCTAssertEqual(provider.getPrfCalls.count, 1)
        XCTAssertEqual(provider.getPrfCalls.first?.credentialId, provider.credentialId, "never an empty placeholder")
        XCTAssertEqual(provider.getPrfCalls.first?.salt, storedSalt, "the stored PRF salt, so the unwrap key is stable")
        XCTAssertEqual(assertion.prfSalt, storedSalt)
    }

    /// Login after `logout()`: the account-scoped session store is empty, so
    /// the salt has to come from the account registry - offered per credential
    /// in the ceremony itself, and used for the separate probe when the
    /// ceremony carried no PRF. A fresh random salt here would derive a key the
    /// container was never sealed with (review finding on PR #139).
    func testAfterLogoutSaltsComeFromAccountRegistryPerCredential() async throws {
        let provider = RecordingAuthProvider()
        provider.ceremonyPrf = nil
        provider.separatePrf = PrfOutput(first: Data("from-separate".utf8))
        let server = FakeAuthServer()
        let registeredSalt = Data(repeating: 0x11, count: 32)
        let otherSalt = Data(repeating: 0x22, count: 32)
        let otherCredentialId = Data("other-cred".utf8)
        let account = CachedAccount(
            userId: "user-\(UUID().uuidString)",
            tenantId: "test-tenant",
            displayName: "Alice",
            backendUrl: "https://example.invalid",
            passkeys: [
                CachedPasskey(credentialId: SirosWallet.b64UrlEncode(provider.credentialId), prfSalt: SirosWallet.b64Encode(registeredSalt)),
                CachedPasskey(credentialId: SirosWallet.b64UrlEncode(otherCredentialId), prfSalt: SirosWallet.b64Encode(otherSalt)),
            ],
            hkdfSalt: SirosWallet.b64Encode(Data(repeating: 0x33, count: 32)),
            hkdfInfo: SirosWallet.b64Encode(Data("info".utf8))
        )
        // Reproduce logout(): the store was scoped to the account and held its
        // salt; clear() wipes the account's values but keeps activeAccountId.
        let sessionStore = InMemorySessionStore()
        sessionStore.activeAccountId = account.accountId
        sessionStore.prfSalt = SirosWallet.b64Encode(registeredSalt)
        sessionStore.clear()
        XCTAssertNil(sessionStore.prfSalt, "precondition: post-logout store holds no salt")
        XCTAssertEqual(sessionStore.activeAccountId, account.accountId, "precondition: clear() keeps the scope id")
        let wallet = makeWallet(authProvider: provider, sessionStore: sessionStore)
        wallet.accountRegistry.upsertAccount(account)

        let assertion = try await wallet.performPasskeyAssertion(asClient: server.makeClient())

        let offered = provider.lastAuthenticateOptions?.prfSaltsByCredential
        XCTAssertEqual(offered?[provider.credentialId], registeredSalt, "every loginable credential is offered with its own salt")
        XCTAssertEqual(offered?[otherCredentialId], otherSalt)
        XCTAssertEqual(provider.getPrfCalls.first?.salt, registeredSalt, "the probe uses the salt of the credential actually used")
        XCTAssertEqual(assertion.prfSalt, registeredSalt)
        XCTAssertEqual(assertion.cachedAccount?.accountId, account.accountId, "login() can restore hkdfSalt/hkdfInfo from this account")
    }

    /// The session store's salt belongs to the active account. A credential
    /// known to belong to a different cached account (here one whose registry
    /// entry carries no salt, so it is absent from the candidates) must never be
    /// probed with it - that would derive a real PRF under the wrong salt and
    /// fail only later, at unwrap.
    func testSessionSaltIsNotPairedWithAnotherAccountsCredential() async throws {
        let provider = RecordingAuthProvider()
        provider.ceremonyPrf = nil
        provider.separatePrf = PrfOutput(first: Data("from-separate".utf8))
        let server = FakeAuthServer()
        let sessionStore = InMemorySessionStore()
        sessionStore.activeAccountId = "test-tenant:active-user"
        let activeSalt = Data(repeating: 0x5a, count: 32)
        sessionStore.prfSalt = SirosWallet.b64Encode(activeSalt)
        let wallet = makeWallet(authProvider: provider, sessionStore: sessionStore)

        wallet.accountRegistry.upsertAccount(CachedAccount(
            userId: "other-user", tenantId: "test-tenant", displayName: "Bob", backendUrl: "https://example.invalid",
            passkeys: [CachedPasskey(credentialId: SirosWallet.b64UrlEncode(provider.credentialId), prfSalt: "")]
        ))
        wallet.accountRegistry.upsertAccount(CachedAccount(
            userId: "active-user", tenantId: "test-tenant", displayName: "Alice", backendUrl: "https://example.invalid",
            passkeys: [CachedPasskey(credentialId: SirosWallet.b64UrlEncode(Data("alice-cred".utf8)), prfSalt: SirosWallet.b64Encode(activeSalt))]
        ))

        let assertion = try await wallet.performPasskeyAssertion(asClient: server.makeClient())

        XCTAssertNotEqual(provider.getPrfCalls.first?.salt, activeSalt, "another account's credential never gets the active account's salt")
        XCTAssertEqual(assertion.cachedAccount?.userId, "other-user")
    }

    /// `unlockKeystore()` unwraps the resumed account's container, so only that
    /// account's passkeys may be offered - not every cached account's.
    func testCandidatesScopedToAccountForUnlock() async throws {
        let provider = RecordingAuthProvider()
        provider.ceremonyPrf = PrfOutput(first: Data("prf".utf8))
        let server = FakeAuthServer()
        let wallet = makeWallet(authProvider: provider, sessionStore: InMemorySessionStore())
        func account(_ user: String, _ cred: Data, _ salt: UInt8) -> CachedAccount {
            CachedAccount(
                userId: user, tenantId: "test-tenant", displayName: user, backendUrl: "https://example.invalid",
                passkeys: [CachedPasskey(credentialId: SirosWallet.b64UrlEncode(cred), prfSalt: SirosWallet.b64Encode(Data(repeating: salt, count: 32)))]
            )
        }
        let alice = account("alice", provider.credentialId, 0x0a)
        let bobCred = Data("bob-cred".utf8)
        wallet.accountRegistry.upsertAccount(alice)
        wallet.accountRegistry.upsertAccount(account("bob", bobCred, 0x0b))

        _ = try await wallet.performPasskeyAssertion(asClient: server.makeClient(), accountId: alice.accountId)
        let scoped = provider.lastAuthenticateOptions?.prfSaltsByCredential
        XCTAssertEqual(scoped?.count, 1)
        XCTAssertNotNil(scoped?[provider.credentialId])
        XCTAssertNil(scoped?[bobCred], "the other account's passkey is not offered on unlock")
        XCTAssertEqual(provider.lastAuthenticateOptions?.allowCredentials?.map(\.id), [provider.credentialId],
                       "discovery is restricted to the resumed account's passkeys")

        _ = try await wallet.performPasskeyAssertion(asClient: server.makeClient())
        XCTAssertEqual(provider.lastAuthenticateOptions?.prfSaltsByCredential?.count, 2, "login offers every account")
        XCTAssertNil(provider.lastAuthenticateOptions?.allowCredentials, "login lets the user pick any account")

        // The platform ignored the allowlist and answered with Bob's passkey
        // (the provider always returns its own credentialId): reject before
        // the caller can hand loginFinish a valid assertion.
        wallet.accountRegistry.upsertAccount(account("bob", provider.credentialId, 0x0b))
        wallet.accountRegistry.upsertAccount(account("alice", Data("alice-cred".utf8), 0x0a))
        server.postedPaths.removeAll()
        do {
            _ = try await wallet.performPasskeyAssertion(asClient: server.makeClient(), accountId: alice.accountId)
            XCTFail("a credential owned by another account must not complete a scoped unlock")
        } catch let e as SirosError {
            XCTAssertTrue("\(e)".contains("different account"), "\(e)")
        }
        XCTAssertEqual(server.postedPaths, ["/auth/passkey/login/begin"])
    }
}

#endif

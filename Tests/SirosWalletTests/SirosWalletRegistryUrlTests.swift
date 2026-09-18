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

/// Covers `SirosWallet.resolvedRegistryUrl` - the value threaded through to
/// `vctmFetcher`/`mddlSchemaFetcher`'s registry-service fetch strategy at
/// every call site. Uses an explicit stub `KeystoreManager` (like
/// `SirosWalletWscdSelectionTests`) so it runs identically on Linux and
/// Apple platforms, without needing CryptoKit / a real `JweKeystore`.
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

final class SirosWalletRegistryUrlTests: XCTestCase {

    private func makeWallet(config: WalletConfig) -> SirosWallet {
        let wallet = SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: StubKeystoreManager())
        XCTAssertNotNil(wallet)
        return wallet!
    }

    func testResolvedRegistryUrlDerivesFromBackendUrlWhenNil() {
        let config = WalletConfig(backendUrl: "https://wallet.example.com")
        let wallet = makeWallet(config: config)

        XCTAssertEqual(wallet.resolvedRegistryUrl, "https://wallet.example.com/registry")
    }

    func testResolvedRegistryUrlDerivationTrimsTrailingSlashFromBackendUrl() {
        let config = WalletConfig(backendUrl: "https://wallet.example.com/")
        let wallet = makeWallet(config: config)

        XCTAssertEqual(wallet.resolvedRegistryUrl, "https://wallet.example.com/registry")
    }

    func testResolvedRegistryUrlUsesExplicitConfigValueWhenSet() {
        // An integrator pointing the registry lookup at a deployment
        // independent of backendUrl - e.g. a different environment's
        // registry, matching wallet-frontend's standalone `VCT_REGISTRY_URL`.
        var config = WalletConfig(backendUrl: "https://wallet.example.com")
        config.registryUrl = "https://registry.example.com/v1"
        let wallet = makeWallet(config: config)

        XCTAssertEqual(wallet.resolvedRegistryUrl, "https://registry.example.com/v1")
    }

    // MARK: - Registry-service auth headers (security-sensitive)

    /// Covers `SirosWallet.makeTypeMetadataHttpGet` - the HTTP GET closure
    /// shared by `vctmFetcher`/`mddlSchemaFetcher`. It must attach
    /// `X-Tenant-ID`/`Authorization` headers ONLY when the target URL is
    /// go-wallet-backend's own resolved registry service, and NEVER for the
    /// other two fetch strategies' URLs (arbitrary third-party issuer
    /// domains) - a leak there would hand the wallet's own bearer
    /// token/tenant ID to an external party. Exercises the closure directly
    /// (via `@testable import`), injecting a stub `performRequest` so no
    /// real network call is made; a throwing `AuthServerClient` httpFn
    /// forces `ensureBackendToken()` to fail, exercising the legacy
    /// `sessionStore.appToken` fallback path, same as `BackendApiClient`'s.
    private struct NoAsSession: Error {}

    private func makeAuthTokens(tenantId: String = "default") -> AuthTokens {
        let asClient = AuthServerClient(baseUrl: "https://as.example.com", tenantId: tenantId) { _, _, _, _ in
            throw NoAsSession()
        }
        return AuthTokens(authServerClient: asClient, tenantId: tenantId)
    }

    func testTypeMetadataHttpGetAttachesAuthHeadersForRegistryUrl() async {
        let sessionStore = InMemorySessionStore()
        // SessionStoreProtocol scopes all reads/writes to `activeAccountId`
        // (nil means every read/write is a no-op) - must be set for
        // `appToken` to actually persist, matching every other
        // `InMemorySessionStore` use in this SDK.
        sessionStore.activeAccountId = "tenant-42:test-user"
        sessionStore.appToken = "legacy-app-token"
        var capturedRequest: URLRequest?

        let httpGet = SirosWallet.makeTypeMetadataHttpGet(
            registryUrl: "https://wallet.example.com/registry",
            tenantId: "tenant-42",
            authTokens: makeAuthTokens(),
            sessionStore: sessionStore,
            performRequest: { request in
                capturedRequest = request
                return Data("{}".utf8)
            }
        )

        _ = await httpGet("https://wallet.example.com/registry/type-metadata?vct=urn:eudi:diploma:1")

        // `value(forHTTPHeaderField:)` (unlike `allHTTPHeaderFields`) looks
        // up case-insensitively, matching HTTP semantics - relevant on
        // Linux, where swift-corelibs-foundation canonicalizes the header
        // key casing it stores internally.
        XCTAssertEqual(capturedRequest?.value(forHTTPHeaderField: "X-Tenant-ID"), "tenant-42")
        XCTAssertEqual(capturedRequest?.value(forHTTPHeaderField: "Authorization"), "Bearer legacy-app-token")
    }

    func testTypeMetadataHttpGetOmitsAuthHeadersForIssuerDirectUrl() async {
        let sessionStore = InMemorySessionStore()
        // SessionStoreProtocol scopes all reads/writes to `activeAccountId`
        // (nil means every read/write is a no-op) - must be set for
        // `appToken` to actually persist, matching every other
        // `InMemorySessionStore` use in this SDK.
        sessionStore.activeAccountId = "tenant-42:test-user"
        sessionStore.appToken = "legacy-app-token"
        var capturedRequest: URLRequest?

        let httpGet = SirosWallet.makeTypeMetadataHttpGet(
            registryUrl: "https://wallet.example.com/registry",
            tenantId: "tenant-42",
            authTokens: makeAuthTokens(),
            sessionStore: sessionStore,
            performRequest: { request in
                capturedRequest = request
                return Data("{}".utf8)
            }
        )

        // Issuer-direct strategy's URL - an arbitrary third-party domain,
        // NOT the registry URL above.
        _ = await httpGet("https://issuer.example.com/type-metadata/diploma")

        XCTAssertNil(capturedRequest?.value(forHTTPHeaderField: "X-Tenant-ID"), "must never leak the tenant ID to a third-party issuer")
        XCTAssertNil(capturedRequest?.value(forHTTPHeaderField: "Authorization"), "must never leak the wallet's bearer token to a third-party issuer")
    }

    func testTypeMetadataHttpGetOmitsAuthHeadersForWellKnownUrl() async {
        let sessionStore = InMemorySessionStore()
        // SessionStoreProtocol scopes all reads/writes to `activeAccountId`
        // (nil means every read/write is a no-op) - must be set for
        // `appToken` to actually persist, matching every other
        // `InMemorySessionStore` use in this SDK.
        sessionStore.activeAccountId = "tenant-42:test-user"
        sessionStore.appToken = "legacy-app-token"
        var capturedRequest: URLRequest?

        let httpGet = SirosWallet.makeTypeMetadataHttpGet(
            registryUrl: "https://wallet.example.com/registry",
            tenantId: "tenant-42",
            authTokens: makeAuthTokens(),
            sessionStore: sessionStore,
            performRequest: { request in
                capturedRequest = request
                return Data("{}".utf8)
            }
        )

        // Well-known strategy's URL - also a third-party issuer domain.
        _ = await httpGet("https://example.com/.well-known/vct/types/pid")

        XCTAssertNil(capturedRequest?.value(forHTTPHeaderField: "X-Tenant-ID"))
        XCTAssertNil(capturedRequest?.value(forHTTPHeaderField: "Authorization"))
    }
}

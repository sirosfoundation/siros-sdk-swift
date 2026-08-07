// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
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
}

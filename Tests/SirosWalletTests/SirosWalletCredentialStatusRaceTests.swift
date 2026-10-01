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

/// `credentialStatus(of:)` writes to `credentialStatusCache` only after
/// `await`ing the (potentially slow, real-network) evaluator - a session
/// boundary or this credential's own deletion can complete WHILE that
/// `await` is still suspended. Uses a stub `KeystoreManager` (like
/// `SirosWalletLifecycleTests`) so it runs identically on Linux and Apple
/// platforms, without CryptoKit.
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
    func generateKey(algorithm: String) async throws -> String { "key-1" }
    func sign(keyId: String, payload: Data, algorithm: String) async throws -> Data { Data() }
    func generateProof(audience: String, nonce: String, freshKey: Bool) async throws -> String { "" }
    func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String { "" }
    func signVpToken(credential: String, disclosedClaims: [String]?, nonce: String, audience: String, kid: String?) async throws -> String { "" }
    func exportEncryptedContainer() async throws -> Data { Data() }
    func listKeys() -> [KeyInfo] { [] }
    func exportWscdCredentials() async -> [String: String] { [:] }
    func setWscdCredentials(pluginId: String, state: String) async {}
    func extensionEntries(namespace: String) async -> [String: String] { [:] }
    func setExtensionEntry(namespace: String, key: String, value: String) async throws {}
    func removeExtensionEntry(namespace: String, key: String) async throws {}
    func exportCredentialRefreshTokens() async -> [Int64: CredentialRefreshTokenEntry] { [:] }
    func setCredentialRefreshToken(batchId: Int64, entry: CredentialRefreshTokenEntry) async {}
    func removeCredentialRefreshToken(batchId: Int64) async {}
    func saveCredential(id: Int64, json: String) async throws {}
    func getCredential(id: Int64) async throws -> String? { nil }
    func getAllCredentials() async throws -> [Int64: String] { [:] }
    func deleteCredential(id: Int64) async throws {}
    func clearCredentials() async throws {}
    func savePresentationRecord(id: Int64, json: String) async throws {}
    func getAllPresentationRecords() async throws -> [Int64: String] { [:] }
    func clearPresentationRecords() async throws {}
    func generateKeypairs(count: Int) async throws -> [KeypairInfo] { [] }
    func generateKeyAttestation(nonce: String, count: Int) async throws -> String { "" }
}

final class SirosWalletCredentialStatusRaceTests: XCTestCase {

    private func makeWallet(credentialStore: CredentialStore) -> SirosWallet {
        var config = WalletConfig(backendUrl: "https://wallet.example.invalid")
        config.credentialStore = credentialStore
        let wallet = SirosWallet(
            config: config,
            authProvider: StubAuthProvider(),
            keystore: StubKeystoreManager()
        )
        XCTAssertNotNil(wallet)
        return wallet!
    }

    /// A credential whose `validUntil` is long past - `evaluate()` short-
    /// circuits on the validity window before ever consulting the network
    /// (see `CredentialStatusTests.testTheValidityWindowShortCircuitsTheStatusList`),
    /// so this resolves to `.expired` (never `.valid`) quickly and
    /// deterministically - exactly what makes the cache-write assertion
    /// below meaningful: `.valid` is `cachedCredentialStatus`'s own default
    /// for an id with NO entry, so only a status that is provably NOT
    /// `.valid` can distinguish "no entry was written" from "one was".
    private func expiredCredential(id: Int64) -> StoredCredential {
        func b64(_ object: [String: Any]) -> String {
            Data(try! JSONSerialization.data(withJSONObject: object)).base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        let payload: [String: Any] = ["iss": "https://issuer.example", "validUntil": "2020-01-01T00:00:00Z"]
        let raw = "\(b64(["alg": "ES256", "typ": "dc+sd-jwt"])).\(b64(payload)).sig~"
        return StoredCredential(id: id, format: "dc+sd-jwt", raw: raw, batchId: id, instanceId: 0)
    }

    /// Regression (review finding): `deleteCredential(_:)` removes a
    /// credential without bumping the session generation at all (that's a
    /// session-boundary concept, not a per-credential one) - evaluating a
    /// credential that has ALREADY been deleted by the time the (here,
    /// instant) evaluation completes must not resurrect a cache entry for
    /// the freed id.
    func testCredentialStatusDoesNotCacheAResultForACredentialDeletedDuringEvaluation() async {
        let store = InMemoryCredentialStore()
        let credential = expiredCredential(id: 42)
        await store.save(credential)
        let wallet = makeWallet(credentialStore: store)

        // Deleted BEFORE credentialStatus(of:) is even called - simulating
        // the moment a concurrent deletion would have completed while a
        // slower, real evaluation was still in flight. The caller's own
        // `credential` value is still the one from before the deletion,
        // exactly as it would be for an evaluation already under way.
        await wallet.deleteCredential(42)

        let status = await wallet.credentialStatus(of: credential)
        XCTAssertEqual(status, .expired, "the evaluation itself still completes and returns a real result")
        XCTAssertEqual(
            wallet.cachedCredentialStatus(of: 42), .valid,
            "must stay at cachedCredentialStatus's default for an unknown id - .expired must NOT have been cached"
        )
    }
}

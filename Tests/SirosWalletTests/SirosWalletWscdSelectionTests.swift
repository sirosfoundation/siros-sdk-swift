// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosAuth
import SirosCredentials
import SirosKeystore
@testable import SirosWallet

/// Integration-level wiring tests for `SirosWallet.requestBackendKeyAttestation`'s
/// use of `WscdSelectionPolicy` (see `WscdSelectionPolicyTests` for exhaustive
/// coverage of the policy's own branch logic in isolation).
///
/// Unlike `SirosWalletKeyAttestationTests`, these don't need CryptoKit / a
/// real `JweKeystore`: `SirosWallet.init?` only falls back to `JweKeystore()`
/// when the `keystore` parameter is nil, so passing an explicit stub
/// keystore (as every test here does) works identically on Linux and Apple
/// platforms.
private final class StubAuthProvider: AuthProvider, @unchecked Sendable {
    struct NotImplemented: Error {}
    func register(options: RegisterOptions) async throws -> RegisterResult { throw NotImplemented() }
    func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw NotImplemented() }
    func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw NotImplemented() }
}

/// Minimal `KeystoreManager` stub - `label` is baked into every generated
/// key ID so a test can tell which stub instance actually produced a given
/// batch of keys without needing to compare object identity.
private final class StubKeystoreManager: KeystoreManager, @unchecked Sendable {
    let label: String
    private(set) var generateKeypairsCallCount = 0
    private(set) var generateKeyAttestationCallCount = 0

    init(label: String) { self.label = label }

    var isUnlocked: Bool { true }
    func unlock(prfOutput: Data, encryptedContainer: Data, hkdfSalt: Data, hkdfInfo: Data) async throws {}
    func lock() {}
    func generateKey(algorithm: String) async throws -> String { "\(label)-key" }
    func sign(keyId: String, payload: Data, algorithm: String) async throws -> Data { Data() }
    func generateProof(audience: String, nonce: String, freshKey: Bool) async throws -> String { "\(label)-proof" }
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

    func generateKeypairs(count: Int) async throws -> [KeypairInfo] {
        generateKeypairsCallCount += 1
        return (0..<count).map { KeypairInfo(keyId: "\(label)-key-\($0)", publicKeyJWK: ["kty": "EC"]) }
    }

    // Overrides `KeystoreManager`'s default (which throws "not supported") -
    // tags its output with `label` so a regression test can tell which
    // instance actually produced the self-signed fallback attestation
    // without needing object identity.
    func generateKeyAttestation(nonce: String, count: Int) async throws -> String {
        generateKeyAttestationCallCount += 1
        return "\(label)-attestation"
    }
}

final class SirosWalletWscdSelectionTests: XCTestCase {

    private func fakeApiClient(keyAttestationJwt: String = "fake-jwt") -> BackendApiClient {
        BackendApiClient(baseUrl: "https://example.invalid", httpFn: { _, _, _, _ in
            try! JSONSerialization.data(withJSONObject: ["key_attestation": keyAttestationJwt])
        })
    }

    private func offer(issuer: String, configId: String) -> CredentialOffer {
        CredentialOffer(
            credentialConfigurationId: configId,
            credentialIssuerIdentifier: issuer,
            credentialName: "Test Credential",
            issuerName: "Test Issuer"
        )
    }

    func testBackwardCompatibleWhenAvailableKeystoresNotSet() async throws {
        // No `availableKeystores` at all - even with a declared requirement
        // on the active VCTM, selection logic must not engage, and
        // generation must use the wallet's single default keystore exactly
        // as it did before this feature existed.
        let defaultKeystore = StubKeystoreManager(label: "default")
        let config = WalletConfig(backendUrl: "https://example.invalid")
        let wallet = SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: defaultKeystore)
        XCTAssertNotNil(wallet)
        let w = wallet!
        w.apiClient = fakeApiClient()
        w.activeVctm = Vctm(vct: "urn:example:pid", requiredKeyStorage: "iso_18045_high")

        let (result, effectiveKeystore) = try await w.requestBackendKeyAttestation(audience: "https://issuer.example.com", nonce: "n", count: 1)

        XCTAssertEqual(result?.keyIds.first, "default-key-0")
        XCTAssertEqual(defaultKeystore.generateKeypairsCallCount, 1)
        XCTAssert(effectiveKeystore === defaultKeystore, "no availableKeystores configured - the resolved keystore must be the default")
    }

    func testUsesDefaultMappingSelectedPluginInsteadOfDefaultKeystore() async throws {
        let defaultKeystore = StubKeystoreManager(label: "softkey")
        let fidoKeystore = StubKeystoreManager(label: "fido2")

        var config = WalletConfig(backendUrl: "https://example.invalid")
        config.availableKeystores = ["fido2": fidoKeystore]
        config.defaultWscdMapping = ["https://issuer.example.com|urn:example:pid": "fido2"]

        let wallet = SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: defaultKeystore)
        let w = wallet!
        w.apiClient = fakeApiClient()
        w.activeOffer = offer(issuer: "https://issuer.example.com", configId: "urn:example:pid")
        w.activeVctm = Vctm(vct: "urn:example:pid", requiredKeyStorage: "iso_18045_high")

        let (result, effectiveKeystore) = try await w.requestBackendKeyAttestation(audience: "https://issuer.example.com", nonce: "n", count: 1)

        XCTAssertEqual(result?.keyIds.first, "fido2-key-0", "must generate via the selected fido2 keystore, not the default")
        XCTAssertEqual(fidoKeystore.generateKeypairsCallCount, 1)
        XCTAssertEqual(defaultKeystore.generateKeypairsCallCount, 0, "must NOT touch the default keystore once a plugin is selected")
        XCTAssert(effectiveKeystore === fidoKeystore, "the resolved keystore returned to the caller must be the one actually used")
    }

    func testUsesMddlSchemaRequirementForMdocCredentials() async throws {
        // Same wiring, but the active type metadata is the mdoc analogue
        // (`activeMddlSchema`), not `activeVctm` - proves the mdoc path is
        // also threaded through, not just SD-JWT.
        let defaultKeystore = StubKeystoreManager(label: "softkey")
        let fidoKeystore = StubKeystoreManager(label: "fido2")

        var config = WalletConfig(backendUrl: "https://example.invalid")
        config.availableKeystores = ["fido2": fidoKeystore]

        let wallet = SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: defaultKeystore)
        let w = wallet!
        w.apiClient = fakeApiClient()
        w.activeOffer = offer(issuer: "https://issuer.example.com", configId: "org.iso.18013.5.1.mDL")
        w.activeMddlSchema = MddlSchema(
            format: "mso_mdoc",
            doctype: "org.iso.18013.5.1.mDL",
            requiredKeyStorage: "iso_18045_high"
        )

        let (result, _) = try await w.requestBackendKeyAttestation(audience: "https://issuer.example.com", nonce: "n", count: 1)

        // Only one eligible plugin ("fido2") is registered - auto-picked, no prompt needed.
        XCTAssertEqual(result?.keyIds.first, "fido2-key-0")
    }

    func testThrowsNoEligiblePluginWhenNoneMeetTheRequirement() async throws {
        let defaultKeystore = StubKeystoreManager(label: "softkey")
        var config = WalletConfig(backendUrl: "https://example.invalid")
        // Registered under a plugin ID not in `WscdPluginCapabilities`'s
        // static table - nothing meets any requirement.
        config.availableKeystores = ["some-unknown-plugin": StubKeystoreManager(label: "unknown")]

        let wallet = SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: defaultKeystore)
        let w = wallet!
        w.apiClient = fakeApiClient()
        w.activeVctm = Vctm(vct: "urn:example:pid", requiredKeyStorage: "iso_18045_high")

        do {
            _ = try await w.requestBackendKeyAttestation(audience: "https://issuer.example.com", nonce: "n", count: 1)
            XCTFail("expected WscdSelectionError.noEligiblePlugin to propagate")
        } catch WscdSelectionError.noEligiblePlugin {
            // Expected - and critically, `defaultKeystore.generateKeypairs`
            // must never have been reached (see assertion below): this must
            // never silently fall back to an insufficient plugin.
        }
        XCTAssertEqual(defaultKeystore.generateKeypairsCallCount, 0)
    }

    func testNoRequirementDeclaredUsesDefaultKeystoreEvenWithAvailableKeystoresSet() async throws {
        let defaultKeystore = StubKeystoreManager(label: "softkey")
        let fidoKeystore = StubKeystoreManager(label: "fido2")
        var config = WalletConfig(backendUrl: "https://example.invalid")
        config.availableKeystores = ["fido2": fidoKeystore]
        // No activeVctm/activeMddlSchema at all -> requiredTier resolves to nil -> no-op.

        let wallet = SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: defaultKeystore)
        let w = wallet!
        w.apiClient = fakeApiClient()

        let (result, _) = try await w.requestBackendKeyAttestation(audience: "https://issuer.example.com", nonce: "n", count: 1)

        XCTAssertEqual(result?.keyIds.first, "softkey-key-0")
        XCTAssertEqual(fidoKeystore.generateKeypairsCallCount, 0)
    }

    func testThrowsNoEligiblePluginWhenAvailableKeystoresIsExplicitlyEmpty() async throws {
        // `availableKeystores` set to a non-nil but EMPTY dictionary - the
        // host app opted into multi-plugin selection but has zero plugins
        // registered right now. This must throw `noEligiblePlugin` (like any
        // other zero-eligible case), not silently skip selection entirely
        // and fall back to the default keystore.
        let defaultKeystore = StubKeystoreManager(label: "softkey")
        var config = WalletConfig(backendUrl: "https://example.invalid")
        config.availableKeystores = [:]

        let wallet = SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: defaultKeystore)
        let w = wallet!
        w.apiClient = fakeApiClient()
        w.activeVctm = Vctm(vct: "urn:example:pid", requiredKeyStorage: "iso_18045_high")

        do {
            _ = try await w.requestBackendKeyAttestation(audience: "https://issuer.example.com", nonce: "n", count: 1)
            XCTFail("expected WscdSelectionError.noEligiblePlugin to propagate")
        } catch WscdSelectionError.noEligiblePlugin {
            // Expected.
        }
        XCTAssertEqual(defaultKeystore.generateKeypairsCallCount, 0, "must never silently fall back to the default keystore")
    }

    // Regression test for the fallback-keystore-bypass bug: when
    // `requestBackendKeyAttestation` resolves a non-default plugin (via
    // `WscdSelectionPolicy`) but the backend attestation call itself then
    // fails (forcing `generateProofs`'s self-signed fallback), the fallback
    // must run on that SAME resolved plugin, not silently on `self.keystore`
    // - otherwise a resolved higher-tier plugin is bypassed and a
    // lower-tier self-signed attestation is generated instead.
    func testFallbackAfterFailedBackendAttestationUsesResolvedKeystoreNotDefault() async throws {
        let defaultKeystore = StubKeystoreManager(label: "softkey")
        let fidoKeystore = StubKeystoreManager(label: "fido2")

        var config = WalletConfig(backendUrl: "https://example.invalid")
        config.availableKeystores = ["fido2": fidoKeystore]

        let wallet = SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: defaultKeystore)
        let w = wallet!
        // A backend session IS present, but its response is malformed (no
        // "key_attestation" field), so `requestKeyAttestation` throws and
        // `requestBackendKeyAttestation` returns a nil result - exercising
        // the self-signed fallback path in `generateProofs`.
        w.apiClient = BackendApiClient(baseUrl: "https://example.invalid", httpFn: { _, _, _, _ in
            try! JSONSerialization.data(withJSONObject: [String: Any]())
        })
        w.activeOffer = offer(issuer: "https://issuer.example.com", configId: "org.iso.18013.5.1.mDL")
        w.activeMddlSchema = MddlSchema(
            format: "mso_mdoc",
            doctype: "org.iso.18013.5.1.mDL",
            requiredKeyStorage: "iso_18045_high"
        )

        let proofs = try await w.generateProofs(
            audience: "https://issuer.example.com",
            nonce: "n",
            count: 1,
            proofTypesSupported: nil,
            proofTypeHint: "attestation"
        )

        XCTAssertEqual(proofs.count, 1)
        XCTAssertEqual(
            proofs[0].attestation, "fido2-attestation",
            "self-signed fallback must run on the resolved fido2 keystore, not the default"
        )
        XCTAssertEqual(fidoKeystore.generateKeypairsCallCount, 1)
        XCTAssertEqual(fidoKeystore.generateKeyAttestationCallCount, 1)
        XCTAssertEqual(defaultKeystore.generateKeypairsCallCount, 0, "must never touch the default keystore once a plugin is resolved")
        XCTAssertEqual(defaultKeystore.generateKeyAttestationCallCount, 0, "the self-signed fallback must not silently use self.keystore")
    }
}

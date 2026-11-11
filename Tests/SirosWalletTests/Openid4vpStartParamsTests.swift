// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosTransport
import SirosAuth
import SirosKeystore
import SirosCredentials
@testable import SirosWallet

/// `openid4vpStartParams` — the engine's OID4VP start params built from the
/// link's own query members (siros-sdk-kotlin#394's twin, found by the
/// on-device GDC audit: the whole deep link wrapped as `request_uri` made the
/// engine try to FETCH its own `openid4vp://` URI). All four link shapes are
/// pinned: host-less spec form, host'd form, by-value request, bare reference.
final class Openid4vpStartParamsTests: XCTestCase {
    private struct NotImplemented: Error {}

    private final class NoopAuthProvider: AuthProvider {
        func register(options: RegisterOptions) async throws -> RegisterResult { throw NotImplemented() }
        func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw NotImplemented() }
        func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw NotImplemented() }
    }

    private final class NoopKeystoreManager: KeystoreManager, @unchecked Sendable {
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

    private func wallet() -> SirosWallet {
        let w = SirosWallet(
            config: WalletConfig(backendUrl: "https://wallet.example.invalid", credentialStore: InMemoryCredentialStore()),
            authProvider: NoopAuthProvider(), keystore: NoopKeystoreManager(), accountRegistry: .inMemory()
        )
        XCTAssertNotNil(w)
        return w!
    }

    /// The string at `member` of the params object, or nil.
    private func string(_ params: AnyCodable, _ member: String) -> String? {
        guard case .object_(let dict) = params, case .string(let value)? = dict[member] else { return nil }
        return value
    }

    func testHostLessSpecFormCarriesTheMembersPercentDecoded() {
        let w = wallet()
        let params = w.openid4vpStartParams(
            "openid4vp://?client_id=x509_hash%3Aabc&request_uri=https%3A%2F%2Fverifier.example%2Fr"
        )
        XCTAssertEqual(string(params, "client_id"), "x509_hash:abc")
        XCTAssertEqual(string(params, "request_uri"), "https://verifier.example/r")
    }

    func testHostedFormsQueryIsEverythingAfterTheFirstQuestionMark() {
        let w = wallet()
        // A verifier's host before the query: the host is NOT a member (the
        // pre-fix whole-link form would have handed the engine
        // `openid4vp://cb?request_uri=…` AS the request_uri to fetch).
        let params = w.openid4vpStartParams("openid4vp://cb?request_uri=https%3A%2F%2Fv%2Fr")
        XCTAssertEqual(string(params, "request_uri"), "https://v/r")
        XCTAssertNil(string(params, "client_id"))
    }

    func testByValueRequestRidesAsItsOwnMember() {
        let w = wallet()
        let params = w.openid4vpStartParams("openid4vp://?request=eyJhbGciOiJFUzI1NiJ9.e30.AA")
        XCTAssertEqual(string(params, "request"), "eyJhbGciOiJFUzI1NiJ9.e30.AA")
    }

    func testABareReferenceIsTheRequestUriItself() {
        let w = wallet()
        let params = w.openid4vpStartParams("https://verifier.example/request-object")
        XCTAssertEqual(string(params, "request_uri"), "https://verifier.example/request-object")
    }
}
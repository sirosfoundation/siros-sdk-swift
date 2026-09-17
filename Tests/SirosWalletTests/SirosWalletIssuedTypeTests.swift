// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosAuth
import SirosCredentials
@testable import SirosWallet

import SirosKeystore

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

private final class StubAuthProvider: AuthProvider, @unchecked Sendable {
    struct NotImplemented: Error {}
    func register(options: RegisterOptions) async throws -> RegisterResult { throw NotImplemented() }
    func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw NotImplemented() }
    func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw NotImplemented() }
}

/// The wallet's two checks on a credential as it arrives.
///
/// Everything earlier in the issuance path — the issuer's entitlement under ARF
/// section 6.6.2.3, which type metadata to apply, which WSCD to use — is decided
/// from what the issuer *advertised*. These are the only two things that look at
/// what actually turned up. Mirrors the Kotlin SDK's IssuedTypeVerificationTest.
final class SirosWalletIssuedTypeTests: XCTestCase {

    /// A stub `KeystoreManager` rather than the default `JweKeystore`, so these
    /// tests run on Linux as well as on Apple platforms: nothing here signs or
    /// unwraps anything, and the Kotlin original they mirror runs on the JVM.
    private func makeWallet() -> SirosWallet {
        let config = WalletConfig(backendUrl: "https://example.invalid")
        let wallet = SirosWallet(
            config: config,
            authProvider: StubAuthProvider(),
            keystore: StubKeystoreManager(),
            accountRegistry: .inMemory()
        )
        XCTAssertNotNil(wallet)
        return wallet!
    }

    private func sdJwt(vct: String?, integrity: String? = nil) -> String {
        var claims: [String] = []
        if let vct { claims.append("\"vct\":\"\(vct)\"") }
        if let integrity { claims.append("\"vct#integrity\":\"\(integrity)\"") }
        let body = "{" + claims.joined(separator: ",") + "}"
        func b64(_ s: String) -> String {
            Data(s.utf8).base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        return "\(b64("{\"alg\":\"ES256\"}")).\(b64(body)).sig"
    }

    private func payload(_ raw: String) -> [String: Any] {
        CredentialUtils.parseJwtPayload(raw) ?? [:]
    }

    // MARK: - issued type

    func testAcceptsACredentialOfTheAuthorisedType() {
        let w = makeWallet()
        w.activeVctm = Vctm(vct: "urn:eudi:pid:1")
        XCTAssertNil(w.verifyIssuedType(format: "dc+sd-jwt", raw: sdJwt(vct: "urn:eudi:pid:1")))
    }

    func testRefusesACredentialOfADifferentType() {
        // The whole point: an issuer entitled to one attestation type must not
        // be able to deliver another and have every earlier decision stand.
        let w = makeWallet()
        w.activeVctm = Vctm(vct: "urn:eudi:pid:1")
        let reason = w.verifyIssuedType(format: "dc+sd-jwt", raw: sdJwt(vct: "urn:example:other"))
        XCTAssertNotNil(reason)
        XCTAssertTrue(reason!.contains("urn:example:other"))
        XCTAssertTrue(reason!.contains("urn:eudi:pid:1"))
    }

    func testAcceptsWhenNoTypeWasAuthorised() {
        // Nothing resolved means nothing to compare. A check that could not run
        // must not become a refusal.
        let w = makeWallet()
        w.activeVctm = nil
        w.activeMddlSchema = nil
        XCTAssertNil(w.verifyIssuedType(format: "dc+sd-jwt", raw: sdJwt(vct: "urn:eudi:pid:1")))
    }

    func testAcceptsWhenTheCredentialDeclaresNoType() {
        let w = makeWallet()
        w.activeVctm = Vctm(vct: "urn:eudi:pid:1")
        XCTAssertNil(w.verifyIssuedType(format: "dc+sd-jwt", raw: sdJwt(vct: nil)))
    }

    func testMdocIsComparedAgainstTheDoctypeNotTheVct() {
        // The two namespaces are separate; comparing an mdoc against a vct
        // would refuse every mdoc ever issued.
        let w = makeWallet()
        w.activeVctm = Vctm(vct: "urn:eudi:pid:1")
        w.activeMddlSchema = nil
        XCTAssertNil(w.verifyIssuedType(format: "mso_mdoc", raw: "not-a-jwt"))
    }

    func testUsesTheOffersTypeWhenMetadataResolutionFailed() {
        // The situation the check exists for and would otherwise miss: metadata
        // never resolved, so there is no Vctm - but the offer still declared a
        // vct, and that is what the entitlement check was run against.
        let w = makeWallet()
        w.activeVctm = nil
        w.activeOffer = CredentialOffer(
            credentialConfigurationId: "pid",
            credentialIssuerIdentifier: "https://issuer.example.com",
            credentialName: "PID",
            issuerName: "Issuer",
            vct: "urn:eudi:pid:1"
        )
        XCTAssertNotNil(w.verifyIssuedType(format: "dc+sd-jwt", raw: sdJwt(vct: "urn:example:other")))
        XCTAssertNil(w.verifyIssuedType(format: "dc+sd-jwt", raw: sdJwt(vct: "urn:eudi:pid:1")))
    }

    func testAPreParsedTypeIsUsedAsGiven() {
        // Both storage paths have already parsed the credential; the comparison
        // must use that parse rather than a second one.
        let w = makeWallet()
        w.activeVctm = Vctm(vct: "urn:eudi:pid:1")
        XCTAssertNotNil(w.verifyIssuedType(
            format: "dc+sd-jwt",
            raw: sdJwt(vct: "urn:eudi:pid:1"),
            declaredType: "urn:example:other"
        ))
    }

    // MARK: - vct#integrity

    private func document(_ vct: String) -> VctmDocument {
        VctmDocument(raw: "{\"vct\":\"\(vct)\"}", vctm: Vctm(vct: vct))
    }

    /// A document whose bytes - and therefore whose digest - differ by `name`,
    /// so a test can hold one version and pin another.
    private func document(_ vct: String, name: String) -> VctmDocument {
        let raw = "{\"vct\":\"\(vct)\",\"name\":\"\(name)\"}"
        return VctmDocument(raw: raw, vctm: Vctm(vct: vct))
    }

    private func offer(vct: String) -> CredentialOffer {
        CredentialOffer(
            credentialConfigurationId: "pid_1",
            credentialIssuerIdentifier: "https://issuer.example.invalid",
            credentialName: "PID",
            issuerName: "Issuer",
            vct: vct
        )
    }

    private func digest(of raw: String) -> String {
        "sha256-" + Data(SHA256.hash(data: Data(raw.utf8))).base64EncodedString()
    }

    func testAcceptsTypeMetadataMatchingTheIssuersDigest() async {
        let w = makeWallet()
        let doc = document("urn:eudi:pid:1")
        w.activeVctmDocument = doc
        let raw = sdJwt(vct: "urn:eudi:pid:1", integrity: digest(of: doc.raw))
        let reason = await w.verifyVctIntegrity(format: "dc+sd-jwt", payload: payload(raw))
        XCTAssertNil(reason)
    }

    func testRefusesTypeMetadataTheIssuerDidNotPin() async {
        // A registry serving altered metadata for a type the issuer is
        // legitimately entitled to issue.
        let w = makeWallet()
        w.activeVctmDocument = document("urn:eudi:pid:1")
        let raw = sdJwt(vct: "urn:eudi:pid:1", integrity: digest(of: #"{"vct":"urn:eudi:pid:1","claims":[]}"#))
        let reason = await w.verifyVctIntegrity(format: "dc+sd-jwt", payload: payload(raw))
        XCTAssertNotNil(reason)
    }

    func testAcceptsACredentialThatPinsNothing() async {
        let w = makeWallet()
        w.activeVctmDocument = document("urn:eudi:pid:1")
        let reason = await w.verifyVctIntegrity(format: "dc+sd-jwt", payload: payload(sdJwt(vct: "urn:eudi:pid:1")))
        XCTAssertNil(reason)
    }

    func testAcceptsWhenNoMetadataWasResolvedToCheck() async {
        // Nothing was applied, so nothing was tampered with.
        let w = makeWallet()
        w.activeVctmDocument = nil
        let raw = sdJwt(vct: "urn:eudi:pid:1", integrity: digest(of: #"{"vct":"urn:eudi:pid:1"}"#))
        let reason = await w.verifyVctIntegrity(format: "dc+sd-jwt", payload: payload(raw))
        XCTAssertNil(reason)
    }

    // MARK: - re-resolution against the pin

    /// The heal: the wallet holds a document cached before the issuer changed
    /// what it publishes, so the pin disagrees with it. That is ordinary, not
    /// hostile - resolve again directed by the pin, and accept the credential
    /// when the issuer's own document is found. Ports siros-sdk-kotlin#191.
    func testAStaleResolvedDocumentIsReResolvedAndTheCredentialAccepted() async {
        let w = makeWallet()
        let issuers = document("urn:eudi:pid:1", name: "PID")
        w.activeVctmDocument = document("urn:eudi:pid:1", name: "PID (old)")
        w.activeOffer = offer(vct: "urn:eudi:pid:1")
        w.vctmFetcher = VctmFetcher(httpGet: { @Sendable _ in issuers.raw })

        let raw = sdJwt(vct: "urn:eudi:pid:1", integrity: digest(of: issuers.raw))
        let reason = await w.verifyVctIntegrity(format: "dc+sd-jwt", payload: payload(raw))

        XCTAssertNil(reason, "the issuer's own document was found, so the credential stands")
        XCTAssertEqual(
            w.activeVctmDocument?.raw, issuers.raw,
            "and the wallet keeps the document the issuer pinned, not the stale one"
        )
    }

    /// The security property is unchanged: a document that does not hash to the
    /// pin is never accepted, wherever it came from. A wallet that cannot find
    /// the pinned document anywhere still refuses.
    func testACredentialWhosePinnedDocumentNoSourceHasIsStillRefused() async {
        let w = makeWallet()
        w.activeVctmDocument = document("urn:eudi:pid:1", name: "PID (old)")
        w.activeOffer = offer(vct: "urn:eudi:pid:1")
        // Every source serves something, but none of it is what was pinned.
        w.vctmFetcher = VctmFetcher(httpGet: { @Sendable _ in #"{"vct":"urn:eudi:pid:1","name":"also wrong"}"# })

        let raw = sdJwt(vct: "urn:eudi:pid:1", integrity: digest(of: #"{"vct":"urn:eudi:pid:1","name":"PID"}"#))
        let reason = await w.verifyVctIntegrity(format: "dc+sd-jwt", payload: payload(raw))

        XCTAssertNotNil(reason)
    }

    /// Re-resolution needs an offer to resolve against; without one there is
    /// nowhere to look, and the refusal stands as before.
    func testWithNoOfferToResolveAgainstTheRefusalStands() async {
        let w = makeWallet()
        w.activeVctmDocument = document("urn:eudi:pid:1", name: "PID (old)")
        w.activeOffer = nil

        let raw = sdJwt(vct: "urn:eudi:pid:1", integrity: digest(of: #"{"vct":"urn:eudi:pid:1","name":"PID"}"#))
        let reason = await w.verifyVctIntegrity(format: "dc+sd-jwt", payload: payload(raw))
        XCTAssertNotNil(reason)
    }

    func testMdocCarriesNoVctIntegrity() async {
        let w = makeWallet()
        w.activeVctmDocument = document("urn:eudi:pid:1")
        let raw = sdJwt(vct: "urn:eudi:pid:1", integrity: digest(of: "wrong"))
        let reason = await w.verifyVctIntegrity(format: "mso_mdoc", payload: payload(raw))
        XCTAssertNil(reason)
    }
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

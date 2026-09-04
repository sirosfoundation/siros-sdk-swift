// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosAuth
import SirosCredentials
@testable import SirosWallet

#if canImport(CryptoKit)
import CryptoKit
#endif

// `SirosWallet.init` requires a real `JweKeystore`, only available where
// CryptoKit is — matching this target's existing convention. The digest half of
// this feature is covered on every platform by SirosCredentialsTests.
#if canImport(CryptoKit)

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

    private func makeWallet() -> SirosWallet {
        let config = WalletConfig(backendUrl: "https://example.invalid")
        let wallet = SirosWallet(config: config, authProvider: StubAuthProvider())
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

    // MARK: - vct#integrity

    private func document(_ vct: String) -> VctmDocument {
        VctmDocument(raw: "{\"vct\":\"\(vct)\"}", vctm: Vctm(vct: vct))
    }

    private func digest(of raw: String) -> String {
        "sha256-" + Data(SHA256.hash(data: Data(raw.utf8))).base64EncodedString()
    }

    func testAcceptsTypeMetadataMatchingTheIssuersDigest() {
        let w = makeWallet()
        let doc = document("urn:eudi:pid:1")
        w.activeVctmDocument = doc
        let raw = sdJwt(vct: "urn:eudi:pid:1", integrity: digest(of: doc.raw))
        XCTAssertNil(w.verifyVctIntegrity(format: "dc+sd-jwt", payload: payload(raw)))
    }

    func testRefusesTypeMetadataTheIssuerDidNotPin() {
        // A registry serving altered metadata for a type the issuer is
        // legitimately entitled to issue.
        let w = makeWallet()
        w.activeVctmDocument = document("urn:eudi:pid:1")
        let raw = sdJwt(vct: "urn:eudi:pid:1", integrity: digest(of: #"{"vct":"urn:eudi:pid:1","claims":[]}"#))
        XCTAssertNotNil(w.verifyVctIntegrity(format: "dc+sd-jwt", payload: payload(raw)))
    }

    func testAcceptsACredentialThatPinsNothing() {
        let w = makeWallet()
        w.activeVctmDocument = document("urn:eudi:pid:1")
        XCTAssertNil(w.verifyVctIntegrity(format: "dc+sd-jwt", payload: payload(sdJwt(vct: "urn:eudi:pid:1"))))
    }

    func testAcceptsWhenNoMetadataWasResolvedToCheck() {
        // Nothing was applied, so nothing was tampered with.
        let w = makeWallet()
        w.activeVctmDocument = nil
        let raw = sdJwt(vct: "urn:eudi:pid:1", integrity: digest(of: #"{"vct":"urn:eudi:pid:1"}"#))
        XCTAssertNil(w.verifyVctIntegrity(format: "dc+sd-jwt", payload: payload(raw)))
    }

    func testMdocCarriesNoVctIntegrity() {
        let w = makeWallet()
        w.activeVctmDocument = document("urn:eudi:pid:1")
        let raw = sdJwt(vct: "urn:eudi:pid:1", integrity: digest(of: "wrong"))
        XCTAssertNil(w.verifyVctIntegrity(format: "mso_mdoc", payload: payload(raw)))
    }
}

#endif

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

final class InteropProfileTests: XCTestCase {

    func testAddingDiipDoesNotChangeWhatAWalletSendsByDefault() {
        // Every SIROS ID issuer already accepts the HAIP-shaped proof; making
        // DIIP the default would have been a wire change nobody asked for.
        XCTAssertEqual(InteropProfile.default, .haip)
    }

    func testEachProfileNamesTheHolderKeyItsOwnWay() {
        XCTAssertEqual(InteropProfile.haip.holderBinding, .embeddedJwk)
        XCTAssertEqual(InteropProfile.diip.holderBinding, .didJwk)
    }

    func testAProfileIsParsedFromConfigurationAndNothingIsGuessed() {
        XCTAssertEqual(InteropProfile.from(id: "haip"), .haip)
        XCTAssertEqual(InteropProfile.from(id: " DIIP "), .diip)
        XCTAssertNil(InteropProfile.from(id: "something-else"))
        XCTAssertNil(InteropProfile.from(id: nil))
    }

    // MARK: - negotiation
    //
    // The point of these: a wallet holding credentials from a HAIP ecosystem
    // and a DIIP ecosystem has to shape each proof to its issuer, and nobody
    // can reasonably be asked which profile an issuer they just scanned
    // belongs to. The issuer already says so in its own metadata.

    func testAHaipIssuerAsksForTheKeyItself() {
        XCTAssertEqual(HolderBinding.negotiate(["jwk"]), .embeddedJwk)
    }

    func testADiipIssuerAsksForADidJwk() {
        XCTAssertEqual(HolderBinding.negotiate(["did:jwk"]), .didJwk)
        // A bare "did" means any DID method.
        XCTAssertEqual(HolderBinding.negotiate(["did"]), .didJwk)
    }

    func testTheEmbeddedKeyWinsWhenAnIssuerAcceptsBoth() {
        // Either is interoperable by the issuer's own declaration, and the
        // embedded key needs no DID resolution anywhere in the chain.
        XCTAssertEqual(HolderBinding.negotiate(["did:jwk", "jwk"]), .embeddedJwk)
        XCTAssertEqual(HolderBinding.negotiate(["jwk", "did:jwk"]), .embeddedJwk)
    }

    func testCaseAndWhitespaceInAdvertisedMethodsDoNotDefeatTheMatch() {
        XCTAssertEqual(HolderBinding.negotiate([" JWK "]), .embeddedJwk)
        XCTAssertEqual(HolderBinding.negotiate(["DID:JWK"]), .didJwk)
    }

    func testAnIssuerThatAdvertisesNothingUsableLeavesTheChoiceToTheCaller() {
        // Nil means "fall back to the configured profile" - guessing here
        // would fail the issuance just as surely, with less to debug.
        XCTAssertNil(HolderBinding.negotiate(nil))
        XCTAssertNil(HolderBinding.negotiate([]))
        XCTAssertNil(HolderBinding.negotiate(["cose_key"]))
        // A DID method whose keys this wallet cannot mint is not a match.
        XCTAssertNil(HolderBinding.negotiate(["did:web", "did:ebsi"]))
    }

    func testABindingNamesTheOid4vciMethodItCorrespondsTo() {
        XCTAssertEqual(HolderBinding.embeddedJwk.bindingMethod, "jwk")
        XCTAssertEqual(HolderBinding.didJwk.bindingMethod, "did:jwk")
    }

    func testTheBindingMethodIsReadOffACredentialConfiguration() {
        // End to end: what an issuer publishes in its OID4VCI metadata is what
        // the wallet negotiates from.
        let haip = CredentialConfiguration(
            format: "dc+sd-jwt", cryptographicBindingMethodsSupported: ["jwk"]
        )
        let diip = CredentialConfiguration(
            format: "dc+sd-jwt", cryptographicBindingMethodsSupported: ["did:jwk"]
        )
        XCTAssertEqual(HolderBinding.negotiate(haip.cryptographicBindingMethodsSupported), .embeddedJwk)
        XCTAssertEqual(HolderBinding.negotiate(diip.cryptographicBindingMethodsSupported), .didJwk)
        XCTAssertNil(HolderBinding.negotiate(CredentialConfiguration(format: "dc+sd-jwt")
            .cryptographicBindingMethodsSupported))
    }

    func testIssuerMetadataDecodesTheBindingMethods() throws {
        let json = """
        {
          "credential_issuer": "https://issuer.example",
          "credential_configurations_supported": {
            "pid": {
              "format": "dc+sd-jwt",
              "cryptographic_binding_methods_supported": ["did:jwk", "jwk"]
            }
          }
        }
        """
        let metadata = try JSONDecoder().decode(IssuerMetadata.self, from: Data(json.utf8))
        let config = try XCTUnwrap(metadata.credentialConfigurationsSupported["pid"])
        XCTAssertEqual(config.cryptographicBindingMethodsSupported, ["did:jwk", "jwk"])
    }
    func testARealDiipIssuersAdvertisedMethodsNegotiateTheDidBinding() {
        // Verbatim from https://nl.gov.issuer.dev.eduwallet.nl's
        // .well-known/openid-credential-issuer (PID, dc+sd-jwt), reached
        // through the eduwallet demo launcher. It advertises no `jwk` at all,
        // so a wallet that defaults to HAIP still has to send this issuer the
        // DIIP proof shape - which is the whole point of negotiating rather
        // than configuring.
        XCTAssertEqual(HolderBinding.negotiate(["did:jwk", "did:key"]), .didJwk)
        // And the substring trap: "jwk" must be matched as a whole value, not
        // found inside "did:jwk".
        XCTAssertEqual(HolderBinding.negotiate(["did:jwk"]), .didJwk)
        XCTAssertEqual(HolderBinding.negotiate(["jwk", "did:jwk"]), .embeddedJwk)
        // A DID method that is not did:jwk names nothing this Holder can use.
        XCTAssertNil(HolderBinding.negotiate(["did:key"]))
    }
}

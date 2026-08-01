// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosCredentials
@testable import SirosWallet

/// `SirosWallet.buildCredentialOffer` reads the standard OID4VCI
/// `credential_metadata.display` field (falling back to the issuer's own
/// top-level `display`) to build display metadata (name/logo/colors) for a
/// credential configuration.
///
/// `activeOffer` (built from exactly this) was previously only ever set by
/// `startIssuanceByOffer`, the picker-driven path - the QR/deep-link entry
/// point (`startIssuance`) never populated it, so every credential issued via
/// a scanned offer (real-world issuers included) was stored with no display
/// metadata at all, confirmed against a real geneva2026.mdoc.online mDL
/// credential offer. `startIssuance` now resolves it via this same helper.
final class CredentialOfferMetadataTests: XCTestCase {

    private func metadata(configId: String) -> IssuerMetadata {
        IssuerMetadata(
            credentialIssuer: "https://geneva2026.mdoc.online",
            display: [IssuerDisplay(name: "Geneva 2026")],
            credentialConfigurationsSupported: [
                configId: CredentialConfiguration(
                    format: "mso_mdoc",
                    doctype: configId,
                    credentialMetadata: CredentialDisplayMetadata(display: [
                        CredentialDisplayEntry(
                            name: "Mobile Driving License",
                            locale: "en-US",
                            logo: LogoInfo(uri: "data:image/png;base64,abc")
                        ),
                    ])
                ),
            ]
        )
    }

    func testUsesCredentialMetadataDisplayOverIssuerDisplay() {
        let offer = SirosWallet.buildCredentialOffer(
            issuerUrl: "https://geneva2026.mdoc.online",
            configId: "org.iso.18013.5.1.mDL",
            metadata: metadata(configId: "org.iso.18013.5.1.mDL")
        )

        XCTAssertEqual(offer?.credentialName, "Mobile Driving License")
        XCTAssertEqual(offer?.issuerName, "Geneva 2026")
        XCTAssertEqual(offer?.logoUri, "data:image/png;base64,abc")
        XCTAssertEqual(offer?.credentialConfigurationId, "org.iso.18013.5.1.mDL")
        XCTAssertEqual(offer?.credentialIssuerIdentifier, "https://geneva2026.mdoc.online")
    }

    func testFallsBackToIssuerDisplayAndConfigIdWhenNoCredentialMetadata() {
        let metadata = IssuerMetadata(
            credentialIssuer: "https://issuer.example.com",
            display: [IssuerDisplay(name: "Example Issuer", backgroundColor: "#123456")],
            credentialConfigurationsSupported: [
                "pid": CredentialConfiguration(format: "vc+sd-jwt"),
            ]
        )

        let offer = SirosWallet.buildCredentialOffer(issuerUrl: "https://issuer.example.com", configId: "pid", metadata: metadata)

        XCTAssertEqual(offer?.credentialName, "pid", "no credential_metadata.display - falls back to the raw configId")
        XCTAssertEqual(offer?.issuerName, "Example Issuer")
        XCTAssertEqual(offer?.backgroundColor, "#123456", "falls back to the issuer's own display when the config has none")
    }

    func testFallsBackToHostWhenIssuerHasNoDisplayEither() {
        let metadata = IssuerMetadata(
            credentialIssuer: "https://issuer.example.com",
            credentialConfigurationsSupported: ["pid": CredentialConfiguration(format: "vc+sd-jwt")]
        )

        let offer = SirosWallet.buildCredentialOffer(issuerUrl: "https://issuer.example.com", configId: "pid", metadata: metadata)

        XCTAssertEqual(offer?.issuerName, "issuer.example.com")
    }

    func testReturnsNilWhenConfigIdNotOfferedByIssuer() {
        let offer = SirosWallet.buildCredentialOffer(
            issuerUrl: "https://geneva2026.mdoc.online",
            configId: "not-offered",
            metadata: metadata(configId: "org.iso.18013.5.1.mDL")
        )

        XCTAssertNil(offer)
    }
}

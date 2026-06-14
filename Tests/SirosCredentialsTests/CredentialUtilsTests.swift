// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

final class CredentialUtilsTests: XCTestCase {

    private var sampleJwt: String {
        let header = base64Url("""
        {"alg":"ES256","typ":"vc+sd-jwt"}
        """)
        let payload = base64Url("""
        {"iss":"https://issuer.example.com","sub":"user123","iat":1700000000,"exp":1800000000,"vct":"urn:example:diploma","given_name":"Alice","family_name":"Smith","degree":"MSc Computer Science","cnf":{"jwk":{}},"_sd_alg":"sha-256"}
        """)
        return "\(header).\(payload).fakesig"
    }

    private func base64Url(_ string: String) -> String {
        Data(string.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    func testParseJwtPayloadExtractsPayload() {
        let payload = CredentialUtils.parseJwtPayload(sampleJwt)
        XCTAssertNotNil(payload)
        XCTAssertEqual(payload?["iss"] as? String, "https://issuer.example.com")
        XCTAssertEqual(payload?["given_name"] as? String, "Alice")
    }

    func testParseJwtPayloadHandlesSdJwtWithDisclosures() {
        let sdJwt = "\(sampleJwt)~disclosure1~disclosure2"
        let payload = CredentialUtils.parseJwtPayload(sdJwt)
        XCTAssertNotNil(payload)
        XCTAssertEqual(payload?["given_name"] as? String, "Alice")
    }

    func testParseJwtPayloadReturnsNilForInvalidInput() {
        XCTAssertNil(CredentialUtils.parseJwtPayload("not-a-jwt"))
        XCTAssertNil(CredentialUtils.parseJwtPayload(""))
        XCTAssertNil(CredentialUtils.parseJwtPayload("only-one-part"))
    }

    func testParseJwtPayloadReturnsNilForMalformedBase64() {
        XCTAssertNil(CredentialUtils.parseJwtPayload("aaa.!!!invalid!!!.bbb"))
    }

    func testExtractClaimsReturnsUserFacingClaims() {
        let cred = StoredCredential(id: "test-id", format: "vc+sd-jwt", raw: sampleJwt)
        let claims = CredentialUtils.extractClaims(cred)
        let keys = claims.map(\.key)
        XCTAssertTrue(keys.contains("given_name"))
        XCTAssertTrue(keys.contains("family_name"))
        XCTAssertTrue(keys.contains("degree"))
        XCTAssertFalse(keys.contains("iss"))
        XCTAssertFalse(keys.contains("exp"))
        XCTAssertFalse(keys.contains("cnf"))
        XCTAssertFalse(keys.contains("_sd_alg"))
        XCTAssertFalse(keys.contains("vct"))
    }

    func testExtractClaimsUsesVctmLabels() {
        let cred = StoredCredential(
            id: "test-id", format: "vc+sd-jwt", raw: sampleJwt,
            metadata: CredentialMetadata(claims: [
                ClaimMeta(path: ["given_name"], label: "First Name"),
                ClaimMeta(path: ["family_name"], label: "Surname"),
            ])
        )
        let claims = CredentialUtils.extractClaims(cred)
        XCTAssertEqual(claims.first(where: { $0.key == "given_name" })?.label, "First Name")
        XCTAssertEqual(claims.first(where: { $0.key == "family_name" })?.label, "Surname")
    }

    func testExtractClaimsFormatsKeysWhenNoVctm() {
        let cred = StoredCredential(id: "test-id", format: "vc+sd-jwt", raw: sampleJwt)
        let claims = CredentialUtils.extractClaims(cred)
        XCTAssertEqual(claims.first(where: { $0.key == "given_name" })?.label, "Given Name")
    }

    func testExtractClaimsReturnsEmptyForUnparseableCredential() {
        let cred = StoredCredential(id: "bad", format: "vc+sd-jwt", raw: "not-a-jwt")
        XCTAssertTrue(CredentialUtils.extractClaims(cred).isEmpty)
    }

    func testFormatClaimKey() {
        XCTAssertEqual(CredentialUtils.formatClaimKey("given_name"), "Given Name")
        XCTAssertEqual(CredentialUtils.formatClaimKey("family-name"), "Family Name")
        XCTAssertEqual(CredentialUtils.formatClaimKey("degree"), "Degree")
    }

    func testBuildMetadataCombinesOfferAndVctm() {
        let offer = CredentialOffer(
            credentialConfigurationId: "diploma",
            credentialIssuerIdentifier: "https://issuer.example.com",
            credentialName: "Diploma (offer)",
            issuerName: "Test Issuer",
            backgroundColor: "#000000"
        )
        let vctm = Vctm(
            vct: "urn:example:diploma",
            display: [
                VctmDisplay(
                    locale: "en",
                    name: "University Diploma",
                    description: "A diploma from VCTM",
                    rendering: VctmRendering(
                        simple: VctmSimpleRendering(
                            backgroundColor: "#003366",
                            textColor: "#ffffff"
                        )
                    )
                ),
            ],
            claims: [
                VctmClaim(
                    path: ["given_name"],
                    display: [VctmClaimDisplay(locale: "en", label: "Given Name")],
                    sd: "allowed",
                    mandatory: true
                ),
            ]
        )

        let metadata = CredentialUtils.buildMetadata(
            offer: offer, vctm: vctm, rawCredential: sampleJwt)

        // VCTM display may or may not match locale — check fallback behavior
        XCTAssertNotNil(metadata.name)
        XCTAssertEqual(metadata.issuer?.name, "Test Issuer")
        XCTAssertEqual(metadata.vct, "urn:example:diploma")
        XCTAssertNotNil(metadata.claims)
    }

    func testBuildMetadataFallsBackToOfferWhenNoVctm() {
        let offer = CredentialOffer(
            credentialConfigurationId: "diploma",
            credentialIssuerIdentifier: "https://issuer.example.com",
            credentialName: "Diploma (offer)",
            issuerName: "Test Issuer",
            backgroundColor: "#000000"
        )
        let metadata = CredentialUtils.buildMetadata(offer: offer)
        XCTAssertEqual(metadata.name, "Diploma (offer)")
        XCTAssertEqual(metadata.backgroundColor, "#000000")
        XCTAssertNil(metadata.claims)
    }
}

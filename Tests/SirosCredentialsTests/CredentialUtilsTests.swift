// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@preconcurrency import SwiftCBOR
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
        let cred = StoredCredential(id: 1, format: "vc+sd-jwt", raw: sampleJwt, batchId: 1, instanceId: 0)
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
            id: 1, format: "vc+sd-jwt", raw: sampleJwt,
            metadata: CredentialMetadata(claims: [
                ClaimMeta(path: ["given_name"], label: "First Name"),
                ClaimMeta(path: ["family_name"], label: "Surname"),
            ]),
            batchId: 1, instanceId: 0
        )
        let claims = CredentialUtils.extractClaims(cred)
        XCTAssertEqual(claims.first(where: { $0.key == "given_name" })?.label, "First Name")
        XCTAssertEqual(claims.first(where: { $0.key == "family_name" })?.label, "Surname")
    }

    func testExtractClaimsFormatsKeysWhenNoVctm() {
        let cred = StoredCredential(id: 1, format: "vc+sd-jwt", raw: sampleJwt, batchId: 1, instanceId: 0)
        let claims = CredentialUtils.extractClaims(cred)
        XCTAssertEqual(claims.first(where: { $0.key == "given_name" })?.label, "Given Name")
    }

    func testExtractClaimsReturnsEmptyForUnparseableCredential() {
        let cred = StoredCredential(id: 2, format: "vc+sd-jwt", raw: "not-a-jwt", batchId: 2, instanceId: 0)
        XCTAssertTrue(CredentialUtils.extractClaims(cred).isEmpty)
    }

    func testExtractClaimsResolvesDeeplyNestedVctmPath() {
        let header = base64Url(#"{"alg":"ES256","typ":"vc+sd-jwt"}"#)
        let payload = base64Url("""
        {"iss":"https://issuer.example.com","exp":1800000000,"vct":"urn:example:diploma",
         "credentialSubject":{"hasClaim":{"awardedBy":{"institution":"ArtEZ"}},"givenName":"Alice"}}
        """)
        let raw = "\(header).\(payload).fakesig"
        let cred = StoredCredential(
            id: 3, format: "vc+sd-jwt", raw: raw,
            metadata: CredentialMetadata(claims: [
                ClaimMeta(path: ["credentialSubject", "hasClaim", "awardedBy", "institution"], label: "Institution"),
            ]),
            batchId: 3, instanceId: 0
        )
        let claims = CredentialUtils.extractClaims(cred)
        let institution = claims.first(where: { $0.key == "credentialSubject.hasClaim.awardedBy.institution" })
        XCTAssertEqual(institution?.label, "Institution")
        XCTAssertEqual(institution?.value, "ArtEZ")
        // The ancestor top-level key must not also be dumped raw as its own claim.
        XCTAssertFalse(claims.contains(where: { $0.key == "credentialSubject" }))
    }

    func testExtractClaimsSkipsVctmClaimMissingFromCredential() {
        let cred = StoredCredential(
            id: 4, format: "vc+sd-jwt", raw: sampleJwt,
            metadata: CredentialMetadata(claims: [
                ClaimMeta(path: ["credentialSubject", "nonexistent"], label: "Nope"),
            ]),
            batchId: 4, instanceId: 0
        )
        let claims = CredentialUtils.extractClaims(cred)
        XCTAssertFalse(claims.contains(where: { $0.label == "Nope" }))
    }

    func testParseSdJwtPartsDecodesHeaderPayloadAndDisclosures() {
        let disclosure = base64Url(#"["salt123","given_name","Alice"]"#)
        let raw = "\(sampleJwt)~\(disclosure)~"
        let parts = CredentialUtils.parseSdJwtParts(raw)
        XCTAssertNotNil(parts.header)
        XCTAssertTrue(parts.header?.contains("ES256") ?? false)
        XCTAssertNotNil(parts.payload)
        XCTAssertTrue(parts.payload?.contains("Alice") ?? false)
        XCTAssertEqual(parts.disclosures.count, 1)
        XCTAssertTrue(parts.disclosures[0].contains("given_name"))
    }

    func testPrettyPrintJsonIndentsValidJson() {
        let pretty = CredentialUtils.prettyPrintJson(#"{"a":1,"b":2}"#)
        XCTAssertTrue(pretty.contains("\n"))
        XCTAssertTrue(pretty.contains("\"a\""))
    }

    func testPrettyPrintJsonReturnsInputUnchangedForNonJson() {
        XCTAssertEqual(CredentialUtils.prettyPrintJson("not json"), "not json")
    }

    func testPrettyPrintXmlIndentsNestedElements() {
        let pretty = CredentialUtils.prettyPrintXml("<svg><text>{{name}}</text></svg>")
        XCTAssertTrue(pretty.contains("\n"))
        XCTAssertTrue(pretty.contains("<text>"))
        XCTAssertTrue(pretty.contains("{{name}}"))
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

    // MARK: - mdoc (mso_mdoc)

    private let mdocDocType = "org.iso.18013.5.1.mDL"
    private let mdocNamespace = "org.iso.18013.5.1"

    private func buildTaggedItem(digestId: UInt64, elementIdentifier: String, elementValue: String) -> CBOR {
        let item: CBOR = .map([
            .utf8String("digestID"): .unsignedInt(digestId),
            .utf8String("random"): .byteString([UInt8](repeating: 0, count: 16)),
            .utf8String("elementIdentifier"): .utf8String(elementIdentifier),
            .utf8String("elementValue"): .utf8String(elementValue),
        ])
        return .tagged(.encodedCBORDataItem, .byteString(item.encode()))
    }

    /// Build a synthetic mdoc credential's raw (base64url) bytes: a DeviceResponse-shaped envelope.
    private func buildMdocRaw() -> String {
        let items: CBOR = .array([
            buildTaggedItem(digestId: 0, elementIdentifier: "family_name", elementValue: "Doe"),
            buildTaggedItem(digestId: 1, elementIdentifier: "given_name", elementValue: "Jane"),
        ])
        let nameSpaces: CBOR = .map([.utf8String(mdocNamespace): items])
        let issuerAuth: CBOR = .array(Array(repeating: .byteString([]), count: 4))
        let issuerSigned: CBOR = .map([
            .utf8String("nameSpaces"): nameSpaces,
            .utf8String("issuerAuth"): issuerAuth,
        ])
        let document: CBOR = .map([
            .utf8String("docType"): .utf8String(mdocDocType),
            .utf8String("issuerSigned"): issuerSigned,
        ])
        let envelope: CBOR = .map([
            .utf8String("documents"): .array([document]),
            .utf8String("status"): .unsignedInt(0),
        ])
        return Data(envelope.encode()).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    func testExtractClaimsDispatchesToMdocParsingForMsoMdocFormat() {
        let cred = StoredCredential(
            id: 5,
            format: "mso_mdoc",
            raw: buildMdocRaw(),
            metadata: CredentialMetadata(
                doctype: mdocDocType,
                claims: [
                    ClaimMeta(path: [mdocNamespace, "family_name"], label: "Family Name", mandatory: true),
                ]
            ),
            batchId: 5,
            instanceId: 0
        )

        let claims = CredentialUtils.extractClaims(cred)
        XCTAssertEqual(claims.count, 2)
        let familyName = claims.first { $0.key == "\(mdocNamespace).family_name" }
        XCTAssertEqual(familyName?.label, "Family Name")
        XCTAssertEqual(familyName?.value, "Doe")
        XCTAssertEqual(familyName?.mandatory, true)

        let givenName = claims.first { $0.key == "\(mdocNamespace).given_name" }
        // No ClaimMeta entry for given_name - falls back to formatted key.
        XCTAssertEqual(givenName?.label, "Given Name")
        XCTAssertEqual(givenName?.value, "Jane")
    }

    func testBuildMdocMetadataPopulatesDoctypeAndClaimsFromMddlSchema() {
        let offer = CredentialOffer(
            credentialConfigurationId: "mdl",
            credentialIssuerIdentifier: "https://issuer.example.com",
            credentialName: "Driving Licence (offer)",
            issuerName: "Test Issuer"
        )
        let locale = Locale.current.identifier.replacingOccurrences(of: "_", with: "-")
        let schema = MddlSchema(
            format: "mso_mdoc",
            doctype: mdocDocType,
            display: [MddlDisplay(locale: locale, name: "Driving Licence")],
            claims: [
                mdocNamespace: [
                    "family_name": MddlClaimMeta(
                        display: [MddlClaimDisplay(locale: locale, name: "Family Name")],
                        mandatory: true,
                        valueType: "tstr"
                    ),
                ],
            ]
        )

        let metadata = CredentialUtils.buildMdocMetadata(offer: offer, mddlSchema: schema)
        XCTAssertEqual(metadata.name, "Driving Licence")
        XCTAssertEqual(metadata.doctype, mdocDocType)
        XCTAssertNil(metadata.vct)
        XCTAssertEqual(metadata.claims?.count, 1)
        XCTAssertEqual(metadata.claims?.first?.path, [mdocNamespace, "family_name"])
        XCTAssertEqual(metadata.claims?.first?.label, "Family Name")
        XCTAssertEqual(metadata.claims?.first?.mandatory, true)
    }

    func testBuildMdocMetadataFallsBackToOfferWhenNoMddlSchema() {
        let offer = CredentialOffer(
            credentialConfigurationId: "mdl",
            credentialIssuerIdentifier: "https://issuer.example.com",
            credentialName: "Driving Licence (offer)",
            issuerName: "Test Issuer",
            backgroundColor: "#1a365d"
        )
        let metadata = CredentialUtils.buildMdocMetadata(offer: offer)
        XCTAssertEqual(metadata.name, "Driving Licence (offer)")
        XCTAssertEqual(metadata.backgroundColor, "#1a365d")
        XCTAssertNil(metadata.claims)
    }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

/// The wallet-side half of ARF v3.0.0 section 6.6.2.3 rests entirely on
/// decoding the backend's decision correctly. These pin the wire shape that
/// go-wallet-backend's `pkg/issuertrust` actually emits, because a field that
/// silently fails to decode would turn a refusal into a pass.
final class IssuerEntitlementDecodingTests: XCTestCase {

    private func decode(_ json: String) throws -> IssuerEntitlement {
        try JSONDecoder().decode(IssuerEntitlement.self, from: Data(json.utf8))
    }

    func testDecodesARefusalWithItsFindings() throws {
        let ent = try decode("""
        {
          "allowed": false,
          "mode": "fail",
          "evaluated": true,
          "findings": [
            {
              "code": "attestation_type_not_registered",
              "message": "provider is not registered to issue dc+sd-jwt of type \\"eu.europa.ec.eudi.pid.1\\"",
              "credential_type": "eu.europa.ec.eudi.pid.1"
            }
          ],
          "entitlements": ["http://data.europa.eu/eudi/id/pid-provider"],
          "subject": "VATSE-1234567890"
        }
        """)

        XCTAssertFalse(ent.allowed)
        XCTAssertEqual(ent.mode, "fail")
        XCTAssertTrue(ent.evaluated)
        XCTAssertEqual(ent.findings.count, 1)
        XCTAssertEqual(ent.findings[0].code, "attestation_type_not_registered")
        // snake_case, not camelCase - the backend emits `credential_type`.
        XCTAssertEqual(ent.findings[0].credentialType, "eu.europa.ec.eudi.pid.1")
        XCTAssertEqual(ent.entitlements, ["http://data.europa.eu/eudi/id/pid-provider"])
        XCTAssertEqual(ent.subject, "VATSE-1234567890")
    }

    func testWarnModeIsAllowedButStillCarriesFindings() throws {
        let ent = try decode("""
        {
          "allowed": true,
          "mode": "warn",
          "evaluated": false,
          "findings": [
            {
              "code": "no_registration_certificate",
              "message": "issuer metadata carries no registration certificate in issuer_info"
            }
          ]
        }
        """)

        XCTAssertTrue(ent.allowed)
        // `evaluated` false with `allowed` true is precisely the state that
        // must not read as a pass: nothing was checked.
        XCTAssertFalse(ent.evaluated)
        XCTAssertEqual(ent.findings.first?.code, "no_registration_certificate")
        XCTAssertNil(ent.findings.first?.credentialType)
    }

    func testOmittedFieldsDoNotFailDecoding() throws {
        // go-wallet-backend omits empty findings/entitlements (`omitempty`).
        // If that made the whole decision undecodable, the wallet would fall
        // back to "not checked" for every well-formed pass.
        let ent = try decode(#"{"allowed": true, "mode": "off", "evaluated": false}"#)
        XCTAssertTrue(ent.allowed)
        XCTAssertEqual(ent.mode, "off")
        XCTAssertTrue(ent.findings.isEmpty)
        XCTAssertTrue(ent.entitlements.isEmpty)
        XCTAssertNil(ent.subject)
    }

    func testIssuerMetadataCarriesSignedMetadataAndIssuerInfo() throws {
        // ETSI TS 119 472-3: the provider's WRPAC signs `signed_metadata`, and
        // its registration certificate travels in `issuer_info`.
        let metadata = try JSONDecoder().decode(IssuerMetadata.self, from: Data("""
        {
          "credential_issuer": "https://issuer.example.com",
          "credential_configurations_supported": {},
          "signed_metadata": "eyJhbGciOiJFUzI1NiJ9.e30.sig",
          "issuer_info": [
            {"format": "registration_cert", "credential": "eyJ0eXAiOiJyYy13cnArand0In0.e30.sig"}
          ]
        }
        """.utf8))

        XCTAssertEqual(metadata.signedMetadata, "eyJhbGciOiJFUzI1NiJ9.e30.sig")
        XCTAssertEqual(metadata.issuerInfo?.count, 1)
        XCTAssertEqual(metadata.issuerInfo?[0].format, "registration_cert")
        XCTAssertNotNil(metadata.issuerInfo?[0].credential)
    }

    func testIssuerMetadataWithoutTheNewFieldsStillDecodes() throws {
        // Every issuer that has not yet been registered emits neither field.
        let metadata = try JSONDecoder().decode(IssuerMetadata.self, from: Data(#"""
        {"credential_issuer": "https://issuer.example.com", "credential_configurations_supported": {}}
        """#.utf8))
        XCTAssertNil(metadata.signedMetadata)
        XCTAssertNil(metadata.issuerInfo)
    }
}

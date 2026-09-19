// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosTransport
@testable import SirosCredentials

final class AuthorizationDetailsTests: XCTestCase {

    func testAKnownConfigurationIsAskedForByCredentialConfigurationID() throws {
        let details = try XCTUnwrap(AuthorizationDetails.build(credentialConfigurationID: "pid"))
        XCTAssertEqual(details.count, 1)
        XCTAssertEqual(details[0].type, "openid_credential")
        XCTAssertEqual(details[0].credentialConfigurationID, "pid")
    }

    func testNothingIsAskedForWhenTheConfigurationIsUnknown() {
        // The offer could not be resolved, so there is nothing to name. The
        // `scope` path is left exactly as it was.
        XCTAssertNil(AuthorizationDetails.build(credentialConfigurationID: nil))
        XCTAssertNil(AuthorizationDetails.build(credentialConfigurationID: ""))
        XCTAssertNil(AuthorizationDetails.build(credentialConfigurationID: "   "))
    }

    func testAnAuthorizationServerListingTypesWithoutOpenidCredentialIsTakenAtItsWord() {
        XCTAssertNil(AuthorizationDetails.build(
            credentialConfigurationID: "pid", advertisedTypes: ["something_else"]
        ))
        XCTAssertNil(AuthorizationDetails.build(credentialConfigurationID: "pid", advertisedTypes: []))
    }

    func testAnAuthorizationServerListingOpenidCredentialGetsTheDetails() throws {
        let details = try XCTUnwrap(AuthorizationDetails.build(
            credentialConfigurationID: "pid", advertisedTypes: ["openid_credential"]
        ))
        XCTAssertEqual(details.first?.credentialConfigurationID, "pid")
    }

    func testUnknownAuthorizationServerCapabilityIsNotAReasonToWithhold() throws {
        // On the engine-driven transports the AS is discovered server-side, so
        // the wallet usually holds no metadata. Sending intent the Issuer may
        // ignore is safe; withholding it fails the requirement outright.
        let details = try XCTUnwrap(AuthorizationDetails.build(
            credentialConfigurationID: "pid", advertisedTypes: nil
        ))
        XCTAssertEqual(details.first?.credentialConfigurationID, "pid")
    }

    func testTheWireShapeIsWhatOid4vciAndTheEngineExpect() throws {
        // Field names have to match go-wallet-backend's FlowStartMessage and
        // wallet-frontend's flow_start exactly - all three talk to the same
        // issuers. In particular `type` must survive encoding.
        let details = try XCTUnwrap(AuthorizationDetails.build(credentialConfigurationID: "pid"))
        let encoded = try JSONEncoder().encode(details)
        let json = try XCTUnwrap(String(data: encoded, encoding: .utf8))
        XCTAssertTrue(json.contains("\"type\":\"openid_credential\""), json)
        XCTAssertTrue(json.contains("\"credential_configuration_id\":\"pid\""), json)
    }

    func testFlowStartCarriesTheDetailsAndOmitsThemWhenAbsent() throws {
        // Absent must mean "do not ask this way", not "ask with nothing".
        let withDetails = FlowStartMessage(
            protocol: "oid4vci",
            authorizationDetails: AuthorizationDetails.build(credentialConfigurationID: "pid")
        )
        let encoder = JSONEncoder()
        let carried = try XCTUnwrap(String(data: try encoder.encode(withDetails), encoding: .utf8))
        XCTAssertTrue(carried.contains("\"authorization_details\""), carried)

        let without = FlowStartMessage(protocol: "oid4vci")
        let bare = try XCTUnwrap(String(data: try encoder.encode(without), encoding: .utf8))
        XCTAssertFalse(bare.contains("authorization_details"), bare)
    }
}

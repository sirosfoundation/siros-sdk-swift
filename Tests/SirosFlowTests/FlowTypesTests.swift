// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosFlow

final class FlowTypesTests: XCTestCase {

    func testSignActionRawValues() {
        XCTAssertEqual(SignAction.generateProof.rawValue, "generate_proof")
        XCTAssertEqual(SignAction.signPresentation.rawValue, "sign_presentation")
    }

    func testSignActionFromRawValue() {
        XCTAssertEqual(SignAction(rawValue: "generate_proof"), .generateProof)
        XCTAssertEqual(SignAction(rawValue: "sign_presentation"), .signPresentation)
        XCTAssertNil(SignAction(rawValue: "invalid"))
    }

    func testSignParamsDefaults() {
        let params = SignParams()
        XCTAssertNil(params.audience)
        XCTAssertNil(params.nonce)
        XCTAssertNil(params.issuer)
        XCTAssertNil(params.responseUri)
        XCTAssertNil(params.credentialsToInclude)
    }

    func testSignParamsInit() {
        let params = SignParams(
            audience: "https://issuer.example.com",
            nonce: "abc123"
        )
        XCTAssertEqual(params.audience, "https://issuer.example.com")
        XCTAssertEqual(params.nonce, "abc123")
    }

    func testSignResponseInit() {
        let r1 = SignResponse(proofJwt: "jwt-abc")
        XCTAssertEqual(r1.proofJwt, "jwt-abc")
        XCTAssertNil(r1.vpToken)

        let r2 = SignResponse(vpToken: "vp-token")
        XCTAssertNil(r2.proofJwt)
        XCTAssertEqual(r2.vpToken, "vp-token")
    }

    func testMatchResponseInit() {
        let resp = MatchResponse(credentialIds: ["cred-1", "cred-2"])
        XCTAssertEqual(resp.credentialIds, ["cred-1", "cred-2"])
    }

    func testOID4VCIFlowParamsInit() {
        let params = OID4VCIFlowParams(credentialOfferUri: "https://issuer.example.com/offer/123")
        XCTAssertEqual(params.credentialOfferUri, "https://issuer.example.com/offer/123")
        XCTAssertNil(params.issuerUrl)
    }

    func testOID4VPFlowParamsInit() {
        let params = OID4VPFlowParams(requestUri: "https://verifier.example.com/request/abc")
        XCTAssertEqual(params.requestUri, "https://verifier.example.com/request/abc")
    }
}

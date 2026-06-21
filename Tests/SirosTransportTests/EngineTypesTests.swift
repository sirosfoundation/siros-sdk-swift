// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosTransport

final class EngineTypesTests: XCTestCase {
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    func testHandshakeMessageEncoding() throws {
        let msg = HandshakeMessage(appToken: "test-token")
        let data = try encoder.encode(msg)
        let text = String(data: data, encoding: .utf8)!

        XCTAssertTrue(text.contains("\"type\":\"handshake\""))
        XCTAssertTrue(text.contains("\"app_token\":\"test-token\""))
    }

    func testFlowStartIssuanceEncoding() throws {
        let msg = FlowStartMessage(
            protocol: "oid4vci",
            offer: "offer-json",
            credentialOfferUri: "https://issuer.example.com/offer",
            redirectUri: "app://callback"
        )
        let data = try encoder.encode(msg)
        let text = String(data: data, encoding: .utf8)!

        XCTAssertTrue(text.contains("\"type\":\"flow_start\""))
        XCTAssertTrue(text.contains("\"protocol\":\"oid4vci\""))
        XCTAssertTrue(text.contains("\"offer\":\"offer-json\""))
        XCTAssertTrue(text.contains("credential_offer_uri"))
        XCTAssertTrue(text.contains("issuer.example.com"))
        XCTAssertTrue(text.contains("redirect_uri"))
    }

    func testFlowStartPresentationEncoding() throws {
        let msg = FlowStartMessage(
            protocol: "oid4vp",
            requestUri: "https://verifier.example.com/request",
            requestUriRef: "urn:request:1"
        )
        let data = try encoder.encode(msg)
        let text = String(data: data, encoding: .utf8)!

        XCTAssertTrue(text.contains("\"protocol\":\"oid4vp\""))
        XCTAssertTrue(text.contains("request_uri"))
        XCTAssertTrue(text.contains("verifier.example.com"))
        XCTAssertTrue(text.contains("\"request_uri_ref\":\"urn:request:1\""))
    }

    func testSignResponseEncoding() throws {
        let msg = SignResponseMessage(
            flowId: "flow-77",
            proofJwt: "proof-jwt",
            vpToken: "vp-token",
            proofs: [ProofObject(proofType: "jwt", jwt: "nested-proof")]
        )
        let data = try encoder.encode(msg)
        let text = String(data: data, encoding: .utf8)!

        XCTAssertTrue(text.contains("\"type\":\"sign_response\""))
        XCTAssertTrue(text.contains("\"flow_id\":\"flow-77\""))
        XCTAssertTrue(text.contains("\"proof_jwt\":\"proof-jwt\""))
        XCTAssertTrue(text.contains("\"vp_token\":\"vp-token\""))
        XCTAssertTrue(text.contains("\"proof_type\":\"jwt\""))
    }

    func testMatchResponseEncoding() throws {
        let msg = MatchResponseMessage(
            flowId: "flow-88",
            matches: [
                CredentialMatch(
                    credentialQueryId: "query-1",
                    credentialId: "cred-1",
                    format: "dc+sd-jwt",
                    vct: "urn:eu:pid:1",
                    availableClaims: ["given_name", "family_name"]
                ),
            ]
        )
        let data = try encoder.encode(msg)
        let text = String(data: data, encoding: .utf8)!

        XCTAssertTrue(text.contains("\"type\":\"match_response\""))
        XCTAssertTrue(text.contains("\"flow_id\":\"flow-88\""))
        XCTAssertTrue(text.contains("\"credential_query_id\":\"query-1\""))
        XCTAssertTrue(text.contains("\"credential_id\":\"cred-1\""))
    }

    func testFlowActionEncoding() throws {
        let msg = FlowActionMessage(
            flowId: "flow-77",
            action: "trust_result",
            payload: ["trusted": .bool(true), "reason": "verified"]
        )
        let data = try encoder.encode(msg)
        let text = String(data: data, encoding: .utf8)!

        XCTAssertTrue(text.contains("\"type\":\"flow_action\""))
        XCTAssertTrue(text.contains("\"flow_id\":\"flow-77\""))
        XCTAssertTrue(text.contains("\"action\":\"trust_result\""))
        XCTAssertTrue(text.contains("\"trusted\":true"))
        XCTAssertTrue(text.contains("\"reason\":\"verified\""))
    }

    func testHandshakeCompleteDecoding() throws {
        let json = """
        {"type":"handshake_complete","session_id":"session-123","capabilities":["oid4vci","oid4vp"]}
        """
        let msg = try decoder.decode(HandshakeCompleteMessage.self, from: json.data(using: .utf8)!)
        XCTAssertEqual(msg.sessionId, "session-123")
        XCTAssertEqual(msg.capabilities, ["oid4vci", "oid4vp"])
    }

    func testFlowProgressDecoding() throws {
        let json = """
        {"type":"flow_progress","flow_id":"flow-1","step":"issuing","payload":{"percent":50}}
        """
        let msg = try decoder.decode(FlowProgressMessage.self, from: json.data(using: .utf8)!)
        XCTAssertEqual(msg.flowId, "flow-1")
        XCTAssertEqual(msg.step, "issuing")
    }

    func testFlowCompleteDecoding() throws {
        let json = """
        {"type":"flow_complete","flow_id":"flow-1","redirect_uri":"https://wallet.example.com/callback","credentials":[{"format":"dc+sd-jwt","credential":"jwt-token","vct":"urn:eu:pid:1"}]}
        """
        let msg = try decoder.decode(FlowCompleteMessage.self, from: json.data(using: .utf8)!)
        XCTAssertEqual(msg.flowId, "flow-1")
        XCTAssertEqual(msg.redirectUri, "https://wallet.example.com/callback")
        XCTAssertEqual(msg.credentials?.first?.credential, "jwt-token")
    }

    func testFlowErrorDecoding() throws {
        let json = """
        {"type":"flow_error","flow_id":"flow-1","step":"authorize","error":{"code":"invalid_request","message":"missing parameter"}}
        """
        let msg = try decoder.decode(FlowErrorMessage.self, from: json.data(using: .utf8)!)
        XCTAssertEqual(msg.flowId, "flow-1")
        XCTAssertEqual(msg.error.code, "invalid_request")
        XCTAssertEqual(msg.error.message, "missing parameter")
    }

    func testSignRequestDecoding() throws {
        let json = """
        {"type":"sign_request","flow_id":"flow-1","action":"proof","params":{"audience":"aud","nonce":"nonce","proof_type":"jwt"}}
        """
        let msg = try decoder.decode(SignRequestMessage.self, from: json.data(using: .utf8)!)
        XCTAssertEqual(msg.flowId, "flow-1")
        XCTAssertEqual(msg.action, "proof")
        XCTAssertEqual(msg.params.audience, "aud")
        XCTAssertEqual(msg.params.proofType, "jwt")
    }

    func testMatchRequestDecoding() throws {
        let json = """
        {"type":"match_request","flow_id":"flow-1","dcql_query":{"credentials":[{"id":"q-1"}]}}
        """
        let msg = try decoder.decode(MatchRequestMessage.self, from: json.data(using: .utf8)!)
        XCTAssertEqual(msg.flowId, "flow-1")
        XCTAssertNotNil(msg.dcqlQuery)
    }

    func testPushMessageDecoding() throws {
        let json = """
        {"type":"push","push_type":"issuance_complete","credentials":[{"format":"dc+sd-jwt","credential":"jwt-token","vct":"urn:eu:pid:1"}]}
        """
        let msg = try decoder.decode(PushMessage.self, from: json.data(using: .utf8)!)
        XCTAssertEqual(msg.pushType, "issuance_complete")
        XCTAssertEqual(msg.credentials?.first?.credential, "jwt-token")
    }

    func testErrorMessageDecoding() throws {
        let json = """
        {"type":"error","code":"bad_request","message":"invalid flow"}
        """
        let msg = try decoder.decode(ErrorMessage.self, from: json.data(using: .utf8)!)
        XCTAssertEqual(msg.code, "bad_request")
        XCTAssertEqual(msg.details, "invalid flow")
    }

    func testCredentialNotificationEncoding() throws {
        let msg = CredentialNotificationMessage(
            flowId: "flow-1",
            notificationId: "notif-abc",
            event: CredentialNotificationEvent.accepted,
            eventDescription: "stored",
            timestamp: "2026-06-22T00:00:00Z"
        )
        let data = try encoder.encode(msg)
        let text = String(data: data, encoding: .utf8)!

        XCTAssertTrue(text.contains("\"type\":\"credential_notification\""))
        XCTAssertTrue(text.contains("\"flow_id\":\"flow-1\""))
        XCTAssertTrue(text.contains("\"notification_id\":\"notif-abc\""))
        XCTAssertTrue(text.contains("\"event\":\"credential_accepted\""))
        XCTAssertTrue(text.contains("\"event_description\":\"stored\""))
    }

    func testCredentialNotificationOmitsOptionalDescription() throws {
        let msg = CredentialNotificationMessage(
            flowId: "flow-1",
            notificationId: "notif-abc",
            event: CredentialNotificationEvent.failure
        )
        let data = try encoder.encode(msg)
        let text = String(data: data, encoding: .utf8)!

        XCTAssertTrue(text.contains("\"event\":\"credential_failure\""))
        XCTAssertFalse(text.contains("event_description"))
    }

    func testNotificationAckDecoding() throws {
        let json = """
        {"type":"notification_ack","flow_id":"flow-1","notification_id":"notif-abc","status":"forwarded"}
        """
        let msg = try decoder.decode(NotificationAckMessage.self, from: json.data(using: .utf8)!)
        XCTAssertEqual(msg.type, "notification_ack")
        XCTAssertEqual(msg.flowId, "flow-1")
        XCTAssertEqual(msg.notificationId, "notif-abc")
        XCTAssertEqual(msg.status, "forwarded")
        XCTAssertNil(msg.error)
    }

    func testCredentialResultNotificationIdRoundtrip() throws {
        let json = """
        {"format":"dc+sd-jwt","credential":"jwt-token","vct":"urn:eu:pid:1","notification_id":"notif-xyz"}
        """
        let result = try decoder.decode(CredentialResult.self, from: json.data(using: .utf8)!)
        XCTAssertEqual(result.notificationId, "notif-xyz")

        let data = try encoder.encode(result)
        let text = String(data: data, encoding: .utf8)!
        XCTAssertTrue(text.contains("\"notification_id\":\"notif-xyz\""))
    }

    func testCredentialResultOmitsNilNotificationId() throws {
        let json = """
        {"format":"dc+sd-jwt","credential":"jwt-token","vct":"urn:eu:pid:1"}
        """
        let result = try decoder.decode(CredentialResult.self, from: json.data(using: .utf8)!)
        XCTAssertNil(result.notificationId)

        let data = try encoder.encode(result)
        let text = String(data: data, encoding: .utf8)!
        XCTAssertFalse(text.contains("notification_id"))
    }
}

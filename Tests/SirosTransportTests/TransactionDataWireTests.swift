// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosTransport

/// EC TS12 wire plumbing: the members the orchestrator sends and the
/// declaration the SDK makes. Golden raw strings come from the independent
/// vectors in leifj/wmp `vectors/openid4x/transaction-data-hashes.json`.
final class TransactionDataWireTests: XCTestCase {
    private let raw = "eyJ0eXBlIjoidXJuOmV1ZGk6c2NhOnBheW1lbnQ6MSIsImNyZWRlbnRpYWxfaWRzIjpbInBheSJdLCJwYXlsb2FkIjp7InRyYW5zYWN0aW9uX2lkIjoidHgtMDAwMSJ9fQ"

    func testEngineSignRequestParamsCarryRawPayloadAlgsAndResponseMode() throws {
        let json = """
        {"audience":"x","nonce":"n","response_mode":"direct_post.jwt",
         "credentials_to_include":[{"credential_query_id":"pay","credential_id":"1"}],
         "transaction_data":[{"raw":"\(raw)","type":"urn:eudi:sca:payment:1",
            "credential_ids":["pay"],"payload":{"transaction_id":"tx-0001"},
            "transaction_data_hashes_alg":["sha-256","sha-384"]}]}
        """
        let p = try JSONDecoder().decode(SignRequestParams.self, from: Data(json.utf8))
        XCTAssertEqual(p.responseMode, "direct_post.jwt")
        let td = try XCTUnwrap(p.transactionData?.first)
        XCTAssertEqual(td.raw, raw)
        XCTAssertEqual(td.type, "urn:eudi:sca:payment:1")
        XCTAssertEqual(td.credentialIds, ["pay"])
        XCTAssertEqual(td.hashesAlg, ["sha-256", "sha-384"])
        XCTAssertEqual(td.payload?.objectValue?["transaction_id"]?.stringValue, "tx-0001")
        XCTAssertEqual(p.credentialsToInclude?.first?.credentialQueryId, "pay")
    }

    func testBareStringHashAlgIsToleratedOnInput() throws {
        let json = #"{"type":"t","raw":"abc","transaction_data_hashes_alg":"sha-384"}"#
        let td = try JSONDecoder().decode(TransactionData.self, from: Data(json.utf8))
        XCTAssertEqual(td.hashesAlg, ["sha-384"])
    }

    func testAbsentOptionalMembersStayNil() throws {
        let td = try JSONDecoder().decode(TransactionData.self, from: Data(#"{"type":"t"}"#.utf8))
        XCTAssertNil(td.raw)
        XCTAssertNil(td.payload)
        XCTAssertNil(td.hashesAlg)
    }

    func testWmpSignSubFlowParamsCarryTheSameMembers() throws {
        let json = """
        {"action":"sign_presentation","nonce":"n","audience":"a","response_mode":"dc_api",
         "verifier_session_id":"vs-1",
         "credentials_to_include":[{"credential_query_id":"pay","credential_id":"7"}],
         "transaction_data":[{"raw":"\(raw)","type":"urn:eudi:sca:payment:1",
            "transaction_data_hashes_alg":["sha-512"]}]}
        """
        let p = try JSONDecoder().decode(SignSubFlowParams.self, from: Data(json.utf8))
        XCTAssertEqual(p.responseMode, "dc_api")
        XCTAssertEqual(p.verifierSessionId, "vs-1")
        XCTAssertEqual(p.credentialsToInclude?.first?.credentialId, "7")
        XCTAssertEqual(p.transactionData?.first?.raw, raw)
        XCTAssertEqual(p.transactionData?.first?.hashesAlg, ["sha-512"])
    }

    /// Presence is kept: absent, null and empty are different.
    func testTransactionDataMemberPresenceIsPreserved() throws {
        func engine(_ extra: String) throws -> SignRequestParams {
            try JSONDecoder().decode(SignRequestParams.self, from: Data(#"{"audience":"a"\#(extra)}"#.utf8))
        }
        func wmp(_ extra: String) throws -> SignSubFlowParams {
            try JSONDecoder().decode(SignSubFlowParams.self, from: Data(#"{"action":"sign_presentation"\#(extra)}"#.utf8))
        }
        XCTAssertFalse(try engine("").transactionDataMember.requestsTransactionHandling)
        XCTAssertFalse(try engine(#","transaction_data":[]"#).transactionDataMember.requestsTransactionHandling)
        XCTAssertTrue(try engine(#","transaction_data":null"#).transactionDataMember.isExplicitNull)
        XCTAssertTrue(try engine(#","transaction_data":null"#).transactionDataMember.requestsTransactionHandling)
        XCTAssertTrue(try engine(#","transaction_data":[{"type":"t"}]"#).transactionDataMember.requestsTransactionHandling)
        XCTAssertFalse(try wmp("").transactionDataMember.requestsTransactionHandling)
        XCTAssertTrue(try wmp(#","transaction_data":null"#).transactionDataMember.requestsTransactionHandling)
        XCTAssertFalse(try wmp(#","transaction_data":[]"#).transactionDataMember.requestsTransactionHandling)
        // Encoding keeps it too: absent is omitted, null stays null.
        let absent = String(decoding: try JSONEncoder().encode(try engine("")), as: UTF8.self)
        XCTAssertFalse(absent.contains("transaction_data"))
        let null = String(decoding: try JSONEncoder().encode(try engine(#","transaction_data":null"#)), as: UTF8.self)
        XCTAssertTrue(null.contains(#""transaction_data":null"#))
    }

    func testSignRequestWithoutTransactionDataIsUnchanged() throws {
        let p = try JSONDecoder().decode(SignRequestParams.self, from: Data(#"{"audience":"a","nonce":"n"}"#.utf8))
        XCTAssertNil(p.transactionData)
        XCTAssertNil(p.responseMode)
    }

    // MARK: - Declaration

    func testFlowStartOmitsFeaturesUnlessDeclared() throws {
        let plain = try JSONEncoder().encode(FlowStartMessage(protocol: "oid4vp", requestUri: "u"))
        XCTAssertFalse(String(decoding: plain, as: UTF8.self).contains("features"))
        let empty = try JSONEncoder().encode(FlowStartMessage(protocol: "oid4vp", requestUri: "u", features: []))
        XCTAssertFalse(String(decoding: empty, as: UTF8.self).contains("features"))

        let declared = try JSONEncoder().encode(
            FlowStartMessage(protocol: "oid4vp", requestUri: "u", features: TransactionDataDeclaration.engineFeatures(enabled: true))
        )
        let obj = try XCTUnwrap(JSONSerialization.jsonObject(with: declared) as? [String: Any])
        XCTAssertEqual(obj["features"] as? [String], ["transaction_data.v1"])
    }

    func testEngineFeaturesOnlyWhenEnabled() {
        XCTAssertNil(TransactionDataDeclaration.engineFeatures(enabled: false))
        XCTAssertEqual(TransactionDataDeclaration.engineFeatures(enabled: true), ["transaction_data.v1"])
    }

    func testWmpCapabilityShape() throws {
        XCTAssertNil(TransactionDataDeclaration.wmpCapabilitiesOffered(enabled: false))
        let caps = try XCTUnwrap(TransactionDataDeclaration.wmpCapabilitiesOffered(enabled: true))
        let data = try JSONEncoder().encode(caps)
        let obj = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let cap = try XCTUnwrap(obj["transaction_data"] as? [String: Any])
        XCTAssertEqual(cap["versions"] as? [Int], [1])
        XCTAssertEqual(cap["hash_algs"] as? [String], ["sha-256", "sha-384", "sha-512"])
    }

    func testSessionCreateSendsOfferedCapabilitiesOnlyWhenGiven() async throws {
        for offered in [false, true] {
            let transport = FakeTransport()
            let session = WmpSession(transport: transport, config: WmpSessionConfig(requestTimeoutMs: 2_000))
            let task = Task {
                try await session.create(
                    authToken: "t",
                    capabilitiesOffered: TransactionDataDeclaration.wmpCapabilitiesOffered(enabled: offered)
                )
            }
            let deadline = Date().addingTimeInterval(2)
            while transport.sentMessages.isEmpty, Date() < deadline { try await Task.sleep(nanoseconds: 10_000_000) }
            let sent = try XCTUnwrap(transport.sentMessages.last)
            let text = String(decoding: sent, as: UTF8.self)
            XCTAssertEqual(text.contains("capabilities_offered"), offered)
            XCTAssertEqual(text.contains("\"transaction_data\""), offered)
            let req = try WmpCodec().decodeRequest(sent)
            transport.receiveFromServer(Data("""
            {"jsonrpc":"2.0","id":"\(req.id!)","result":{"wmp":{"version":"0.1","session_id":"s"},"resumption_token":"r"}}
            """.utf8))
            try await task.value
            try await session.close()
        }
    }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosTransport

final class WmpCodecTests: XCTestCase {
    private let codec = WmpCodec()

    func testEncodeRequestProducesValidJsonRpc2() throws {
        let params: [String: AnyCodable] = ["key": "value"]
        let bytes = try codec.encodeRequest(method: "wmp.session.create", params: params, id: "test-id")
        let text = String(data: bytes, encoding: .utf8)!

        XCTAssertTrue(text.contains("\"jsonrpc\":\"2.0\""))
        XCTAssertTrue(text.contains("\"method\":\"wmp.session.create\""))
        XCTAssertTrue(text.contains("\"id\":\"test-id\""))
        XCTAssertTrue(text.contains("\"key\":\"value\""))
    }

    func testEncodeNotificationOmitsId() throws {
        let bytes = try codec.encodeNotification(method: "wmp.session.close")
        let decoded = try codec.decodeRequest(bytes)
        XCTAssertNil(decoded.id)
        XCTAssertEqual(decoded.method, "wmp.session.close")
    }

    func testDecodeMessageIdentifiesResponse() throws {
        let json = """
        {"jsonrpc":"2.0","id":"req-1","result":{"wmp":{"version":"0.1","session_id":"ses-123"}}}
        """
        let message = try codec.decodeMessage(json.data(using: .utf8)!)

        guard case .response(let response) = message else {
            XCTFail("Expected response")
            return
        }
        XCTAssertEqual(response.id, "req-1")
        XCTAssertNotNil(response.result)
    }

    func testDecodeMessageIdentifiesNotification() throws {
        let json = """
        {"jsonrpc":"2.0","method":"wmp.flow.progress","params":{"wmp":{"version":"0.1"}}}
        """
        let message = try codec.decodeMessage(json.data(using: .utf8)!)

        guard case .notification(let notification) = message else {
            XCTFail("Expected notification")
            return
        }
        XCTAssertEqual(notification.method, "wmp.flow.progress")
    }

    func testDecodeMessageIdentifiesRequestWithId() throws {
        let json = """
        {"jsonrpc":"2.0","id":"req-2","method":"wmp.flow.action","params":{}}
        """
        let message = try codec.decodeMessage(json.data(using: .utf8)!)

        guard case .request(let request) = message else {
            XCTFail("Expected request")
            return
        }
        XCTAssertEqual(request.id, "req-2")
        XCTAssertEqual(request.method, "wmp.flow.action")
    }

    func testDecodeResponseHandlesError() throws {
        let json = """
        {"jsonrpc":"2.0","id":"req-1","error":{"code":-31000,"message":"Session not found"}}
        """
        let response = try codec.decodeResponse(json.data(using: .utf8)!)

        XCTAssertNotNil(response.error)
        XCTAssertEqual(response.error?.code, -31000)
        XCTAssertEqual(response.error?.message, "Session not found")
    }

    func testEncodeParamsSerializesSessionCreateParams() throws {
        let params = SessionCreateParams(
            wmp: WmpMeta(sender: "test-sender"),
            ttl: 3600,
            auth: SessionAuth(type: "bearer", token: "test-token")
        )
        let jsonObj = try codec.encodeParams(params)

        XCTAssertNotNil(jsonObj["wmp"])
        XCTAssertNotNil(jsonObj["auth"])
        XCTAssertNotNil(jsonObj["ttl"])
    }
}

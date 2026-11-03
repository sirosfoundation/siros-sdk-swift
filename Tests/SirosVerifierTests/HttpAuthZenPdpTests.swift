// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
@testable import SirosVerifier

final class AuthZenMockURLProtocol: URLProtocol {
    enum Behaviour {
        case http(status: Int, body: Data)
        case nonHTTP
        case failure(URLError)
    }

    nonisolated(unsafe) private static var behaviour = Behaviour.http(status: 200, body: Data())
    nonisolated(unsafe) private static var seen: [URLRequest] = []
    private static let lock = NSLock()

    static func reset(_ newBehaviour: Behaviour) {
        lock.lock()
        behaviour = newBehaviour
        seen = []
        lock.unlock()
    }

    static var requests: [URLRequest] {
        lock.lock()
        defer { lock.unlock() }
        return seen
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func stopLoading() {}

    override func startLoading() {
        Self.lock.lock()
        Self.seen.append(request)
        let current = Self.behaviour
        Self.lock.unlock()

        switch current {
        case .http(let status, let body):
            let response = HTTPURLResponse(
                url: request.url!,
                statusCode: status,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json"]
            )!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: body)
            client?.urlProtocolDidFinishLoading(self)
        case .nonHTTP:
            let response = URLResponse(
                url: request.url!,
                mimeType: "application/json",
                expectedContentLength: 0,
                textEncodingName: "utf-8"
            )
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocolDidFinishLoading(self)
        case .failure(let error):
            client?.urlProtocol(self, didFailWithError: error)
        }
    }
}

final class HttpAuthZenPdpTests: XCTestCase {
    private let endpoint = URL(string: "https://pdp.example/custom/evaluate?version=1")!

    private func makeClient(
        tenantId: String = "verifier-tenant",
        additionalHeaders: [String: String]? = nil
    ) -> HttpAuthZenPdp {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [AuthZenMockURLProtocol.self]
        configuration.httpAdditionalHeaders = additionalHeaders
        let session = URLSession(configuration: configuration)
        return HttpAuthZenPdp(evaluationEndpoint: endpoint, tenantId: tenantId, session: session)
    }

    func testPermitPostsExactUTF8BodyToCompleteEndpointWithoutCredentials() async throws {
        AuthZenMockURLProtocol.reset(.http(status: 200, body: Data(#"{"decision":true,"context":{"ok":1}}"#.utf8)))
        let requestJSON = "{ \"subject\" : \"κ\", \n \"action\" : [] }"
        // Even a deliberately contaminated injected session must not turn this
        // standalone verifier call into an authenticated wallet request.
        let client = makeClient(additionalHeaders: [
            "Authorization": "Bearer wallet-token",
            "Cookie": "wallet-session=secret",
        ])

        let result = try await client.evaluate(requestJSON: requestJSON)

        XCTAssertTrue(result)
        let request = try XCTUnwrap(AuthZenMockURLProtocol.requests.only)
        XCTAssertEqual(request.url, endpoint)
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.authZenBodyData, Data(requestJSON.utf8))
        XCTAssertEqual(request.value(forHTTPHeaderField: "X-Tenant-ID"), "verifier-tenant")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
        XCTAssertNil(request.value(forHTTPHeaderField: "Authorization"))
        XCTAssertNil(request.value(forHTTPHeaderField: "Cookie"))
    }

    func testEvery2xxPermitIsAccepted() async throws {
        for status in [200, 201, 202, 299] {
            AuthZenMockURLProtocol.reset(.http(status: status, body: Data("{\"decision\":true}".utf8)))
            let result = try await makeClient().evaluate(requestJSON: "{}")
            XCTAssertTrue(result)
        }
    }

    func testExplicitFalseThrowsDeny() async {
        AuthZenMockURLProtocol.reset(.http(status: 200, body: Data("{\"decision\":false}".utf8)))
        do {
            _ = try await makeClient().evaluate(requestJSON: "{}")
            XCTFail("explicit deny must not permit or fall back locally")
        } catch AuthZenPdpError.denied {
            // Expected.
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testMalformedMissingNonBooleanAndDuplicateResponsesAreRejected() async {
        let invalid = [
            "",
            "{",
            "null",
            "[]",
            "true",
            "{}",
            #"{"decision":null}"#,
            #"{"decision":1}"#,
            #"{"decision":"true"}"#,
            #"{"decision":true} trailing"#,
            #"{"decision":true,"decision":true}"#,
            #"{"decision":false,"decision":true}"#,
            #"{"decision":true,"context":{"x":1,"x":2}}"#,
            #"{"\u0064ecision":true,"decision":false}"#,
            #"{"decision":tru}"#,
            #"{"decision":true,}"#,
        ]
        for body in invalid {
            AuthZenMockURLProtocol.reset(.http(status: 200, body: Data(body.utf8)))
            do {
                _ = try await makeClient().evaluate(requestJSON: "{}")
                XCTFail("invalid response was accepted: \(body)")
            } catch AuthZenPdpError.invalidResponse {
                // Expected: malformed/ambiguous responses never become deny or permit.
            } catch {
                XCTFail("unexpected error for \(body): \(error)")
            }
        }
    }

    func testInvalidUTF8ResponseIsRejected() async {
        AuthZenMockURLProtocol.reset(.http(status: 200, body: Data([0x7B, 0xFF, 0x7D])))
        do {
            _ = try await makeClient().evaluate(requestJSON: "{}")
            XCTFail("invalid UTF-8 was accepted")
        } catch AuthZenPdpError.invalidResponse {
            // Expected.
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testNon2xxThrowsHTTPErrorEvenWhenBodySaysPermit() async {
        for status in [400, 401, 403, 500, 503] {
            AuthZenMockURLProtocol.reset(.http(status: status, body: Data("{\"decision\":true}".utf8)))
            do {
                _ = try await makeClient().evaluate(requestJSON: "{}")
                XCTFail("HTTP \(status) was accepted")
            } catch AuthZenPdpError.http(let statusCode) {
                XCTAssertEqual(statusCode, status)
            } catch {
                XCTFail("unexpected error for HTTP \(status): \(error)")
            }
        }
    }

    func testNetworkOutageThrowsTypedNetworkErrorWithoutFallback() async {
        AuthZenMockURLProtocol.reset(.failure(URLError(.notConnectedToInternet)))
        do {
            _ = try await makeClient().evaluate(requestJSON: "{}")
            XCTFail("outage must not permit or invoke a local trust fallback")
        } catch AuthZenPdpError.network(let underlying) {
            XCTAssertEqual((underlying as? URLError)?.code, .notConnectedToInternet)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        XCTAssertEqual(AuthZenMockURLProtocol.requests.count, 1)
    }

    func testNonHTTPResponseIsAResponseError() async {
        AuthZenMockURLProtocol.reset(.nonHTTP)
        do {
            _ = try await makeClient().evaluate(requestJSON: "{}")
            XCTFail("non-HTTP response was accepted")
        } catch AuthZenPdpError.invalidResponse {
            // Expected.
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testEndpointUserInfoIsRefusedBeforeSendingCredentials() async {
        AuthZenMockURLProtocol.reset(.http(status: 200, body: Data("{\"decision\":true}".utf8)))
        let client = HttpAuthZenPdp(
            endpoint: URL(string: "https://user:password@pdp.example/evaluate")!,
            tenantId: "tenant",
            session: nil
        )
        do {
            _ = try await client.evaluate(requestJSON: "{}")
            XCTFail("URL user-info must never become Authorization")
        } catch AuthZenPdpError.invalidResponse {
            // Expected.
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        XCTAssertTrue(AuthZenMockURLProtocol.requests.isEmpty)
    }
}

private extension Array {
    var only: Element? { count == 1 ? self[0] : nil }
}

private extension URLRequest {
    /// Apple URLSession may move an in-memory body to a stream; Linux commonly
    /// leaves it in httpBody. Compare the bytes through either representation.
    var authZenBodyData: Data? {
        if let httpBody { return httpBody }
        guard let stream = httpBodyStream else { return nil }
        stream.open()
        defer { stream.close() }
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: 4096)
        defer { buffer.deallocate() }
        var data = Data()
        while stream.hasBytesAvailable {
            let count = stream.read(buffer, maxLength: 4096)
            if count < 0 { return nil }
            if count == 0 { break }
            data.append(buffer, count: count)
        }
        return data
    }
}

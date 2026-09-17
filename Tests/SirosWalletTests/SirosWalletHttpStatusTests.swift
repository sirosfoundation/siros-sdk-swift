// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosWallet
import SirosCredentials
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Intercepts `URLSession.shared` so the real transport can be driven with a
/// chosen status and body. Registered globally, which is what reaches
/// `URLSession.shared`.
private final class StubURLProtocol: URLProtocol {
    nonisolated(unsafe) static var status = 200
    nonisolated(unsafe) static var body = Data()

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let response = HTTPURLResponse(
            url: request.url!, statusCode: Self.status, httpVersion: "HTTP/1.1", headerFields: nil
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Self.body)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

/// `SirosWallet.defaultHttpFn` is the transport every client the wallet builds
/// runs over, so the lifecycle protocol - which is expressed entirely in status
/// codes and error bodies - only works if it turns a non-2xx into
/// `SirosError.backendApi` with both preserved. It used to discard the
/// response, which made the blocked-state and erasure-retry paths unreachable
/// in a real app while every unit test - each injecting its own transport -
/// stayed green. These drive the real function, so reverting it fails them.
final class SirosWalletHttpStatusTests: XCTestCase {

    override func setUp() {
        super.setUp()
        URLProtocol.registerClass(StubURLProtocol.self)
    }

    override func tearDown() {
        URLProtocol.unregisterClass(StubURLProtocol.self)
        super.tearDown()
    }

    private func send(status: Int, body: String) async throws -> Data {
        StubURLProtocol.status = status
        StubURLProtocol.body = Data(body.utf8)
        return try await SirosWallet.defaultHttpFn(
            "POST", URL(string: "https://backend.example.invalid/auth/passkey/login/finish")!, [:], nil
        )
    }

    func testSuccessfulResponseIsReturnedUnchanged() async throws {
        let data = try await send(status: 200, body: #"{"uuid":"u"}"#)
        XCTAssertEqual(String(decoding: data, as: UTF8.self), #"{"uuid":"u"}"#)
    }

    /// The case the whole blocked-state path depends on.
    func testLifecycleRefusalArrivesAsBackendApiWithStatusAndBody() async {
        let body = #"{"error":"WALLET_SUSPENDED","message":"This device is suspended"}"#
        do {
            _ = try await send(status: 403, body: body)
            XCTFail("a 403 must not be reported as success")
        } catch let error as SirosError {
            guard case let .backendApi(code, _, carried) = error else {
                return XCTFail("expected .backendApi, got \(error)")
            }
            XCTAssertEqual(code, 403)
            XCTAssertEqual(carried, body, "the body must survive - the refusal code is in it")
            XCTAssertEqual(error.walletLifecycleRefusal, .suspended)
        } catch {
            XCTFail("unexpected \(error)")
        }
    }

    /// The case the erasure retry depends on.
    func testErasureIncompleteArrivesAsBackendApi409() async {
        let body = #"{"error":"ERASURE_INCOMPLETE","revoked":2}"#
        do {
            _ = try await send(status: 409, body: body)
            XCTFail("a 409 must not be reported as success")
        } catch let error as SirosError {
            guard case let .backendApi(code, _, carried) = error else {
                return XCTFail("expected .backendApi, got \(error)")
            }
            XCTAssertEqual(code, 409)
            XCTAssertEqual(carried, body)
        } catch {
            XCTFail("unexpected \(error)")
        }
    }
}

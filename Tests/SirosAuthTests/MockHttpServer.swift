// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosAuth

/// A minimal mock HTTP server for testing BackendApiClient and WebAuthnAuthClient.
/// Queues responses and records received requests.
final class MockHttpServer: @unchecked Sendable {
    struct RecordedRequest: Sendable {
        let method: String
        let path: String
        let headers: [String: String]
        let body: Data?
    }

    private let lock = NSLock()
    private var responses: [Data] = []
    private(set) var requests: [RecordedRequest] = []

    /// Queue a response to return for the next request.
    func enqueue(_ json: String) {
        lock.lock()
        defer { lock.unlock() }
        responses.append(Data(json.utf8))
    }

    /// Queue raw response data.
    func enqueueData(_ data: Data) {
        lock.lock()
        defer { lock.unlock() }
        responses.append(data)
    }

    /// The HTTP function to inject into clients.
    var httpFunction: @Sendable (String, URL, [String: String], Data?) async throws -> Data {
        return { [weak self] method, url, headers, body in
            guard let self else { throw TestError.serverDeallocated }
            self.lock.lock()
            let recorded = RecordedRequest(method: method, path: url.path, headers: headers, body: body)
            self.requests.append(recorded)
            guard !self.responses.isEmpty else {
                self.lock.unlock()
                throw TestError.noResponse
            }
            let response = self.responses.removeFirst()
            self.lock.unlock()
            return response
        }
    }

    /// Simple HTTP post function for WebAuthnAuthClient.
    var httpPost: @Sendable (URL, Data) async throws -> Data {
        return { [weak self] url, body in
            guard let self else { throw TestError.serverDeallocated }
            self.lock.lock()
            let recorded = RecordedRequest(method: "POST", path: url.path, headers: [:], body: body)
            self.requests.append(recorded)
            guard !self.responses.isEmpty else {
                self.lock.unlock()
                throw TestError.noResponse
            }
            let response = self.responses.removeFirst()
            self.lock.unlock()
            return response
        }
    }

    enum TestError: Error {
        case noResponse
        case serverDeallocated
    }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosKeystore

#if canImport(siros_wscd_managerFFI)

/// URLSession-based HTTP transport for R2PS protocol messages.
///
/// Implements the SDK-level `R2psTransportProvider` so the Rust R2PS
/// client can make HTTP requests through the platform's HTTP stack. Real
/// OPAQUE (RFC 9807) PAKE crypto is handled entirely in Rust
/// (`r2ps-client`) - this transport only ever moves opaque request/
/// response bytes, same as any other R2PS protocol message.
final class URLSessionR2psTransport: R2psTransportProvider {

    private let serverUrl: String
    private let session: URLSession

    init(serverUrl: String, session: URLSession = .shared) {
        self.serverUrl = serverUrl
        self.session = session
    }

    func send(body: Data) async throws -> Data {
        guard let url = URL(string: serverUrl) else {
            throw R2psTransportError.invalidUrl(serverUrl)
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        request.httpBody = body

        let (data, response) = try await session.data(for: request)
        if let http = response as? HTTPURLResponse, http.statusCode >= 400 {
            throw R2psTransportError.httpError(http.statusCode)
        }
        return data
    }
}

enum R2psTransportError: Error, LocalizedError {
    case invalidUrl(String)
    case httpError(Int)

    var errorDescription: String? {
        switch self {
        case .invalidUrl(let url): return "Invalid R2PS URL: \(url)"
        case .httpError(let code): return "R2PS HTTP error: \(code)"
        }
    }
}

#endif

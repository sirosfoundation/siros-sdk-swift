// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

#if canImport(SirosWscdFFI)
import SirosWscdFFI

/// URLSession-based HTTP transport for R2PS protocol messages.
///
/// Implements `FfiHttpTransport` so the Rust R2PS client can make HTTP
/// requests through the platform's HTTP stack. The R2PS transport uses a
/// simple request/response pattern over a single endpoint.
final class URLSessionR2psTransport: FfiHttpTransport {

    private let serverUrl: String
    private let session: URLSession

    init(serverUrl: String, session: URLSession = .shared) {
        self.serverUrl = serverUrl
        self.session = session
    }

    func send(body: Data) throws -> Data {
        guard let url = URL(string: serverUrl) else {
            throw R2psTransportError.invalidUrl(serverUrl)
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        request.httpBody = body

        var responseData: Data?
        var responseError: Error?
        let semaphore = DispatchSemaphore(value: 0)

        session.dataTask(with: request) { data, response, error in
            if let error {
                responseError = error
            } else if let http = response as? HTTPURLResponse, http.statusCode >= 400 {
                responseError = R2psTransportError.httpError(http.statusCode)
            } else {
                responseData = data
            }
            semaphore.signal()
        }.resume()
        semaphore.wait()

        if let error = responseError { throw error }
        return responseData ?? Data()
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

/// OPAQUE PAKE client implementation.
///
/// Implements `FfiPakeClient` for OPAQUE (RFC 9807) password-authenticated
/// key exchange. In production, this would use a platform OPAQUE library.
/// For the sample app, we use pass-through stubs compatible with the
/// R2PS dev server's test mode.
final class SamplePakeClient: FfiPakeClient {

    func registrationInit(password: Data) throws -> Data {
        // In production: create OPAQUE RegistrationRequest from password
        return password
    }

    func registrationFinalize(serverResp: Data) throws -> Data {
        // In production: process RegistrationResponse, produce RegistrationRecord
        return serverResp
    }

    func authInit(password: Data) throws -> Data {
        // In production: create OPAQUE KE1 from password
        return password
    }

    func authFinalize(serverResp: Data) throws -> Data {
        // In production: process KE2, produce KE3||session_key
        return serverResp
    }
}

#endif

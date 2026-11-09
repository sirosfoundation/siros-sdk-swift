// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosTransport

/// The LOCAL engine mode's HTTP port: the engine's outgoing fetches over
/// URLSession - the same stack the app already uses for everything else
/// (native TLS, system roots, VPNs).
///
/// The engine's other ports are the SDK's own now: the wallet's asks (the signs,
/// the consent, the match, the tx code, the authorization hand-over) are answered
/// by `WalletEngineAskHandler` inside the SDK and carried by `UniFfiEngineAskHost`,
/// exactly as the remote engine's child flows carry them.
///
/// The trust (`Pdp`) is deliberately absent (nil): the local engine fails closed
/// at the trust step until the app wires a trust stack, exactly as the remote
/// engine does unconfigured - the local mode is not a permissive mode.
#if canImport(EngineAdapterSdk)
import EngineAdapterSdk

// The local engine's HTTP port - the bindings module links where the
// XCFramework ships its slices (Vendor/'s framework), and the gate keeps
// this file compiling where it does not, exactly as the SDK's own
// WmpUniFFITransport gates itself.
final class URLSessionEngineHttp: HttpClient, @unchecked Sendable {
    func send(request: HttpRequest) async throws -> HttpResponse {
        guard let url = URL(string: request.url) else {
            throw EngineAdapterSdk.SdkException.Transport("the engine's fetch URL is invalid")
        }
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = request.method
        urlRequest.httpBody = request.body
        for header in request.headers {
            urlRequest.setValue(header.value, forHTTPHeaderField: header.name)
        }
        // Redirects: the engine declares its policy; URLSession follows them or not.
        let (data, response): (Data, URLResponse)
        if request.redirects != RedirectPolicy.None {
            (data, response) = try await URLSession.shared.data(for: urlRequest)
        } else {
            // The engine's fetches are none-following by policy: a redirect is
            // handed back as-is (the engine decides what a 3xx means to it).
            let session = URLSession(configuration: .ephemeral, delegate: NoneRedirectDelegate(), delegateQueue: nil)
            (data, response) = try await session.data(for: urlRequest)
        }
        guard let http = response as? HTTPURLResponse else {
            throw EngineAdapterSdk.SdkException.Transport("the engine's fetch was not an HTTP response")
        }
        // Bound the body exactly as the engine declared: refuse the response if
        // it exceeded the limit (the engine's own port rule, applied on the
        // app's side of the adapter).
        if UInt64(data.count) > request.maxResponseBytes {
            throw EngineAdapterSdk.SdkException.Transport("response exceeded the engine's declared limit")
        }
        return HttpResponse(
            status: UInt16(http.statusCode),
            body: data
        )
    }
}

/// A delegate that hands redirects back instead of following them (the engine's
/// none-following policy - it sees the 3xx itself).
private final class NoneRedirectDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

#endif

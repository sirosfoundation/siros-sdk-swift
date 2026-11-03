// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// A remote OpenID AuthZEN policy decision point.
///
/// Verifier trust evaluation is standalone: this protocol deliberately has no
/// dependency on a wallet, account, login session, or authentication token.
public protocol AuthZenPdp: Sendable {
    /// Evaluate the supplied AuthZEN request. A `true` result means the PDP
    /// returned an explicit JSON `true` decision. An explicit denial throws
    /// ``AuthZenPdpError/denied``; there is no local trust fallback.
    func evaluate(requestJSON: String) async throws -> Bool
}

/// Fail-closed errors produced by an AuthZEN evaluation.
public enum AuthZenPdpError: Error {
    /// The PDP answered successfully with the explicit decision `false`.
    case denied
    /// The PDP endpoint returned a non-2xx HTTP status.
    case http(statusCode: Int)
    /// The response was not a strict AuthZEN response containing one boolean
    /// top-level `decision`, or the configured endpoint embeds credentials.
    case invalidResponse(String)
    /// The HTTP exchange failed before a response was received.
    case network(underlying: any Error)
}

extension AuthZenPdpError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .denied:
            return "AuthZEN decision was deny"
        case .http(let statusCode):
            return "AuthZEN endpoint returned HTTP \(statusCode)"
        case .invalidResponse(let reason):
            return "Invalid AuthZEN response: \(reason)"
        case .network(let underlying):
            return "AuthZEN network failure: \(underlying.localizedDescription)"
        }
    }
}

extension AuthZenPdpError: LocalizedError {
    public var errorDescription: String? { description }
}

/// URLSession-backed AuthZEN PDP client.
///
/// `evaluationEndpoint` is the COMPLETE evaluation URL. No path or query is
/// appended. The request body is the exact UTF-8 representation of the caller's
/// string; it is never decoded and re-serialized.
public final class HttpAuthZenPdp: AuthZenPdp, @unchecked Sendable {
    private let evaluationEndpoint: URL
    private let tenantId: String
    private let session: URLSession

    /// Create a PDP client. Passing no session creates an ephemeral session
    /// with no cookie jar, credential storage, cache, or additional headers.
    /// A session configuration may be injected for URLProtocol-based tests. It
    /// is copied and scrubbed of cookies, credentials, and auth headers.
    public init(
        evaluationEndpoint: URL,
        tenantId: String,
        session: URLSession? = nil
    ) {
        self.evaluationEndpoint = evaluationEndpoint
        self.tenantId = tenantId
        let configuration = session?.configuration ?? Self.makeEphemeralConfiguration()
        Self.sanitize(configuration)
        self.session = URLSession(configuration: configuration)
    }

    /// Spelling convenience for callers that name the complete URL `endpoint`.
    public convenience init(
        endpoint: URL,
        tenantId: String,
        session: URLSession? = nil
    ) {
        self.init(evaluationEndpoint: endpoint, tenantId: tenantId, session: session)
    }

    public func evaluate(requestJSON: String) async throws -> Bool {
        // URL user-info can turn into HTTP Basic authentication in a URL
        // loading stack. Refuse it rather than ever sending Authorization.
        guard evaluationEndpoint.user == nil, evaluationEndpoint.password == nil else {
            throw AuthZenPdpError.invalidResponse("evaluation endpoint must not contain user-info")
        }

        var request = URLRequest(url: evaluationEndpoint)
        request.httpMethod = "POST"
        request.httpBody = Data(requestJSON.utf8)
        request.httpShouldHandleCookies = false
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(tenantId, forHTTPHeaderField: "X-Tenant-ID")
        // In particular, do not inherit credentials from a caller-supplied
        // session's additional headers.
        request.setValue(nil, forHTTPHeaderField: "Authorization")
        request.setValue(nil, forHTTPHeaderField: "Cookie")

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw AuthZenPdpError.network(underlying: error)
        }

        guard let httpResponse = response as? HTTPURLResponse else {
            throw AuthZenPdpError.invalidResponse("response was not HTTP")
        }
        guard (200..<300).contains(httpResponse.statusCode) else {
            throw AuthZenPdpError.http(statusCode: httpResponse.statusCode)
        }

        let decision = try AuthZenResponseParser.decision(in: data)
        guard decision else { throw AuthZenPdpError.denied }
        return true
    }

    private static func makeEphemeralConfiguration() -> URLSessionConfiguration {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        return configuration
    }

    private static func sanitize(_ configuration: URLSessionConfiguration) {
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.urlCredentialStorage = nil
        configuration.urlCache = nil
        configuration.httpAdditionalHeaders = configuration.httpAdditionalHeaders?.filter { key, _ in
            guard let name = (key as? String)?.lowercased() else { return true }
            return name != "authorization" && name != "cookie"
        }
    }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosAuth
import SirosCredentials

/// The HTTP transports every client this wallet builds runs over.
///
/// Split out of `SirosWallet.swift` purely for size - that file is past
/// SwiftLint's `file_length` limit - but it is a cohesive seam: everything
/// here is a `static` closure that turns a URL into bytes, with no dependency
/// on any instance state.
extension SirosWallet {

    /// Default HTTP POST function using URLSession.
    private static let defaultHttpPost: @Sendable (URL, Data) async throws -> Data = { url, body in
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let (data, _) = try await URLSession.shared.data(for: request)
        return data
    }

    /// Default HTTP function for BackendApiClient.
    // Not `private`: `SirosWallet+Lifecycle.swift` needs it too - same
    // cross-file-extension-access reason as `keystore` above.
    /// The transport every client the wallet builds runs over.
    ///
    /// It MUST turn a non-2xx into `SirosError.backendApi(code:message:body:)`,
    /// exactly as `AuthServerClient`'s and `BackendApiClient`'s own convenience
    /// initialisers do. This used to discard the response (`let (data, _)`), so
    /// every error status reached the caller as a successful body: a `403`
    /// carrying `WALLET_SUSPENDED` was parsed as a login response and became a
    /// generic decoding failure, and a `409 ERASURE_INCOMPLETE` never reached
    /// the retry. The status and the body both have to survive, because the
    /// lifecycle protocol is expressed in them.
    static let defaultHttpFn: @Sendable (String, URL, [String: String], Data?) async throws -> Data = { method, url, headers, body in
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.httpBody = body
        for (k, v) in headers { request.setValue(v, forHTTPHeaderField: k) }
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw SirosError.network(message: "Invalid response")
        }
        guard (200..<300).contains(httpResponse.statusCode) else {
            throw SirosError.backendApi(
                code: httpResponse.statusCode,
                message: "Request failed: \(httpResponse.statusCode)",
                body: String(data: data, encoding: .utf8) ?? ""
            )
        }
        return data
    }

    /// Builds the HTTP GET closure shared by `vctmFetcher`/`mddlSchemaFetcher`.
    ///
    /// Both fetchers' registry-service strategy (Strategy 1: `<registryUrl
    /// >/type-metadata?vct=...`) hits go-wallet-backend's own registry
    /// service, which - like every other backend REST call
    /// (`BackendApiClient.request(_:path:body:)`) - may require an
    /// `Authorization: Bearer` token and always wants the tenant-routing
    /// `X-Tenant-ID` header. Their OTHER two strategies (issuer-direct
    /// `<issuerUrl>/type-metadata/<scope>` and the SD-JWT well-known
    /// `.well-known/vct/...`) hit arbitrary third-party issuer domains -
    /// attaching the wallet's own bearer token/tenant ID there would leak
    /// them to an external party. So headers are attached if and only if the
    /// URL being fetched starts with the resolved registry URL for this
    /// wallet instance - the same prefix `VctmFetcher`/`MddlSchemaFetcher`
    /// construct their registry lookup URL from.
    ///
    /// - Parameter performRequest: the actual network call, isolated behind
    ///   this parameter (default: a real `URLSession.shared.data(for:)` call
    ///   that returns the body only on a 200 response) so
    ///   `SirosWalletRegistryUrlTests` can inject a stub that captures the
    ///   built `URLRequest` - in particular its headers - and assert on
    ///   them directly, without a real network round trip (and without
    ///   needing to construct an `HTTPURLResponse`, which
    ///   swift-corelibs-foundation on Linux has no public initializer for).
    ///   Not `private` for the same `@testable import` access reason.
    static func makeTypeMetadataHttpGet(
        registryUrl: String,
        tenantId: String,
        authTokens: AuthTokens,
        sessionStore: SessionStoreProtocol,
        performRequest: @escaping @Sendable (URLRequest) async -> Data? = { request in
            guard let (data, response) = try? await URLSession.shared.data(for: request),
                  let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                return nil
            }
            return data
        }
    ) -> @Sendable (String) async -> String? {
        { url in
            guard let requestUrl = URL(string: url) else { return nil }
            var request = URLRequest(url: requestUrl)
            request.httpMethod = "GET"

            if url.hasPrefix(registryUrl) {
                request.setValue(tenantId, forHTTPHeaderField: "X-Tenant-ID")
                // Mirrors `BackendApiClient.request(_:path:body:)`'s own
                // auth-token precedence: prefer a live AS-issued backend
                // token, falling back to the legacy plain app-token string
                // (read fresh each call - unlike `authTokens`, this DOES
                // change over the wallet's lifetime, e.g. across
                // login/logout) when no AS session is available.
                if let token = try? await authTokens.ensureBackendToken() {
                    request.setValue("Bearer \(token.raw)", forHTTPHeaderField: "Authorization")
                } else if let appToken = sessionStore.appToken {
                    request.setValue("Bearer \(appToken)", forHTTPHeaderField: "Authorization")
                }
            }

            guard let data = await performRequest(request) else { return nil }
            return String(data: data, encoding: .utf8)
        }
    }
}

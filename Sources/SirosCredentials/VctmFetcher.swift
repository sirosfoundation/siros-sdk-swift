// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(os)
import os
private let logger = Logger(subsystem: "org.siros.sdk", category: "VctmFetcher")
#endif

/// Fetches SD-JWT VC Type Metadata from issuer endpoints.
public final class VctmFetcher: Sendable {
    private let httpGet: (@Sendable (String) async -> String?)?
    private let decoder = JSONDecoder()

    public init(httpGet: (@Sendable (String) async -> String?)? = nil) {
        self.httpGet = httpGet
    }

    public func fetch(
        issuerUrl: String,
        scope: String,
        vct: String? = nil,
        registryUrl: String? = nil
    ) async -> Vctm? {
        // Strategy 1 (authoritative): go-wallet-backend's TS11-backed,
        // cached credential-type registry service - the same one
        // wallet-frontend always queries for VCTM lookups, never the
        // issuer directly. Requires both a registry URL and a known `vct`;
        // when `vct` isn't known yet at this call site (e.g. resolved only
        // after a credential is issued), this strategy simply can't run and
        // falls through to the issuer-direct strategies below, exactly like
        // the well-known strategy already does when `vct` is nil.
        if let registryUrl, let vct {
            if let registryLookupUrl = resolveRegistryUrl(registryUrl, vct: vct) {
                if let result = await fetchFromUrl(registryLookupUrl) {
                    return result
                }
            }
        }

        let baseUrl = issuerUrl.hasSuffix("/")
            ? String(issuerUrl.dropLast())
            : issuerUrl
        let typeMetadataUrl = "\(baseUrl)/type-metadata/\(scope)"

        if let result = await fetchFromUrl(typeMetadataUrl) {
            return result
        }

        if let vct {
            if let wellKnownUrl = resolveWellKnownUrl(vct) {
                if let result = await fetchFromUrl(wellKnownUrl) {
                    return result
                }
            }
        }

        #if canImport(os)
        logger.debug("No VCTM found for scope=\(scope) vct=\(vct ?? "nil")")
        #endif
        return nil
    }

    public func parseVctm(_ jsonString: String) -> Vctm? {
        guard let data = jsonString.data(using: .utf8) else { return nil }
        do {
            return try decoder.decode(Vctm.self, from: data)
        } catch {
            #if canImport(os)
            logger.warning("Failed to parse VCTM JSON: \(error.localizedDescription)")
            #endif
            return nil
        }
    }

    // MARK: - Private

    private func fetchFromUrl(_ url: String) async -> Vctm? {
        do {
            #if canImport(os)
            logger.debug("Fetching VCTM from \(url)")
            #endif
            let body: String?
            if let httpGet {
                body = await httpGet(url)
            } else {
                body = try await fetchWithUrlSession(url)
            }
            guard let body else { return nil }
            return parseVctm(body)
        } catch {
            #if canImport(os)
            logger.debug("VCTM fetch error from \(url): \(error.localizedDescription)")
            #endif
            return nil
        }
    }

    private func fetchWithUrlSession(_ urlString: String) async throws -> String? {
        guard let url = URL(string: urlString) else { return nil }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = 10

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    /// Build a `<registryUrl>/type-metadata?vct=<vct>` lookup URL against
    /// go-wallet-backend's registry service. `vct` is URL-encoded via
    /// `URLComponents` since it's typically itself an `https://` URI.
    /// Confirmed live: the same generic `vct` query param name is used for
    /// BOTH SD-JWT `vct` values and ISO 18013-5 mdoc `doctype` values - one
    /// handler/store serves both formats, a historical naming artifact, not
    /// a bug (see `MddlSchemaFetcher.resolveRegistryUrl`).
    private func resolveRegistryUrl(_ registryUrl: String, vct: String) -> String? {
        let baseUrl = registryUrl.hasSuffix("/")
            ? String(registryUrl.dropLast())
            : registryUrl
        var components = URLComponents(string: "\(baseUrl)/type-metadata")
        components?.queryItems = [URLQueryItem(name: "vct", value: vct)]
        return components?.url?.absoluteString
    }

    private func resolveWellKnownUrl(_ vct: String) -> String? {
        guard let url = URL(string: vct),
              let scheme = url.scheme,
              ["http", "https"].contains(scheme),
              let host = url.host else {
            return nil
        }
        let path = url.path.hasPrefix("/") ? String(url.path.dropFirst()) : url.path
        guard !path.isEmpty else { return nil }
        let port = url.port.map { ":\($0)" } ?? ""
        return "\(scheme)://\(host)\(port)/.well-known/vct/\(path)"
    }
}

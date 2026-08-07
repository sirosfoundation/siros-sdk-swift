// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(os)
import os
private let logger = Logger(subsystem: "org.siros.sdk", category: "MddlSchemaFetcher")
#endif

/// Fetches MDDL (mso_mdoc) schema documents from credential issuers - the
/// mdoc analogue of `VctmFetcher`, against the same `/type-metadata/<scope>`
/// relay (confirmed format-blind server-side: `go-wallet-backend`'s registry
/// relay has no format/`mso_mdoc` branching, so it serves whatever document
/// shape it's given unchanged - same mechanism, no new backend endpoint).
public final class MddlSchemaFetcher: Sendable {
    private let httpGet: (@Sendable (String) async -> String?)?
    private let decoder = JSONDecoder()

    public init(httpGet: (@Sendable (String) async -> String?)? = nil) {
        self.httpGet = httpGet
    }

    /// Fetch the MDDL schema for a credential configuration.
    ///
    /// - Parameters:
    ///   - issuerUrl: the credential issuer URL (e.g. "https://issuer.example.com")
    ///   - scope: the credential configuration ID / scope
    ///   - doctype: the ISO 18013-5 mdoc `doctype` this configuration issues,
    ///     when already known (unlike some SD-JWT `vct` cases, this is
    ///     normally known upfront from issuer metadata, so callers should
    ///     pass it whenever available). Used for the registry-service
    ///     strategy below.
    ///   - registryUrl: go-wallet-backend's credential-type registry service
    ///     base URL (e.g. `<backendUrl>/registry`). When non-nil and
    ///     `doctype` is known, tried first as the authoritative, TS11-backed
    ///     source, before falling back to the issuer-direct strategy.
    /// - Returns: the parsed `MddlSchema`, or nil if not available
    public func fetch(
        issuerUrl: String,
        scope: String,
        doctype: String? = nil,
        registryUrl: String? = nil
    ) async -> MddlSchema? {
        // Strategy 1 (authoritative): go-wallet-backend's TS11-backed,
        // cached credential-type registry service - the mdoc analogue of
        // `VctmFetcher`'s identical registry strategy. mdoc doctypes are
        // normally known upfront, so this should virtually always be
        // attempted when a `registryUrl` is configured.
        if let registryUrl, let doctype {
            if let registryLookupUrl = resolveRegistryUrl(registryUrl, doctype: doctype) {
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

        #if canImport(os)
        logger.debug("No MDDL schema found for scope=\(scope)")
        #endif
        return nil
    }

    /// Parse an MDDL schema from raw JSON, e.g. if embedded in an issuer metadata response.
    public func parseMddlSchema(_ jsonString: String) -> MddlSchema? {
        guard let data = jsonString.data(using: .utf8) else { return nil }
        do {
            return try decoder.decode(MddlSchema.self, from: data)
        } catch {
            #if canImport(os)
            logger.warning("Failed to parse MDDL schema JSON: \(error.localizedDescription)")
            #endif
            return nil
        }
    }

    // MARK: - Private

    /// Build a `<registryUrl>/type-metadata?vct=<doctype>` lookup URL
    /// against go-wallet-backend's registry service. The query param is
    /// named `vct`, not `doctype`, on purpose: confirmed live, the backend's
    /// single handler/store uses the same generic `vct` param name for both
    /// SD-JWT `vct` values and ISO 18013-5 mdoc `doctype` values - a
    /// historical naming artifact, not a bug (see
    /// `VctmFetcher.resolveRegistryUrl`).
    private func resolveRegistryUrl(_ registryUrl: String, doctype: String) -> String? {
        let baseUrl = registryUrl.hasSuffix("/")
            ? String(registryUrl.dropLast())
            : registryUrl
        var components = URLComponents(string: "\(baseUrl)/type-metadata")
        components?.queryItems = [URLQueryItem(name: "vct", value: doctype)]
        return components?.url?.absoluteString
    }

    private func fetchFromUrl(_ url: String) async -> MddlSchema? {
        do {
            #if canImport(os)
            logger.debug("Fetching MDDL schema from \(url)")
            #endif
            let body: String?
            if let httpGet {
                body = await httpGet(url)
            } else {
                body = try await fetchWithUrlSession(url)
            }
            guard let body else { return nil }
            return parseMddlSchema(body)
        } catch {
            #if canImport(os)
            logger.debug("MDDL schema fetch error from \(url): \(error.localizedDescription)")
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
}

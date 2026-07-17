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
        vct: String? = nil
    ) async -> Vctm? {
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

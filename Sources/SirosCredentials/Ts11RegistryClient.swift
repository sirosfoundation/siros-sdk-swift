// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(os)
import os
private let logger = Logger(subsystem: "org.siros.sdk", category: "Ts11RegistryClient")
#endif

/// A single format-specific URI within a `Ts11SchemaMeta` entry, e.g. the
/// `sd-jwt` VCTM location or the `mso_mdoc` MDDL location for the same
/// logical credential type. Mirrors `TS11SchemaURI` in
/// `go-wallet-backend/internal/registry/fetcher.go` and Kotlin's
/// `Ts11SchemaUri`.
public struct Ts11SchemaUri: Codable, Sendable, Equatable {
    public let formatIdentifier: String
    public let uri: String

    public init(formatIdentifier: String, uri: String) {
        self.formatIdentifier = formatIdentifier
        self.uri = uri
    }
}

/// Metadata for a single credential-type schema entry from a TS11 registry
/// (`registry.siros.org` or a compatible source), mirroring `TS11SchemaMeta`
/// in `go-wallet-backend/internal/registry/fetcher.go` (and Kotlin's
/// `Ts11SchemaMeta`) field-for-field.
///
/// - `id`: the schema's registry identifier (not necessarily the same as
///   the credential's own `vct`/`doctype` - that authoritative identifier
///   lives inside the fetched VCTM/MDDL document itself; see `VctmFetcher`/
///   `MddlSchemaFetcher` for resolving the actual document once a
///   `schemaURIs` entry is chosen).
/// - `attestationLoS`: the minimum key-storage assurance tier this
///   credential type requires, in the same ISO 18045 vocabulary as
///   `Vctm.requiredKeyStorage`/`MddlSchema.requiredKeyStorage`
///   (`"iso_18045_basic"`/`"iso_18045_moderate"`/`"iso_18045_high"`).
///   Exposed here, unparsed/uninterpreted, so a later caller can compare it
///   against `WscdPluginCapabilities`'s tier table - this type does not do
///   that comparison itself.
/// - `bindingType`: the credential's key-binding mechanism (e.g. `"jwk"`,
///   `"cose_key"`) as declared by the registry.
/// - `supportedFormats`: the credential formats this schema supports (e.g.
///   `"dc+sd-jwt"`, `"mso_mdoc"`).
/// - `schemaURIs`: the format-specific document locations for this schema;
///   empty when the registry hasn't published any yet.
public struct Ts11SchemaMeta: Sendable, Equatable {
    public let id: String
    public let version: String?
    public let attestationLoS: String?
    public let bindingType: String?
    public let supportedFormats: [String]
    public let schemaURIs: [Ts11SchemaUri]
    public let rulebookURI: String?
    public let trustedAuthorities: [String]?

    public init(
        id: String,
        version: String? = nil,
        attestationLoS: String? = nil,
        bindingType: String? = nil,
        supportedFormats: [String] = [],
        schemaURIs: [Ts11SchemaUri] = [],
        rulebookURI: String? = nil,
        trustedAuthorities: [String]? = nil
    ) {
        self.id = id
        self.version = version
        self.attestationLoS = attestationLoS
        self.bindingType = bindingType
        self.supportedFormats = supportedFormats
        self.schemaURIs = schemaURIs
        self.rulebookURI = rulebookURI
        self.trustedAuthorities = trustedAuthorities
    }
}

extension Ts11SchemaMeta: Codable {
    enum CodingKeys: String, CodingKey {
        case id, version, attestationLoS, bindingType, supportedFormats, schemaURIs, rulebookURI, trustedAuthorities
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        version = try container.decodeIfPresent(String.self, forKey: .version)
        attestationLoS = try container.decodeIfPresent(String.self, forKey: .attestationLoS)
        bindingType = try container.decodeIfPresent(String.self, forKey: .bindingType)
        supportedFormats = try container.decodeIfPresent([String].self, forKey: .supportedFormats) ?? []
        schemaURIs = try container.decodeIfPresent([Ts11SchemaUri].self, forKey: .schemaURIs) ?? []
        rulebookURI = try container.decodeIfPresent(String.self, forKey: .rulebookURI)
        trustedAuthorities = try container.decodeIfPresent([String].self, forKey: .trustedAuthorities)
    }
}

/// Wire shape for the paginated `/api/v1/schemas.json` endpoint. Supports
/// both response formats it may return, mirroring `TS11SchemasResponse` in
/// the Go reference implementation:
/// - Current: `{"data": [...], "total": N, "limit": N, "offset": N}`
/// - Legacy: `{"schemas": [...], "next": "...", "total": N, "page": N, "pageSize": N}`
private struct Ts11SchemasWireResponse: Decodable {
    let schemas: [Ts11SchemaMeta]?
    let data: [Ts11SchemaMeta]?
    let total: Int
    let page: Int
    let pageSize: Int
    let limit: Int
    let offset: Int
    let next: String?

    enum CodingKeys: String, CodingKey {
        case schemas, data, total, page, pageSize, limit, offset, next
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemas = try container.decodeIfPresent([Ts11SchemaMeta].self, forKey: .schemas)
        data = try container.decodeIfPresent([Ts11SchemaMeta].self, forKey: .data)
        total = try container.decodeIfPresent(Int.self, forKey: .total) ?? 0
        page = try container.decodeIfPresent(Int.self, forKey: .page) ?? 0
        pageSize = try container.decodeIfPresent(Int.self, forKey: .pageSize) ?? 0
        limit = try container.decodeIfPresent(Int.self, forKey: .limit) ?? 0
        offset = try container.decodeIfPresent(Int.self, forKey: .offset) ?? 0
        next = try container.decodeIfPresent(String.self, forKey: .next)
    }

    /// Whichever schema array is populated (`data` takes precedence over `schemas`).
    func entries() -> [Ts11SchemaMeta] {
        if let data, !data.isEmpty { return data }
        return schemas ?? []
    }

    /// True if there are additional pages to fetch, per either pagination style.
    func hasMorePages() -> Bool {
        if let next, !next.isEmpty { return true }
        if limit > 0 && offset + entries().count < total { return true }
        return false
    }
}

/// Wire shape for the non-paginated `/api/v1/registry.json` endpoint (all credentials, minimal metadata).
private struct Ts11RegistryWireResponse: Decodable {
    let total: Int
    let credentials: [Ts11RegistryListEntry]

    enum CodingKeys: String, CodingKey { case total, credentials }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        total = try container.decodeIfPresent(Int.self, forKey: .total) ?? 0
        credentials = try container.decodeIfPresent([Ts11RegistryListEntry].self, forKey: .credentials) ?? []
    }
}

private struct Ts11RegistryListEntry: Decodable {
    let id: String
    let version: String?
    let supportedFormats: [String]
    let attestationLoS: String?
    let bindingType: String?
    let schemaURIs: [Ts11SchemaUri]?

    enum CodingKeys: String, CodingKey {
        case id, version, supportedFormats, attestationLoS, bindingType, schemaURIs
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        version = try container.decodeIfPresent(String.self, forKey: .version)
        supportedFormats = try container.decodeIfPresent([String].self, forKey: .supportedFormats) ?? []
        attestationLoS = try container.decodeIfPresent(String.self, forKey: .attestationLoS)
        bindingType = try container.decodeIfPresent(String.self, forKey: .bindingType)
        schemaURIs = try container.decodeIfPresent([Ts11SchemaUri].self, forKey: .schemaURIs)
    }
}

/// Queries a real TS11 credential-type registry (`registry.siros.org` by
/// default) directly, rather than going through go-wallet-backend's
/// `/type-metadata` proxy endpoint (which is a cache in front of this same
/// registry, not the registry itself - see `VctmFetcher`/`MddlSchemaFetcher`
/// for that proxy-based lookup path).
///
/// Ports the discovery/pagination/format-detection logic from
/// `go-wallet-backend/internal/registry/fetcher.go`'s `Fetcher.Fetch`/
/// `fetchFromSource`/`processTS11Response` - the confirmed real reference
/// implementation, also ported to Kotlin's `Ts11RegistryClient` - handling:
/// - the paginated current wire shape: `{"data": [...], "total", "limit", "offset"}`
/// - the legacy wire shape: `{"schemas": [...], "next"}`
/// - the non-paginated `/api/v1/registry.json` "all credentials" shape
///   (used when a `sources` entry's URL already points at that file)
///
/// following pagination on each source until exhausted.
///
/// Supports multiple registry `sources`, matching
/// `go-wallet-backend/configs/registry.yaml`'s `sources:` config concept for
/// future multi-registry deployments (defaults to a single entry,
/// `Ts11RegistryClient.defaultRegistryURL`). When more than one source is
/// configured, entries are merged by `Ts11SchemaMeta.id` with later sources
/// overwriting earlier ones - the same merge order `Fetcher.Fetch` uses for
/// its `Sources` list.
///
/// A source URL that already ends in `.json` (e.g. an explicit
/// `.../api/v1/registry.json`) is fetched as-is; otherwise `/api/v1/schemas.json`
/// is appended - mirrors `RemoteSourceConfig.resolveURL()`.
///
/// KNOWN GAP (inherited from the Go reference implementation, not introduced
/// here): neither this client nor `fetcher.go` performs any JWS/signature
/// verification of the registry response. The response is trusted as-is once
/// fetched over TLS. Fixing this, if ever needed, is a separate, deliberate
/// change - not something to silently add here.
///
/// Error handling matches this SDK's existing fetcher classes (`VctmFetcher`,
/// `MddlSchemaFetcher`): failures (network errors, malformed JSON, non-200
/// responses) are logged and degrade gracefully rather than throwing - a
/// source that fails is skipped, and `fetchSchemas()` returns whatever could
/// be gathered from the sources that succeeded (an empty list if all
/// failed). Unlike Kotlin's `httpGet` override (which may itself throw, and
/// is caught), this client's `httpGet` override follows `VctmFetcher`'s
/// existing non-throwing convention (`nil` return means "failed") - the same
/// graceful-degradation outcome, just expressed the way this codebase's
/// other fetchers already do.
public final class Ts11RegistryClient: @unchecked Sendable {
    /// Default TS11 registry base URL.
    public static let defaultRegistryURL = "https://registry.siros.org"

    // Safety valve against a misbehaving/malicious source looping
    // pagination forever (e.g. a "next" URL that always points back to
    // itself). Not present in the Go reference, which relies on Go's
    // context deadline for the equivalent protection - this SDK has no such
    // deadline plumbed through, so a hard page cap stands in for it.
    private static let maxPages = 1000

    private let sources: [String]
    private let httpGet: (@Sendable (String) async -> String?)?
    private let decoder = JSONDecoder()

    /// - Parameters:
    ///   - sources: base registry URLs to query, tried independently and
    ///     merged (see class docs). Defaults to `[Ts11RegistryClient.defaultRegistryURL]`.
    ///   - httpGet: test/host-supplied HTTP GET override; defaults to a real
    ///     `URLSession` fetch when nil.
    public init(
        sources: [String] = [Ts11RegistryClient.defaultRegistryURL],
        httpGet: (@Sendable (String) async -> String?)? = nil
    ) {
        self.sources = sources
        self.httpGet = httpGet
    }

    /// Fetch the full schema list across all configured `sources`, following
    /// pagination on each source until exhausted. See the class docs for
    /// merge order, format detection, and error-handling behavior.
    public func fetchSchemas() async -> [Ts11SchemaMeta] {
        var merged: [String: Ts11SchemaMeta] = [:]
        var order: [String] = []
        var anySucceeded = false

        for source in sources {
            if let entries = await fetchFromSource(source) {
                anySucceeded = true
                for entry in entries {
                    if merged[entry.id] == nil {
                        order.append(entry.id)
                    }
                    merged[entry.id] = entry
                }
            }
        }

        if !anySucceeded && !sources.isEmpty {
            #if canImport(os)
            logger.warning("All \(self.sources.count) TS11 registry source(s) failed; returning no schemas")
            #endif
        }

        return order.compactMap { merged[$0] }
    }

    private func fetchFromSource(_ source: String) async -> [Ts11SchemaMeta]? {
        let resolvedUrl = resolveUrl(source)
        #if canImport(os)
        logger.debug("Fetching TS11 registry source \(resolvedUrl)")
        #endif
        guard let body = await fetchRaw(resolvedUrl) else { return nil }
        return await parseAndPaginate(resolvedUrl: resolvedUrl, firstBody: body)
    }

    /// Mirrors `RemoteSourceConfig.resolveURL()`: an explicit `.json` URL is used as-is.
    private func resolveUrl(_ source: String) -> String {
        if source.hasSuffix(".json") { return source }
        var trimmed = source
        while trimmed.hasSuffix("/") { trimmed.removeLast() }
        return trimmed + "/api/v1/schemas.json"
    }

    private func parseAndPaginate(resolvedUrl: String, firstBody: String) async -> [Ts11SchemaMeta]? {
        if looksLikeAllCredentialsRegistryResponse(firstBody) {
            return parseRegistryResponse(resolvedUrl: resolvedUrl, body: firstBody)
        }

        var entries: [Ts11SchemaMeta] = []
        var currentBody = firstBody
        var pageCount = 0

        while true {
            guard let bodyData = currentBody.data(using: .utf8) else {
                if pageCount == 0 { return nil }
                break
            }

            let page: Ts11SchemasWireResponse
            do {
                page = try decoder.decode(Ts11SchemasWireResponse.self, from: bodyData)
            } catch {
                if pageCount == 0 {
                    #if canImport(os)
                    logger.warning("Failed to parse TS11 schemas response from \(resolvedUrl): \(error.localizedDescription)")
                    #endif
                    return nil
                }
                #if canImport(os)
                logger.warning("Failed to parse a subsequent TS11 schemas page from \(resolvedUrl); stopping pagination")
                #endif
                break
            }

            entries.append(contentsOf: page.entries())
            pageCount += 1

            if !page.hasMorePages() || pageCount >= Self.maxPages { break }

            let nextUrl = nextPageUrl(page: page, baseUrl: resolvedUrl)
            guard let nextBody = await fetchRaw(nextUrl) else {
                #if canImport(os)
                logger.warning("Failed to fetch next page of TS11 schemas from \(nextUrl); stopping pagination")
                #endif
                break
            }
            currentBody = nextBody
        }

        return entries
    }

    /// Detects the `/api/v1/registry.json` "all credentials" shape:
    /// `{"credentials": [...], "total": N}` without the `data`/`schemas` keys
    /// the paginated schemas.json shape uses - mirrors `fetchFromSource`'s
    /// top-level-key format-detector in the Go reference.
    private func looksLikeAllCredentialsRegistryResponse(_ body: String) -> Bool {
        guard let data = body.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return false
        }
        return obj["credentials"] != nil && obj["data"] == nil && obj["schemas"] == nil
    }

    private func parseRegistryResponse(resolvedUrl: String, body: String) -> [Ts11SchemaMeta]? {
        guard let data = body.data(using: .utf8) else { return nil }
        do {
            let resp = try decoder.decode(Ts11RegistryWireResponse.self, from: data)
            return resp.credentials.map { entry in
                Ts11SchemaMeta(
                    id: entry.id,
                    version: entry.version,
                    attestationLoS: entry.attestationLoS,
                    bindingType: entry.bindingType,
                    supportedFormats: entry.supportedFormats,
                    schemaURIs: entry.schemaURIs ?? []
                )
            }
        } catch {
            #if canImport(os)
            logger.warning("Failed to parse TS11 registry.json response from \(resolvedUrl): \(error.localizedDescription)")
            #endif
            return nil
        }
    }

    /// Mirrors `TS11SchemasResponse.NextPageURL()`: the legacy `next` field is
    /// used directly when present; otherwise an offset-based URL is built
    /// against `baseUrl` (the source's originally resolved URL, not the
    /// previously fetched page's URL - matching the Go reference, which
    /// always recomputes from the fixed base rather than accumulating).
    private func nextPageUrl(page: Ts11SchemasWireResponse, baseUrl: String) -> String {
        if let next = page.next, !next.isEmpty { return next }

        let nextOffset = page.offset + page.entries().count
        var clean = baseUrl

        if let offsetRange = clean.range(of: "offset="), offsetRange.lowerBound > clean.startIndex {
            if let ampRange = clean.range(of: "&", range: offsetRange.upperBound..<clean.endIndex) {
                clean = String(clean[clean.startIndex..<offsetRange.lowerBound])
                    + String(clean[clean.index(after: ampRange.lowerBound)...])
            } else {
                // strip preceding '?' or '&'
                clean = String(clean[clean.startIndex..<clean.index(before: offsetRange.lowerBound)])
            }
        }

        let sep = clean.contains("?") ? "&" : "?"
        return "\(clean)\(sep)offset=\(nextOffset)"
    }

    private func fetchRaw(_ url: String) async -> String? {
        if let httpGet {
            return await httpGet(url)
        }
        return await fetchWithUrlSession(url)
    }

    private func fetchWithUrlSession(_ urlString: String) async -> String? {
        await ts11FetchWithUrlSession(
            urlString,
            logCategory: "Ts11RegistryClient",
            logPrefix: "TS11 registry fetch"
        )
    }
}

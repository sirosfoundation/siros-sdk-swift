// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(os)
import os
private let discoveryLogger = Logger(subsystem: "org.siros.sdk", category: "Ts11CredentialDiscovery")
#endif

/// A single `Ts11RegistryClient`-discovered credential type, enriched with a
/// real display identity - see `Ts11CredentialDiscovery` for how
/// `identifier`/`name`/`description` are resolved. Mirrors Kotlin's
/// `Ts11DiscoveredCredential`.
///
/// - `schema`: the original registry entry, unchanged - still needed for
///   `Ts11SchemaMeta.attestationLoS`/`Ts11SchemaMeta.supportedFormats` tier
///   filtering (see `WscdPluginCapabilities`), which this type does not
///   duplicate.
/// - `identifier`: the credential type's own `vct` (SD-JWT VC) or `doctype`
///   (mdoc) identifier, resolved from the schema document at one of
///   `Ts11SchemaMeta.schemaURIs` - the same identifier space
///   `WscdSelectionPolicy`'s `"issuer|credentialType"` mapping keys already
///   use elsewhere in this app. Falls back to the registry's own opaque
///   `Ts11SchemaMeta.id` when no document could be fetched/parsed - this is
///   the "UUID instead of a real name" gap this type exists to close, but a
///   registry UUID is still a better fallback than nothing.
/// - `name`: human-readable display name, when resolved. `nil` when
///   enrichment failed (network error, unparseable document, no recognized
///   format in `Ts11SchemaMeta.schemaURIs`) - callers should fall back to
///   `identifier` for display in that case (see `displayName`).
/// - `description`: human-readable description, when resolved.
public struct Ts11DiscoveredCredential: Sendable, Equatable {
    public let schema: Ts11SchemaMeta
    public let identifier: String
    public let name: String?
    public let description: String?

    public init(schema: Ts11SchemaMeta, identifier: String, name: String? = nil, description: String? = nil) {
        self.schema = schema
        self.identifier = identifier
        self.name = name
        self.description = description
    }

    /// Best available label for display: the resolved `name`, else `identifier`.
    public var displayName: String { name ?? identifier }
}

/// Resolves each `Ts11RegistryClient`-discovered `Ts11SchemaMeta`'s real
/// display identity (`vct`/`doctype` + `name`/`description`), since neither
/// `/api/v1/schemas.json` nor `/api/v1/registry.json` carries a human name or
/// description at the list level - confirmed against the real reference
/// implementation, `go-wallet-backend/internal/registry/fetcher.go`, and
/// mirroring Kotlin's `Ts11CredentialDiscovery`. The ONLY place that identity
/// exists is inside the actual schema document each `Ts11SchemaMeta.schemaURIs`
/// entry points to - mirrors `fetcher.go`'s `fetchSchemaDocument`/
/// `parseDocumentHeader` pattern: for each `Ts11SchemaMeta.schemaURIs` entry,
/// fetch the document, parse out its own `vct`/`doctype`/`name`/`description`,
/// falling back to the raw `Ts11SchemaMeta.id` only if the fetch/parse fails.
///
/// Picks which `Ts11SchemaMeta.schemaURIs` entry to fetch by
/// `Ts11SchemaUri.formatIdentifier`: anything containing `"sd-jwt"` is parsed
/// as a `VctmFetcher`-shaped document (SD-JWT VC Type Metadata); anything
/// containing `"mso_mdoc"` is parsed as an `MddlSchemaFetcher`-shaped
/// document (mdoc MDDL schema, using `display?.first` for its
/// name/description - `MddlSchema` itself has no top-level name/description).
/// A schema with neither format in its `Ts11SchemaMeta.schemaURIs` - or one
/// whose fetch/parse fails - degrades gracefully to the raw `Ts11SchemaMeta.id`
/// (see `Ts11DiscoveredCredential`'s doc comment), exactly like `fetcher.go`:
/// one bad entry never throws or blocks the rest of the discovery list.
///
/// Deliberately does its own raw HTTP GET of the chosen `Ts11SchemaUri.uri`
/// (same `URLSession` pattern `Ts11RegistryClient`/`VctmFetcher`/
/// `MddlSchemaFetcher` each already use) rather than calling
/// `VctmFetcher.fetch`/`MddlSchemaFetcher.fetch`: those methods resolve a
/// document from an *issuer's* URL via their own issuer-direct/well-known/
/// registry-proxy strategies, which don't apply here - a `Ts11SchemaUri.uri`
/// is already the exact document location, so it's fetched as-is and parsed
/// with `VctmFetcher.parseVctm`/`MddlSchemaFetcher.parseMddlSchema` (reusing
/// those fetchers' existing parsing logic and `Vctm`/`MddlSchema` types,
/// rather than re-declaring another copy of either shape here).
public final class Ts11CredentialDiscovery: @unchecked Sendable {
    private let registryClient: Ts11RegistryClient
    private let vctmFetcher: VctmFetcher
    private let mddlSchemaFetcher: MddlSchemaFetcher
    private let httpGet: (@Sendable (String) async -> String?)?

    /// - Parameters:
    ///   - registryClient: supplies the raw discovered schema list.
    ///   - vctmFetcher: used only for its `parseVctm` parsing (its own
    ///     `fetch` issuer-resolution strategies are unused here).
    ///   - mddlSchemaFetcher: used only for its `parseMddlSchema` parsing
    ///     (same rationale as `vctmFetcher`).
    ///   - httpGet: optional HTTP GET override for tests/custom HTTP
    ///     clients; defaults to a real `URLSession` fetch when nil.
    public init(
        registryClient: Ts11RegistryClient = Ts11RegistryClient(),
        vctmFetcher: VctmFetcher = VctmFetcher(),
        mddlSchemaFetcher: MddlSchemaFetcher = MddlSchemaFetcher(),
        httpGet: (@Sendable (String) async -> String?)? = nil
    ) {
        self.registryClient = registryClient
        self.vctmFetcher = vctmFetcher
        self.mddlSchemaFetcher = mddlSchemaFetcher
        self.httpGet = httpGet
    }

    /// Fetch the schema list and enrich every entry - see class docs for resolution/fallback order.
    public func discover() async -> [Ts11DiscoveredCredential] {
        let schemas = await registryClient.fetchSchemas()
        var results: [Ts11DiscoveredCredential] = []
        results.reserveCapacity(schemas.count)
        for schema in schemas {
            results.append(await enrich(schema))
        }
        return results
    }

    private func enrich(_ schema: Ts11SchemaMeta) async -> Ts11DiscoveredCredential {
        if let sdJwtUri = schema.schemaURIs.first(where: { $0.formatIdentifier.localizedCaseInsensitiveContains("sd-jwt") }) {
            if let body = await fetchDocument(sdJwtUri.uri), let vctm = vctmFetcher.parseVctm(body) {
                return Ts11DiscoveredCredential(schema: schema, identifier: vctm.vct, name: vctm.name, description: vctm.description)
            }
        }

        if let mdocUri = schema.schemaURIs.first(where: { $0.formatIdentifier.localizedCaseInsensitiveContains("mso_mdoc") }) {
            if let body = await fetchDocument(mdocUri.uri), let mddl = mddlSchemaFetcher.parseMddlSchema(body) {
                let display = mddl.display?.first
                return Ts11DiscoveredCredential(schema: schema, identifier: mddl.doctype, name: display?.name, description: display?.description)
            }
        }

        // Graceful fallback (see class docs): no recognized format in
        // schemaURIs, or the fetch/parse of a recognized one failed.
        #if canImport(os)
        discoveryLogger.debug("TS11 schema \(schema.id): no display identity resolved, falling back to raw id")
        #endif
        return Ts11DiscoveredCredential(schema: schema, identifier: schema.id)
    }

    private func fetchDocument(_ url: String) async -> String? {
        if let httpGet {
            return await httpGet(url)
        }
        return await fetchWithUrlSession(url)
    }

    private func fetchWithUrlSession(_ urlString: String) async -> String? {
        await ts11FetchWithUrlSession(
            urlString,
            logCategory: "Ts11CredentialDiscovery",
            logPrefix: "TS11 schema document fetch"
        )
    }
}

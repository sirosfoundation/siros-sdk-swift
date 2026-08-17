// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosTransport
#if canImport(CryptoKit)
import CryptoKit
#else
// swift-crypto's `Crypto` module mirrors CryptoKit's API 1:1 (including the
// `SHA256` type used below) - it exists purely so this file compiles and
// runs identically on Linux, where CryptoKit itself isn't available at all.
import Crypto
#endif
#if canImport(os)
import os
private let logger = Logger(subsystem: "org.siros.sdk", category: "ZkCircuitClient")
#endif

// MARK: - Wire types
//
// Mirrors go-zk-circuits' `pkg/catalog/types.go` (the `/v1` REST API served
// at e.g. https://zk-circuits.fly.dev) field-for-field. Field names below
// are already valid Swift camelCase identical to the JSON keys the Go
// service emits (`manifestVersion`, `systemVersion`, `docTypes`, ...), so
// no `CodingKeys` renaming is needed anywhere except where noted.

/// Top-level document served at `GET /v1/manifest.json`.
public struct ZkManifest: Codable, Sendable, Equatable {
    public let manifestVersion: Int
    public let generatedAt: String
    public let catalog: String
    public let circuits: [ZkCircuitDescriptor]
    /// Pagination cursor for a future page of results. The real service
    /// always emits this key (as `null` today - no catalog has ever needed
    /// pagination yet), so it decodes as an optional rather than being
    /// literally absent.
    public let next: String?

    public init(
        manifestVersion: Int,
        generatedAt: String,
        catalog: String,
        circuits: [ZkCircuitDescriptor],
        next: String? = nil
    ) {
        self.manifestVersion = manifestVersion
        self.generatedAt = generatedAt
        self.catalog = catalog
        self.circuits = circuits
        self.next = next
    }
}

/// One catalog entry - the body of `GET /v1/circuits/{id}.json`, and also
/// each element of `ZkManifest.circuits`.
public struct ZkCircuitDescriptor: Sendable, Equatable {
    public let id: String
    public let aliases: [String]?
    public let system: String
    public let systemVersion: String
    public let docTypes: [String]?
    public let published: Bool
    public let status: String
    /// Generic, system-specific parameters (e.g. `num_attributes`). Go's
    /// `map[string]any` has no `omitempty` - the real service always emits
    /// this key, even as `{}` - but decoding defaults it to `[:]` rather
    /// than throwing if a hand-written test fixture omits it.
    public let params: [String: AnyCodable]
    public let artifact: ZkArtifact?
    public let source: ZkSource?
    public let publishedAt: String
    public let deprecatedAt: String?
    public let notes: String?

    public init(
        id: String,
        aliases: [String]? = nil,
        system: String,
        systemVersion: String,
        docTypes: [String]? = nil,
        published: Bool,
        status: String,
        params: [String: AnyCodable] = [:],
        artifact: ZkArtifact? = nil,
        source: ZkSource? = nil,
        publishedAt: String,
        deprecatedAt: String? = nil,
        notes: String? = nil
    ) {
        self.id = id
        self.aliases = aliases
        self.system = system
        self.systemVersion = systemVersion
        self.docTypes = docTypes
        self.published = published
        self.status = status
        self.params = params
        self.artifact = artifact
        self.source = source
        self.publishedAt = publishedAt
        self.deprecatedAt = deprecatedAt
        self.notes = notes
    }
}

extension ZkCircuitDescriptor: Codable {
    enum CodingKeys: String, CodingKey {
        case id, aliases, system, systemVersion, docTypes, published, status, params, artifact, source, publishedAt, deprecatedAt, notes
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        aliases = try c.decodeIfPresent([String].self, forKey: .aliases)
        system = try c.decode(String.self, forKey: .system)
        systemVersion = try c.decode(String.self, forKey: .systemVersion)
        docTypes = try c.decodeIfPresent([String].self, forKey: .docTypes)
        published = try c.decode(Bool.self, forKey: .published)
        status = try c.decode(String.self, forKey: .status)
        params = try c.decodeIfPresent([String: AnyCodable].self, forKey: .params) ?? [:]
        artifact = try c.decodeIfPresent(ZkArtifact.self, forKey: .artifact)
        source = try c.decodeIfPresent(ZkSource.self, forKey: .source)
        publishedAt = try c.decode(String.self, forKey: .publishedAt)
        deprecatedAt = try c.decodeIfPresent(String.self, forKey: .deprecatedAt)
        notes = try c.decodeIfPresent(String.self, forKey: .notes)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encodeIfPresent(aliases, forKey: .aliases)
        try c.encode(system, forKey: .system)
        try c.encode(systemVersion, forKey: .systemVersion)
        try c.encodeIfPresent(docTypes, forKey: .docTypes)
        try c.encode(published, forKey: .published)
        try c.encode(status, forKey: .status)
        try c.encode(params, forKey: .params)
        try c.encodeIfPresent(artifact, forKey: .artifact)
        try c.encodeIfPresent(source, forKey: .source)
        try c.encode(publishedAt, forKey: .publishedAt)
        try c.encodeIfPresent(deprecatedAt, forKey: .deprecatedAt)
        try c.encodeIfPresent(notes, forKey: .notes)
    }
}

/// Describes the downloadable bytes for a circuit (spec §2.6, `pkg/catalog/
/// types.go`'s `Artifact`).
///
/// `url` is a **relative** path (confirmed against the real service's own
/// publish tooling, `pkg/publish/add.go`: `entry.Artifact.URL = "/v1/" +
/// catalog.ArtifactFilePath(...)`, e.g. `/v1/artifacts/sha256/<hex>`) - it
/// must be resolved against a source base URL, not fetched as-is. See
/// `ZkCircuitClient.downloadArtifact`.
///
/// `hash` is over the bytes AS SERVED (i.e. still compressed, when
/// `compression != "none"`) - NOT `uncompressed.hash`, and NOT
/// `params["circuit_hash"]` (the proof system's own identifier). This
/// client only ever verifies against `hash`, matching what it actually
/// downloads.
public struct ZkArtifact: Codable, Sendable, Equatable {
    public let url: String
    public let hash: String
    public let size: Int64
    public let compression: String
    public let mediaType: String
    public let uncompressed: ZkUncompressedInfo?

    public init(
        url: String,
        hash: String,
        size: Int64,
        compression: String,
        mediaType: String,
        uncompressed: ZkUncompressedInfo? = nil
    ) {
        self.url = url
        self.hash = hash
        self.size = size
        self.compression = compression
        self.mediaType = mediaType
        self.uncompressed = uncompressed
    }
}

/// Decompressed-form hash/size, present when `ZkArtifact.compression != "none"`.
public struct ZkUncompressedInfo: Codable, Sendable, Equatable {
    public let hash: String
    public let size: Int64

    public init(hash: String, size: Int64) {
        self.hash = hash
        self.size = size
    }
}

/// Provenance for a catalog entry (spec §2.8).
public struct ZkSource: Codable, Sendable, Equatable {
    public let origin: String
    public let originRef: String?
    public let originPath: String?
    public let toolchain: String?
    public let license: String?
    public let openSource: Bool
    public let addedBy: String
    public let verifiedBy: [ZkVerificationRecord]?

    public init(
        origin: String,
        originRef: String? = nil,
        originPath: String? = nil,
        toolchain: String? = nil,
        license: String? = nil,
        openSource: Bool,
        addedBy: String,
        verifiedBy: [ZkVerificationRecord]? = nil
    ) {
        self.origin = origin
        self.originRef = originRef
        self.originPath = originPath
        self.toolchain = toolchain
        self.license = license
        self.openSource = openSource
        self.addedBy = addedBy
        self.verifiedBy = verifiedBy
    }
}

/// A single structured interop confirmation - descriptive metadata only,
/// carries no trust authority (see `pkg/catalog/types.go`'s doc comment on
/// `VerificationRecord`).
public struct ZkVerificationRecord: Codable, Sendable, Equatable {
    public let tool: String
    public let toolVersion: String
    public let verifierIdentity: String
    public let date: String
    public let result: String
    public let notes: String?

    public init(
        tool: String,
        toolVersion: String,
        verifierIdentity: String,
        date: String,
        result: String,
        notes: String? = nil
    ) {
        self.tool = tool
        self.toolVersion = toolVersion
        self.verifierIdentity = verifierIdentity
        self.date = date
        self.result = result
        self.notes = notes
    }
}

// MARK: - Errors

public enum ZkCircuitClientError: Error, Sendable {
    /// Every configured source failed. `underlying` holds one error per
    /// attempted source, in source-list order.
    case allSourcesFailed(underlying: [Error])
    /// The requested circuit descriptor has no `artifact` field (e.g. a
    /// reference/spec-only entry with no published bytes), so there is
    /// nothing to download.
    case noArtifact(id: String)
    /// A source base URL (or a URL derived from it) isn't a valid URL.
    case invalidUrl(String)
    /// The downloaded artifact's SHA-256 hash didn't match
    /// `ZkArtifact.hash` - the bytes were corrupted or tampered with in
    /// transit and MUST NOT be used.
    case hashMismatch(expected: String, actual: String)
}

extension ZkCircuitClientError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .allSourcesFailed(let errors):
            let details = errors.map { ($0 as? LocalizedError)?.errorDescription ?? "\($0)" }.joined(separator: "; ")
            return "All configured zk-circuit sources failed: \(details)"
        case .noArtifact(let id):
            return "Circuit \"\(id)\" has no published artifact"
        case .invalidUrl(let value):
            return "Invalid zk-circuit URL: \(value)"
        case .hashMismatch(let expected, let actual):
            return "Artifact hash mismatch: expected \(expected), got \(actual)"
        }
    }
}

// MARK: - Client

/// Client for go-zk-circuits' read-only `/v1` REST API (see
/// `~/work/siros.org/go-zk-circuits`, deployed at
/// `https://zk-circuits.fly.dev`, moving to `https://api.circuits.siros.org`
/// once DNS is live).
///
/// ## Multi-source fallback, not merge
///
/// `sources` is an **ordered list of mirrors of the same catalog** - e.g.
/// a primary host plus one or more fallback/mirror hosting services - not a
/// registry-aggregation list like some other SDKs' multi-URL settings. Every
/// entry is expected to serve the *same* `siros-zk-circuits` catalog, just
/// potentially with different availability. Because of that, this client
/// tries each source **in list order and returns the first success**,
/// rather than merging results the way you might merge N independent
/// registries: querying two different mirrors could only ever race to the
/// same answer or one could be a stale/lagging copy, so there is nothing
/// useful to gain by combining partial results across sources, and doing so
/// would risk mixing a `CircuitDescriptor` from one mirror with an
/// `Artifact` hash from another. (There's no existing Swift precedent for
/// multi-source fallback to follow in this codebase - the closest thing,
/// go-wallet-backend's TS11 credential-type registry client, is
/// single-URL-only - so this ordering/fallback behavior is this file's own
/// design, established for future multi-source clients to reuse.)
///
/// Every non-2xx response from the real service is an RFC 9457
/// `application/problem+json` body; this client doesn't parse those fields,
/// it just surfaces a clear thrown error.
public final class ZkCircuitClient: @unchecked Sendable {

    /// The default, single well-known zk-circuits hosting service.
    /// `WalletConfig.zkCircuitUrls`'s default is `[Self.defaultZkCircuitUrl]`.
    public static let defaultZkCircuitUrl = "https://zk-circuits.fly.dev"

    private let sources: [String]
    private let httpGet: @Sendable (URL) async throws -> Data
    private let decoder = JSONDecoder()

    /// - Parameters:
    ///   - sources: ordered list of base URLs, each expected to serve the
    ///     same catalog (see the class doc comment on fallback semantics).
    ///     Defaults to `[Self.defaultZkCircuitUrl]`.
    ///   - httpGet: test-supplied HTTP GET override; defaults to a real
    ///     `URLSession` fetch when nil. Matches this module's existing
    ///     injectable-closure testing pattern (see `VctmFetcher`/
    ///     `MddlSchemaFetcher`'s `httpGet`, and `BackendApiClient`'s
    ///     `httpFn`) rather than a raw `URLSession` parameter, so tests can
    ///     stub per-URL behavior (including per-source failure/fallback)
    ///     without a real network stack.
    public init(
        sources: [String] = [ZkCircuitClient.defaultZkCircuitUrl],
        httpGet: (@Sendable (URL) async throws -> Data)? = nil
    ) {
        self.sources = sources
        self.httpGet = httpGet ?? Self.defaultHttpGet
    }

    private static let defaultHttpGet: @Sendable (URL) async throws -> Data = { url in
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = 30
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw SirosError.network(message: "Invalid response for \(url.absoluteString)")
        }
        guard (200..<300).contains(httpResponse.statusCode) else {
            throw SirosError.network(message: "GET \(url.absoluteString) failed: HTTP \(httpResponse.statusCode)")
        }
        return data
    }

    // MARK: - Public API

    /// `GET /v1/manifest.json` - the full circuit catalog, tried against
    /// each configured source in order until one succeeds.
    public func fetchManifest() async throws -> ZkManifest {
        try await fetchFromSources(path: "/v1/manifest.json") { data in
            try self.decoder.decode(ZkManifest.self, from: data)
        }
    }

    /// `GET /v1/circuits/{id}.json` - a single circuit descriptor. `id` may
    /// be an alias; the real service 301-redirects to the canonical id, and
    /// `URLSession` follows redirects by default, so this just works.
    public func fetchCircuit(id: String) async throws -> ZkCircuitDescriptor {
        try await fetchFromSources(path: "/v1/circuits/\(id).json") { data in
            try self.decoder.decode(ZkCircuitDescriptor.self, from: data)
        }
    }

    /// Downloads `descriptor.artifact`'s bytes and verifies their SHA-256
    /// hash against `descriptor.artifact.hash` (the bytes AS SERVED, i.e.
    /// still compressed if `compression != "none"`) before returning them.
    /// Throws `ZkCircuitClientError.hashMismatch` if verification fails -
    /// the mismatched bytes are never returned to the caller.
    public func downloadArtifact(_ descriptor: ZkCircuitDescriptor) async throws -> Data {
        guard let artifact = descriptor.artifact else {
            throw ZkCircuitClientError.noArtifact(id: descriptor.id)
        }
        let data = try await downloadArtifactBytes(artifact)
        let actualHash = Self.sha256Hex(data)
        guard actualHash.caseInsensitiveCompare(Self.bareHex(artifact.hash)) == .orderedSame else {
            throw ZkCircuitClientError.hashMismatch(expected: artifact.hash, actual: actualHash)
        }
        return data
    }

    // MARK: - Private

    private func downloadArtifactBytes(_ artifact: ZkArtifact) async throws -> Data {
        // An absolute URL (has a scheme) names one specific, concrete
        // location - there's no set of mirrors to fall back across, so it's
        // fetched directly.
        if let direct = URL(string: artifact.url), direct.scheme != nil {
            return try await httpGet(direct)
        }
        // A relative URL (the real service's actual behavior - see
        // `ZkArtifact`'s doc comment) is resolved against each configured
        // source in turn, with the same ordered-fallback semantics as
        // `fetchManifest`/`fetchCircuit`.
        return try await fetchFromSources(path: artifact.url) { $0 }
    }

    /// Tries `path` against each configured source in list order, returning
    /// the first success. See the class doc comment for why this is
    /// ordered fallback, not a merge across sources.
    private func fetchFromSources<T>(path: String, transform: (Data) throws -> T) async throws -> T {
        var errors: [Error] = []
        for base in sources {
            guard let url = Self.zkUrl(base: base, path: path) else {
                errors.append(ZkCircuitClientError.invalidUrl(base))
                continue
            }
            do {
                let data = try await httpGet(url)
                return try transform(data)
            } catch {
                #if canImport(os)
                logger.debug("zk-circuit source failed, trying next: \(url.absoluteString) - \(error.localizedDescription)")
                #endif
                errors.append(error)
            }
        }
        throw ZkCircuitClientError.allSourcesFailed(underlying: errors)
    }

    private static func zkUrl(base: String, path: String) -> URL? {
        let trimmedBase = base.hasSuffix("/") ? String(base.dropLast()) : base
        let normalizedPath = path.hasPrefix("/") ? path : "/\(path)"
        return URL(string: "\(trimmedBase)\(normalizedPath)")
    }

    private static func sha256Hex(_ data: Data) -> String {
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// `ZkArtifact.hash` is wire-formatted as `"sha256:<hex>"` (matching
    /// go-zk-circuits' own hash field convention), but `sha256Hex` returns a
    /// bare hex digest with no prefix - comparing the two directly without
    /// stripping this prefix always failed, even for a byte-for-byte-correct
    /// download (confirmed live: "expected sha256:44c4b98..., got
    /// 44c4b98..." - the same digest, just one side prefixed). Strips it if
    /// present; leaves the string as-is otherwise, so a legacy unprefixed
    /// hash value would still compare correctly too.
    private static func bareHex(_ hash: String) -> String {
        hash.hasPrefix("sha256:") ? String(hash.dropFirst("sha256:".count)) : hash
    }
}

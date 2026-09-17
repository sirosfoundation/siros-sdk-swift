// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(CryptoKit)
import CryptoKit
#else
// swift-crypto's `Crypto` module mirrors CryptoKit's API 1:1 - it exists so
// this file compiles and runs identically on Linux.
import Crypto
#endif
#if canImport(os)
import os
private let logger = Logger(subsystem: "org.siros.sdk", category: "TokenStatusList")
#endif

/// IETF Token Status List - the revocation mechanism DIIP requires.
///
/// A credential carries a `status.status_list` reference: an index plus the
/// URI of a Status List Token. That token is a JWS (`typ: statuslist+jwt`)
/// whose payload holds a zlib-compressed bit array; the bits at the
/// credential's index encode its status.
///
/// - SeeAlso: [draft-ietf-oauth-status-list-15](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/15/)
public enum TokenStatusList {

    /// The entry widths the draft allows, in bits.
    public static let entryWidths: Set<Int> = [1, 2, 4, 8]

    /// Status values registered by the Token Status List draft.
    public enum Status {
        public static let valid = 0x00
        public static let invalid = 0x01
        public static let suspended = 0x02
    }

    /// The `status.status_list` object embedded in a credential.
    public struct Reference: Sendable, Equatable {
        public let idx: Int
        public let uri: String

        public init(idx: Int, uri: String) {
            self.idx = idx
            self.uri = uri
        }
    }

    /// What a status lookup produced.
    public enum Resolution: Sendable, Equatable {
        /// The status bits found at the credential's index.
        case found(Int)

        /// The status could not be established - typically an unreachable
        /// list. A caller must treat this as a warning, not a revocation: a
        /// wallet that hid every credential whose status endpoint is down
        /// would be unusable offline.
        case unavailable(String)
    }

    /// Read the Status List reference out of a credential's claims, if it has
    /// one.
    public static func extractReference(from claims: [String: Any]) -> Reference? {
        guard let status = claims["status"] as? [String: Any],
              let statusList = status["status_list"] as? [String: Any],
              let idx = (statusList["idx"] as? NSNumber)?.intValue ?? (statusList["idx"] as? Int),
              let uri = statusList["uri"] as? String,
              idx >= 0, !uri.isEmpty
        else { return nil }
        return Reference(idx: idx, uri: uri)
    }

    /// Read the status at `idx` from a decompressed status list.
    ///
    /// Entries are packed `bits` at a time, least significant bits first
    /// within each byte. Returns nil when `bits` is not a legal width or the
    /// index lies past the end of the list.
    public static func readStatus(in list: Data, bits: Int, idx: Int) -> Int? {
        guard entryWidths.contains(bits), idx >= 0 else { return nil }
        let entriesPerByte = 8 / bits
        let byteIndex = idx / entriesPerByte
        guard byteIndex < list.count else { return nil }
        let shift = (idx % entriesPerByte) * bits
        let mask = (1 << bits) - 1
        return (Int(list[list.startIndex + byteIndex]) >> shift) & mask
    }

    /// Inflate the zlib-compressed `lst` member.
    public static func inflate(_ compressed: Data) -> Data? {
        Inflate.inflate(compressed)
    }

    /// A fetched status list, remembered so one list is fetched once per
    /// session rather than once per credential that points at it.
    struct CacheEntry {
        let fetchedAt: Date
        /// The token's own `ttl`; 0 or absent keeps the entry for the lifetime
        /// of the cache.
        let ttlSeconds: TimeInterval
        let bits: Int
        let list: Data
        /// The issuer this token was authenticated for. A cached list must not
        /// be handed to a credential from a different issuer: the `iss` check
        /// happens on fetch, so reusing the entry across issuers - or reusing
        /// an entry first fetched with no expected issuer - would bypass it.
        let issuer: String?
        /// The token's own `exp`. Enforced on every cache hit: with no `ttl`
        /// the entry would otherwise be served for the life of the process,
        /// long past the point where the issuer expected it to be re-fetched,
        /// and would miss every revocation published since.
        let expiresAt: Date?
    }
}

/// Fetches, verifies and reads Status List Tokens.
///
/// Holds the per-session cache, so construct one per wallet session and share
/// it across credentials: a list covering ten thousand credentials is fetched
/// once, not once per credential that points into it.
public actor TokenStatusListClient {
    private let httpGet: @Sendable (String, [String: String]) async -> Data?
    private let resolveIssuerKey: (@Sendable (String, String?) async -> [String: String]?)?
    private let now: @Sendable () -> Date
    private var cache: [String: TokenStatusList.CacheEntry] = [:]

    /// - Parameters:
    ///   - httpGet: fetches a URL with the given headers, returning the body
    ///     or nil. Injected so a host's own client, pinning and caching apply.
    ///   - resolveIssuerKey: resolves an issuer's signing key when the Status
    ///     List Token's header carries no `x5c`. Given the token's issuer
    ///     identifier and the header `kid`. A DID-identified issuer is handled
    ///     by ``DidResolver``; anything else is the host's to answer.
    ///   - now: time source, overridable for deterministic tests.
    public init(
        httpGet: @escaping @Sendable (String, [String: String]) async -> Data?,
        resolveIssuerKey: (@Sendable (String, String?) async -> [String: String]?)? = nil,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.httpGet = httpGet
        self.resolveIssuerKey = resolveIssuerKey
        self.now = now
    }

    /// Look up one credential's entry.
    ///
    /// - Parameters:
    ///   - expectedIssuer: the issuer of the credential being checked. The
    ///     Status List Token's `iss` must match it - otherwise anyone able to
    ///     serve a URL could publish a status list for someone else's
    ///     credentials. Nil skips the check, which is only safe when the
    ///     caller has no issuer to compare against.
    ///   - clockTolerance: leeway applied to the token's own `exp` and `nbf`.
    public func resolve(
        _ reference: TokenStatusList.Reference,
        expectedIssuer: String? = nil,
        clockTolerance: TimeInterval = 0
    ) async -> TokenStatusList.Resolution {
        let currentTime = now()

        if let entry = cache[reference.uri] {
            let withinTtl = entry.ttlSeconds <= 0
                || currentTime.timeIntervalSince(entry.fetchedAt) < entry.ttlSeconds
            // The `iss` check ran when this entry was fetched, and it only
            // authenticated the token for THAT issuer. A different one - or an
            // entry first fetched without an expected issuer - has to go back
            // to the network rather than inherit that decision.
            let sameIssuer = entry.issuer == expectedIssuer
            let unexpired = entry.expiresAt.map {
                $0.timeIntervalSince1970 + clockTolerance >= currentTime.timeIntervalSince1970
            } ?? true
            if withinTtl && sameIssuer && unexpired {
                guard let status = TokenStatusList.readStatus(in: entry.list, bits: entry.bits, idx: reference.idx) else {
                    return .unavailable("Index \(reference.idx) is outside the cached status list")
                }
                return .found(status)
            }
        }

        guard let body = await httpGet(reference.uri, ["Accept": "application/statuslist+jwt"]),
              let token = String(data: body, encoding: .utf8)?
                  .trimmingCharacters(in: .whitespacesAndNewlines),
              !token.isEmpty
        else {
            return .unavailable("Could not fetch the status list at \(reference.uri)")
        }

        let segments = token.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard segments.count == 3,
              let header = try? JSONSerialization.jsonObject(
                  with: EncryptedContainerBase64.urlDecode(segments[0])
              ) as? [String: Any],
              let claims = try? JSONSerialization.jsonObject(
                  with: EncryptedContainerBase64.urlDecode(segments[1])
              ) as? [String: Any]
        else {
            return .unavailable("Status list at \(reference.uri) is not a JWS")
        }

        // §5.1: the token is typed so it cannot be confused with any other JWS
        // the same issuer signs.
        guard header["typ"] as? String == "statuslist+jwt" else {
            return .unavailable("Unexpected Status List Token typ: \(header["typ"] as? String ?? "none")")
        }

        let issuer = claims["iss"] as? String
        if let expectedIssuer, issuer != expectedIssuer {
            return .unavailable(
                "Status List Token was issued by \(issuer ?? "nobody"), expected \(expectedIssuer)"
            )
        }
        // §5.1: `sub` binds the token to the URI it was served from.
        if let subject = claims["sub"] as? String, subject != reference.uri {
            return .unavailable("Status List Token subject \(subject) does not match \(reference.uri)")
        }

        switch await verifySignature(segments: segments, header: header, issuer: issuer) {
        case .failure(let reason):
            return .unavailable(reason)
        case .success:
            break
        }

        let nowSeconds = currentTime.timeIntervalSince1970
        if let exp = (claims["exp"] as? NSNumber)?.doubleValue, exp + clockTolerance < nowSeconds {
            return .unavailable("Status List Token expired")
        }
        if let nbf = (claims["nbf"] as? NSNumber)?.doubleValue, nbf - clockTolerance > nowSeconds {
            return .unavailable("Status List Token is not valid yet")
        }

        guard let statusList = claims["status_list"] as? [String: Any] else {
            return .unavailable("Status List Token has no status_list claim")
        }
        guard let bits = (statusList["bits"] as? NSNumber)?.intValue else {
            return .unavailable("Status List Token declares no entry width")
        }
        // Checked here rather than left to readStatus, which can only report
        // "no status at this index" - a misleading thing to tell someone
        // debugging an issuer that published an illegal width.
        guard TokenStatusList.entryWidths.contains(bits) else {
            let allowed = TokenStatusList.entryWidths.sorted().map(String.init).joined(separator: ", ")
            return .unavailable(
                "Status List Token declares an entry width of \(bits) bits; the draft allows \(allowed)"
            )
        }
        guard let lst = statusList["lst"] as? String,
              let inflated = TokenStatusList.inflate(EncryptedContainerBase64.urlDecode(lst))
        else {
            return .unavailable("Status list could not be decompressed")
        }

        let ttl = (statusList["ttl"] as? NSNumber)?.doubleValue
            ?? (claims["ttl"] as? NSNumber)?.doubleValue
            ?? 0
        cache[reference.uri] = TokenStatusList.CacheEntry(
            fetchedAt: currentTime,
            ttlSeconds: ttl,
            bits: bits,
            list: inflated,
            issuer: expectedIssuer,
            expiresAt: (claims["exp"] as? NSNumber).map { Date(timeIntervalSince1970: $0.doubleValue) }
        )

        guard let status = TokenStatusList.readStatus(in: inflated, bits: bits, idx: reference.idx) else {
            return .unavailable("Index \(reference.idx) is outside the status list")
        }
        return .found(status)
    }

    private enum VerificationOutcome {
        case success
        case failure(String)
    }

    /// Verify the token's signature with the issuer's published key.
    ///
    /// Only ES256 is verified, which is the only algorithm DIIP admits. A
    /// token signed with anything else - or by a key this wallet cannot
    /// resolve - is reported as an unavailable status, never as a valid one.
    private func verifySignature(
        segments: [String],
        header: [String: Any],
        issuer: String?
    ) async -> VerificationOutcome {
        guard header["alg"] as? String == "ES256" else {
            return .failure("Unsupported Status List Token algorithm: \(header["alg"] as? String ?? "none")")
        }
        guard let issuer, let resolveIssuerKey else {
            return .failure("No signing key available for the Status List Token")
        }
        guard let jwk = await resolveIssuerKey(issuer, header["kid"] as? String) else {
            return .failure("Could not resolve the Status List Token signing key for \(issuer)")
        }
        guard let x = jwk["x"], let y = jwk["y"] else {
            return .failure("Status List Token signing key is not an EC public key")
        }

        let xData = EncryptedContainerBase64.urlDecode(x)
        let yData = EncryptedContainerBase64.urlDecode(y)
        guard xData.count == 32, yData.count == 32 else {
            return .failure("Status List Token signing key is not a P-256 public key")
        }
        guard let publicKey = try? P256.Signing.PublicKey(
            x963Representation: Data([0x04]) + xData + yData
        ) else {
            return .failure("Status List Token signing key could not be imported")
        }

        let signature = EncryptedContainerBase64.urlDecode(segments[2])
        guard let parsed = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else {
            return .failure("Status List Token signature is malformed")
        }
        let signingInput = Data("\(segments[0]).\(segments[1])".utf8)
        guard publicKey.isValidSignature(parsed, for: signingInput) else {
            return .failure("Status List Token signature is not valid")
        }
        return .success
    }
}

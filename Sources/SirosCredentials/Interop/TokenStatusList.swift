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

        /// The list's own HTTP endpoint could not be reached at all - no
        /// response, of any kind, came back. A caller must treat this as a
        /// warning, not a revocation: a wallet that hid every credential
        /// whose status endpoint happens to be down would be unusable
        /// offline. The ONLY case this fail-open treatment is for - see
        /// ``unavailable(_:)``'s doc comment for why every other failure
        /// mode is a DIFFERENT case, not this one (review finding).
        case unreachable(String)

        /// A response came back, but the status could not be established
        /// from it - wrong `typ`, an issuer/subject mismatch, an expired or
        /// not-yet-valid token, a malformed list, no resolvable signing key,
        /// an invalid signature, and so on. Unlike ``unreachable(_:)``, this
        /// is NOT offline-friendly: a reachable-but-unverifiable response
        /// means revocation cannot be established, which a caller must
        /// treat as `.unknown`/unusable, never as `.valid` - conflating the
        /// two previously let ANY verification failure, a forged/invalid
        /// signature included, read exactly like a wallet that is merely
        /// offline (review finding).
        case unavailable(String)
    }

    /// Read the Status List reference out of a credential's claims, if it has
    /// one.
    public static func extractReference(from claims: [String: Any]) -> Reference? {
        guard let status = claims["status"] as? [String: Any],
              let statusList = status["status_list"] as? [String: Any],
              let idx = exactIndex(statusList["idx"]),
              let uri = statusList["uri"] as? String,
              !uri.isEmpty
        else { return nil }
        return Reference(idx: idx, uri: uri)
    }

    /// Whether `claims` declares a status reference AT ALL, even one
    /// `extractReference` could not parse into a full `Reference` (a bad
    /// `idx`, a missing/empty `uri`, or - review finding - a `status` member
    /// that is not even a map).
    ///
    /// `extractReference`'s nil alone cannot distinguish "this credential
    /// carries no status claim" (an ordinary credential, correctly `.valid`)
    /// from "it carries one this SDK could not read" (attacker-adjacent
    /// data - `mdocValidityClaims` preserves a `status` object even when its
    /// `idx` cannot be represented as `Int`, or `status` itself is a scalar -
    /// neither must be silently treated the same as the first case).
    ///
    /// Any PRESENCE of the `status` key counts as declared (review finding) -
    /// even `{"status":{}}`, an empty object with no `status_list` member at
    /// all. A conformant issuer that means "no revocation tracking" simply
    /// OMITS `status` entirely; one that emits the key with nothing readable
    /// inside it is exactly as attacker-adjacent/unreadable as a `status_list`
    /// with neither `idx` nor `uri` usable, which this already treats as
    /// present rather than absent - the same standard applied consistently
    /// one level up, rather than only once something is nested far enough in
    /// to specifically be `status_list`.
    public static func hasStatusReference(_ claims: [String: Any]) -> Bool {
        claims["status"] != nil
    }

    /// `idx` as an exact, non-negative `Int`, or nil.
    ///
    /// It selects which bit of the status list applies, and it comes from the
    /// credential. `NSNumber.intValue` truncates a fractional value and clamps
    /// one that does not fit - either of which would read some other
    /// credential's status - so the conversion has to be exact. Casting to
    /// `Int` is exactly that: since SE-0170 an `NSNumber` cast fails rather
    /// than losing information.
    private static func exactIndex(_ value: Any?) -> Int? {
        guard let idx = value as? Int, idx >= 0 else { return nil }
        return idx
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

    /// What fetching the Status List Token's own HTTP endpoint produced.
    ///
    /// A plain `Data?` cannot tell ``resolve(_:expectedIssuer:clockTolerance:)``
    /// WHY no data came back, and it needs to know: a genuinely unreachable
    /// endpoint is offline-friendly (``Resolution/unreachable(_:)``), but a
    /// request this wallet's OWN policy refused to even attempt (non-HTTPS, a
    /// private/loopback host, userinfo) or one that reached the server and
    /// got back something other than 2xx is neither "offline" nor safe to
    /// treat the same way - conflating either with genuine unreachability
    /// let a blocked or failing status URI read as `.valid` (review finding).
    public enum FetchOutcome: Sendable {
        /// A response body came back.
        case success(Data)
        /// No response of any kind came back - DNS failure, connection
        /// refused, timeout. The ONE case that is offline-friendly.
        case unreachable
        /// Either the request was never attempted at all (this wallet's own
        /// fetch policy forbade the URL) or it reached the server and got
        /// back a non-2xx response. Both mean "a status check was not
        /// possible", never "offline".
        case rejected
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
    private let httpGet: @Sendable (String, [String: String]) async -> TokenStatusList.FetchOutcome
    private let resolveIssuerKey: (@Sendable (String, String?) async -> [String: String]?)?
    private let now: @Sendable () -> Date
    private var cache: [String: TokenStatusList.CacheEntry] = [:]
    // Oldest-first insertion order, for FIFO eviction once maxCacheEntries is
    // exceeded (review finding): without a bound, a wallet holding many
    // credentials with distinct status-list URIs retains every one of their
    // lists - each up to Inflate's own 64 MiB output cap - for the life of
    // this client, growing memory without limit. A re-inserted (re-fetched)
    // uri is moved back to the end, so repeatedly-consulted lists are the
    // ones that survive eviction.
    private var cacheOrder: [String] = []
    private let maxCacheEntries = 500

    /// - Parameters:
    ///   - httpGet: fetches a URL with the given headers, reporting which of
    ///     ``TokenStatusList/FetchOutcome`` resulted - NOT a plain `Data?`:
    ///     see that type's doc comment for why. Injected so a host's own
    ///     client, pinning and caching apply.
    ///   - resolveIssuerKey: resolves the Status List Token's signing key,
    ///     given the token's issuer identifier and its header `kid`. Key
    ///     resolution is always delegated this way: a certificate chain in the
    ///     token header is deliberately not honoured, because accepting one
    ///     would let any certificate stand in for the key the issuer actually
    ///     publishes. A DID-identified issuer is answered through
    ///     ``DidResolver``; anything else is the host's to answer.
    ///   - now: time source, overridable for deterministic tests.
    public init(
        httpGet: @escaping @Sendable (String, [String: String]) async -> TokenStatusList.FetchOutcome,
        resolveIssuerKey: (@Sendable (String, String?) async -> [String: String]?)? = nil,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.httpGet = httpGet
        self.resolveIssuerKey = resolveIssuerKey
        self.now = now
    }

    /// Drop every cached Status List Token - for a session boundary
    /// (logout, account switch), where a token fetched under the previous
    /// account must not be reused for the next one (review finding): with no
    /// `ttl` (or a long one), a cached entry can otherwise survive logout and
    /// mask a revocation published after it was fetched, served to whichever
    /// account's credentials next point at the same `uri`.
    public func clearCache() {
        cache.removeAll()
        cacheOrder.removeAll()
    }

    /// Record a freshly-verified entry, evicting the oldest one first if
    /// this would exceed `maxCacheEntries` (review finding - see
    /// `cacheOrder`'s doc comment).
    private func setCacheEntry(_ entry: TokenStatusList.CacheEntry, forUri uri: String) {
        if cache[uri] == nil {
            cacheOrder.append(uri)
        } else {
            cacheOrder.removeAll { $0 == uri }
            cacheOrder.append(uri)
        }
        cache[uri] = entry
        while cacheOrder.count > maxCacheEntries {
            let evicted = cacheOrder.removeFirst()
            cache.removeValue(forKey: evicted)
        }
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

        let body: Data
        switch await httpGet(reference.uri, ["Accept": "application/statuslist+jwt"]) {
        case .unreachable:
            // No response of any kind - the one genuinely offline-friendly
            // case (review finding: this used to also catch everything
            // below, which it must not).
            return .unreachable("Could not fetch the status list at \(reference.uri)")
        case .rejected:
            // Either this wallet's own policy refused to even attempt the
            // request, or the server was reached and answered with
            // something other than 2xx. Neither is "offline" (review
            // finding): a blocked or failing status URI must not read as
            // `.valid`.
            return .unavailable("Could not fetch the status list at \(reference.uri)")
        case .success(let data):
            body = data
        }
        guard let token = String(data: body, encoding: .utf8)?
                  .trimmingCharacters(in: .whitespacesAndNewlines),
              !token.isEmpty
        else {
            return .unavailable("Status list at \(reference.uri) was empty")
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
        // §5.1: `sub` binds the token to the URI it was served from - REQUIRED,
        // not merely checked when present (review finding). A token missing
        // `sub` entirely would otherwise pass this check for free and could be
        // served back at any credential status URI the issuer's key signs
        // anything for, defeating the subject-to-URI binding the field exists
        // to enforce.
        let subject = claims["sub"] as? String
        guard subject == reference.uri else {
            return .unavailable(
                "Status List Token subject \(subject ?? "<missing>") does not match \(reference.uri)"
            )
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
        // Exactly, not `intValue`: that truncates, so a published width of 1.5
        // would be read as 1 and pass the check below. `bits` decides how the
        // list is carved up, so a wrong width reads the wrong credential's
        // status.
        guard let bits = statusList["bits"] as? Int else {
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
        setCacheEntry(
            TokenStatusList.CacheEntry(
                fetchedAt: currentTime,
                ttlSeconds: ttl,
                bits: bits,
                list: inflated,
                issuer: expectedIssuer,
                expiresAt: (claims["exp"] as? NSNumber).map { Date(timeIntervalSince1970: $0.doubleValue) }
            ),
            forUri: reference.uri
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
        // kty/crv checked explicitly, not inferred from x/y merely being
        // present (review finding): a JWKS entry for a different key type or
        // purpose - an RSA key, or an EC key on a different curve - that
        // happens to also carry members named `x`/`y` would otherwise still
        // be imported and treated as valid ES256/P-256 material.
        guard jwk["kty"] == "EC", jwk["crv"] == "P-256" else {
            return .failure("Status List Token signing key is not an EC P-256 public key")
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

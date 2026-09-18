// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosCredentials

/// DIIP's Validity and Revocation Algorithm, run over the credentials this
/// wallet holds: the `validFrom` / `validUntil` window, then the issuer's
/// Token Status List.
///
/// A host app renders the outcome and computes none of it - establishing
/// revocation means fetching and verifying a Status List Token, which is not
/// something a UI layer should be doing.
extension SirosWallet {

    /// The DIIP release this wallet follows when it speaks
    /// ``InteropProfile/diip`` - see ``DiipProfile``.
    public var diipProfile: DiipProfile { config.diipProfile }

    /// The interoperability profile this wallet speaks with `issuer` when
    /// nothing else decides - see ``InteropProfile``.
    ///
    /// A per-Issuer override wins over the wallet-wide default. The match is
    /// by prefix so that a `credential_issuer` with a path under a configured
    /// base counts, and the longest configured prefix wins so a specific entry
    /// is not shadowed by a broader one. This is an escape hatch for an Issuer
    /// whose metadata is wrong, not the normal path: see
    /// ``holderBinding(for:)``.
    public func interopProfile(for issuer: String?) -> InteropProfile {
        issuerOverride(for: issuer) ?? config.interopProfile
    }

    /// The configured override for `issuer`, if a specific one was set.
    ///
    /// Compared as URLs, not as strings. A string prefix test matches
    /// `https://issuer.example.evil` against an override for
    /// `https://issuer.example` - a different domain handed another issuer's
    /// configuration - and `https://issuer.example@evil.com/x` too, where the
    /// part that looks like the configured issuer is only userinfo and the
    /// real host is someone else's. Both are the same bug wearing different
    /// clothes: whoever controls the matched string controls which profile is
    /// used.
    ///
    /// So: scheme, host and port must be equal, the path must be the
    /// configured one or a segment under it, and a URL carrying userinfo never
    /// matches - a legitimate `credential_issuer` has none, and accepting one
    /// only reopens the trick above.
    func issuerOverride(for issuer: String?) -> InteropProfile? {
        guard let issuer, let candidate = URL(string: issuer) else { return nil }
        return config.issuerInteropProfiles
            .filter { entry in Self.sameIssuer(candidate, entry.key) }
            .max { $0.key.count < $1.key.count }?
            .value
    }

    /// The port a URL actually addresses: the explicit one, else the
    /// scheme's default.
    static func effectivePort(of url: URL) -> Int? {
        if let port = url.port { return port }
        switch url.scheme?.lowercased() {
        case "https": return 443
        case "http": return 80
        default: return nil
        }
    }

    static func sameIssuer(_ candidate: URL, _ configured: String) -> Bool {
        guard let base = URL(string: configured),
              candidate.user == nil, candidate.password == nil,
              base.user == nil, base.password == nil,
              candidate.scheme?.lowercased() == base.scheme?.lowercased(),
              candidate.host?.lowercased() == base.host?.lowercased(),
              // Effective ports, not the literal ones: `URL.port` is nil when
              // the port is implicit, so comparing directly makes
              // `https://issuer.example` and `https://issuer.example:443`
              // look like different issuers and silently drops the override.
              Self.effectivePort(of: candidate) == Self.effectivePort(of: base)
        else { return false }

        func trimmed(_ path: String) -> String {
            path.hasSuffix("/") ? String(path.dropLast()) : path
        }
        let basePath = trimmed(base.path)
        let candidatePath = trimmed(candidate.path)
        if basePath.isEmpty { return true }
        return candidatePath == basePath || candidatePath.hasPrefix(basePath + "/")
    }

    /// How the Holder's key should be named in an OID4VCI proof to `issuer` -
    /// the one thing HAIP and DIIP genuinely disagree about, and something
    /// OID4VCI makes a per-issuance choice.
    ///
    /// **Negotiated, not configured.** The Issuer's own
    /// `cryptographic_binding_methods_supported` for the configuration being
    /// issued says which identifier it can verify, so a wallet holding
    /// credentials from a HAIP ecosystem and a DIIP ecosystem shapes each
    /// proof to its Issuer without anyone choosing a profile. A user cannot
    /// reasonably be asked which of two interoperability profiles an issuer
    /// they just scanned belongs to, and does not have to be.
    ///
    /// The configured profile is only the fallback, for an Issuer that
    /// advertises nothing usable - and the per-Issuer override the escape
    /// hatch above that, for one that advertises the wrong thing.
    ///
    /// Handed to `KeystoreManager.generateProof` so the keystore never has to
    /// know about issuers.
    public func holderBinding(for issuer: String?) -> HolderBinding {
        // An explicit per-Issuer override comes first. It exists precisely for
        // an Issuer whose metadata advertises the wrong thing, so letting the
        // metadata win would leave it with nothing to override.
        if let override = issuerOverride(for: issuer) {
            return override.holderBinding
        }

        let advertised = activeOffer
            .flatMap { offer -> [String]? in
                guard issuer == nil || offer.credentialIssuerIdentifier == issuer else { return nil }
                return offer.cryptographicBindingMethodsSupported
            }
        if let negotiated = HolderBinding.negotiate(advertised) {
            return negotiated
        }
        return config.interopProfile.holderBinding
    }

    /// Evaluate one credential's status.
    ///
    /// The result is cached; ``refreshCredentialStatuses()`` re-runs it. A
    /// status list that cannot be reached leaves the credential
    /// ``CredentialStatus/valid`` rather than hiding it, which is what keeps
    /// the wallet usable offline.
    public func credentialStatus(of credential: StoredCredential) async -> CredentialStatus {
        guard let claims = CredentialUtils.validityClaims(credential) else { return .valid }
        let status = await credentialStatusEvaluator.evaluate(claims: claims)
        credentialStatusCache.set(credential.id, status)
        return status
    }

    /// The last known status of a credential, without network access or
    /// re-evaluation - for synchronous call sites such as a SwiftUI body.
    /// ``CredentialStatus/valid`` until ``refreshCredentialStatuses()`` has
    /// run.
    public func cachedCredentialStatus(of credentialId: Int64) -> CredentialStatus {
        credentialStatusCache.get(credentialId)
    }

    /// Re-evaluate every held credential, and return the statuses by
    /// credential id.
    @discardableResult
    public func refreshCredentialStatuses() async -> [Int64: CredentialStatus] {
        var statuses: [Int64: CredentialStatus] = [:]
        for credential in await credentialStore.getAll() {
            statuses[credential.id] = await credentialStatus(of: credential)
        }
        credentialStatusCache.retain(Set(statuses.keys))
        return statuses
    }

    /// Resolve a DID to its document, for the methods ``diipProfile``
    /// requires - an Issuer's signing key, or a Verifier's identity.
    public func resolveDid(_ did: String) async -> DidResolution {
        await didResolver.resolve(did)
    }

    /// The signing key an issuer publishes, for verifying a Status List Token
    /// it signed.
    ///
    /// Resolved through ``DidResolver``, so `did:web` and anything else that
    /// needs resolving goes to go-trust rather than being fetched here. A
    /// status list whose key cannot be resolved goes unverified, which the
    /// reader reports as an unavailable status, never as a valid one.
    static func resolveIssuerSigningKey(
        issuer: String,
        kid: String?,
        resolver: DidResolver,
        profile: DiipProfile
    ) async -> [String: String]? {
        if DidMethod.of(issuer) != nil {
            return await resolver.resolve(issuer).document?
                .findPublicKey(kid: kid, relationship: .assertionMethod)
        }
        return await resolveHttpsIssuerSigningKey(issuer: issuer, kid: kid, profile: profile)
    }

    /// The signing key an HTTPS-identified Issuer publishes, from its SD-JWT
    /// VC issuer metadata (`jwks`, or `jwks_uri`).
    ///
    /// Most Issuers are identified by an HTTPS URL rather than a DID, so
    /// without this the Token Status List could never be verified for them and
    /// every revocation check would degrade to "unavailable" - which this SDK
    /// deliberately treats as usable, so revocation would silently never
    /// apply.
    ///
    /// This is not a trust decision and does not pretend to be one. The path
    /// is derived from the Issuer's own identifier, so there is no choice of
    /// authority to make - unlike DID method resolution, which is go-trust's
    /// (see ``DidResolver``). Whether this Issuer is trusted at all is
    /// answered by the issuer trust list, the same as for the credential
    /// itself; all this does is obtain the key that Issuer publishes under its
    /// own name.
    ///
    /// The well-known suffix moves with the profile: SD-JWT VC renamed it
    /// between drafts, so it comes from
    /// ``DiipProfile/sdJwtVcIssuerMetadataPath`` rather than being hardcoded.
    /// Both spellings are tried, since an issuer pinned to the other draft is
    /// common.
    static func resolveHttpsIssuerSigningKey(
        issuer: String,
        kid: String?,
        profile: DiipProfile
    ) async -> [String: String]? {
        guard issuer.hasPrefix("https://") else { return nil }
        // Trim every trailing slash, not just one: the well-known path
        // carries its own leading slash.
        var base = issuer
        while base.hasSuffix("/") { base.removeLast() }

        var paths = [profile.sdJwtVcIssuerMetadataPath]
        for fallback in ["/.well-known/jwt-vc-issuer", "/.well-known/vc-issuer"]
        where !paths.contains(fallback) {
            paths.append(fallback)
        }

        for path in paths {
            guard let body = await fetchPublicUrl(base + path, headers: [:]),
                  let keys = await issuerJwks(metadata: body)
            else { continue }
            if let key = selectIssuerKey(keys, kid: kid) { return key }
        }
        return nil
    }

    /// The JWK set an SD-JWT VC issuer metadata document points at, inline or
    /// by reference.
    static func issuerJwks(metadata body: Data) async -> [[String: Any]]? {
        guard let metadata = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            return nil
        }
        if let jwks = metadata["jwks"] as? [String: Any], let keys = jwks["keys"] as? [[String: Any]] {
            return keys
        }
        guard let uri = metadata["jwks_uri"] as? String,
              let referenced = await fetchPublicUrl(uri, headers: [:]),
              let jwks = try? JSONSerialization.jsonObject(with: referenced) as? [String: Any],
              let keys = jwks["keys"] as? [[String: Any]]
        else { return nil }
        return keys
    }

    /// Pick the key a Status List Token's `kid` names, or the only usable one
    /// when it named none. A set with several keys and no `kid` is ambiguous,
    /// and guessing there would mean accepting a signature from whichever key
    /// happened to be first.
    static func selectIssuerKey(_ keys: [[String: Any]], kid: String?) -> [String: String]? {
        // A key carrying private material is not something an issuer publishes
        // for verification; refusing it keeps a misconfigured JWKS from being
        // treated as a verification key.
        let usable = keys.filter { $0["d"] == nil && $0["k"] == nil }
        let match: [String: Any]?
        if let kid {
            match = usable.first { ($0["kid"] as? String) == kid }
        } else {
            match = usable.count == 1 ? usable[0] : nil
        }
        return match?.compactMapValues { $0 as? String }
    }

    /// Fetch a URL that belongs to a third party - an issuer's Status List
    /// Token, named by a URI inside the credential itself.
    ///
    /// Only documents whose location the credential already states, never DID
    /// resolution: which document is authoritative for an identifier is
    /// go-trust's decision (see ``DidResolver``). The Status List Token's own
    /// signing key is still resolved through that path, so fetching the list
    /// is not a trust decision.
    ///
    /// These carry NO wallet credentials: attaching this wallet's bearer token
    /// or tenant id to a request at an arbitrary domain would leak them.
    static func fetchPublicUrl(_ urlString: String, headers: [String: String]) async -> Data? {
        guard let url = URL(string: urlString) else { return nil }
        var request = URLRequest(url: url)
        for (name, value) in headers {
            request.setValue(value, forHTTPHeaderField: name)
        }
        guard let (data, response) = try? await thirdPartySession.data(for: request),
              let http = response as? HTTPURLResponse,
              (200..<300).contains(http.statusCode)
        else { return nil }
        return data
    }
}

/// The session third-party fetches go out on.
///
/// Not attaching an `Authorization` header is not enough on its own to say a
/// request carries no wallet credentials: `URLSession.shared` keeps a shared
/// cookie store and credential cache, so a cookie set by one of this wallet's
/// own hosts would ride along to a third-party domain that happens to match -
/// a leak no call site can see, because nothing at the call site mentions
/// cookies. An ephemeral configuration with the cookie and credential storage
/// removed is what makes the guarantee in `fetchPublicUrl` true rather than
/// merely intended.
private let thirdPartySession: URLSession = {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.httpCookieStorage = nil
    configuration.httpCookieAcceptPolicy = .never
    configuration.httpShouldSetCookies = false
    configuration.urlCredentialStorage = nil
    configuration.urlCache = nil
    configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
    return URLSession(configuration: configuration)
}()

/// A small mutable cache of evaluated statuses.
///
/// `SirosWallet` is a `final class`, not an actor, so this holds its own lock
/// rather than relying on the wallet's isolation.
final class CredentialStatusCache: @unchecked Sendable {
    private let lock = NSLock()
    private var statuses: [Int64: CredentialStatus] = [:]

    func get(_ id: Int64) -> CredentialStatus {
        lock.lock()
        defer { lock.unlock() }
        return statuses[id] ?? .valid
    }

    func set(_ id: Int64, _ status: CredentialStatus) {
        lock.lock()
        defer { lock.unlock() }
        statuses[id] = status
    }

    /// Drop everything not in `ids` - a credential that has been deleted
    /// should not keep a stale status alive.
    func retain(_ ids: Set<Int64>) {
        lock.lock()
        defer { lock.unlock() }
        statuses = statuses.filter { ids.contains($0.key) }
    }

    /// All held statuses, e.g. after a logout.
    func clear() {
        lock.lock()
        defer { lock.unlock() }
        statuses.removeAll()
    }
}

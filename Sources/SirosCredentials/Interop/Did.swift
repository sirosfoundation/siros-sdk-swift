// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// A DID method this SDK knows by name.
public enum DidMethod: String, Sendable, CaseIterable {
    /// `did:jwk` - the key itself, base64url-encoded into the identifier.
    /// Resolves offline.
    case jwk

    /// `did:web` - the DID document served over HTTPS from a domain the DID
    /// names.
    case web

    /// `did:webvh` - `did:web` plus a verifiable, append-only history of the
    /// document. A DIIP Future Direction, not yet required by any release.
    case webvh

    /// `did:key` - the key encoded as a multicodec. Predates DIIP in this SDK
    /// and in wallet-frontend; a wallet holding credentials bound to one keeps
    /// working, but no DIIP version requires it.
    case key

    /// The method of a DID string, or nil if it is not a DID or the method is
    /// unknown.
    public static func of(_ did: String) -> DidMethod? {
        guard did.hasPrefix("did:") else { return nil }
        let method = did.dropFirst("did:".count).prefix { $0 != ":" }
        return DidMethod(rawValue: String(method))
    }
}

/// Which verification relationship a key is being looked up for.
public enum DidRelationship: Sendable {
    case authentication
    case assertionMethod
    case any
}

/// One verification method of a ``DidDocument``.
public struct VerificationMethod: Sendable, Equatable {
    public let id: String
    public let type: String
    public let controller: String
    /// The public key as a JWK. Only `JsonWebKey2020`-shaped methods carry one.
    public let publicKeyJwk: [String: String]?

    public init(id: String, type: String, controller: String, publicKeyJwk: [String: String]?) {
        self.id = id
        self.type = type
        self.controller = controller
        self.publicKeyJwk = publicKeyJwk
    }
}

/// The subset of a DID document this SDK reads: the verification methods and
/// which relationships they take part in.
///
/// DIIP names keys by relationship - an Issuer signs with a key from
/// `assertionMethod`, a Holder's `cnf.kid` points into `authentication` - so a
/// document is only useful here if it keeps that distinction.
public struct DidDocument: Sendable, Equatable {
    /// The DID this document describes.
    public let id: String
    /// Verification methods by their full id (`<did>#<fragment>`).
    public let verificationMethods: [String: VerificationMethod]
    /// Verification method ids in the `authentication` relationship.
    public let authentication: [String]
    /// Verification method ids in the `assertionMethod` relationship.
    public let assertionMethod: [String]

    public init(
        id: String,
        verificationMethods: [String: VerificationMethod],
        authentication: [String] = [],
        assertionMethod: [String] = []
    ) {
        self.id = id
        self.verificationMethods = verificationMethods
        self.authentication = authentication
        self.assertionMethod = assertionMethod
    }

    /// The public JWK named by `kid` within `relationship`.
    ///
    /// A nil `kid` means "whichever key this relationship has", which is the
    /// only thing a verifier can do when the credential or proof did not name
    /// one - unambiguous for `did:jwk`, which has exactly one.
    public func findPublicKey(kid: String?, relationship: DidRelationship) -> [String: String]? {
        let ids: [String]
        switch relationship {
        case .authentication: ids = authentication
        case .assertionMethod: ids = assertionMethod
        case .any: ids = Array(verificationMethods.keys)
        }
        // A document that lists no relationship at all still resolves: DID
        // Core lets a method's verification methods be used for any purpose
        // unless the document narrows it.
        let candidates = ids.isEmpty && relationship != .any ? Array(verificationMethods.keys) : ids

        let match: String?
        if let kid {
            // A `kid` may be the absolute DID URL, or just the fragment.
            let wantedFragment = kid.firstIndex(of: "#").map { String(kid[kid.index(after: $0)...]) } ?? kid
            match = candidates.first { $0 == kid || $0.hasSuffix("#" + wantedFragment) }
        } else {
            match = candidates.first
        }
        guard let match else { return nil }
        return verificationMethods[match]?.publicKeyJwk
    }
}

/// What a resolution attempt produced.
public enum DidResolution: Sendable {
    case resolved(DidDocument)

    /// Resolution did not produce a document. This is a failure, never a
    /// silently-empty success: a caller that cannot tell the two apart would
    /// treat an unreachable issuer as an unsigned credential.
    case failed(did: String, reason: String)

    /// The document if resolution succeeded, else nil.
    public var document: DidDocument? {
        if case .resolved(let document) = self { return document }
        return nil
    }
}

/// Resolves the DID methods DIIP requires.
///
/// `did:jwk` resolves offline - the key *is* the identifier - so it needs no
/// network and cannot fail for connectivity reasons. `did:web` is an HTTPS
/// fetch. `did:webvh` is recognised but deliberately not resolved: see
/// ``DidResolver/resolve(_:)``.
public actor DidResolver {
    private let profile: DiipProfile
    private let httpGet: @Sendable (String) async -> Data?

    /// - Parameters:
    ///   - profile: decides which methods are in scope; a method outside the
    ///     profile still resolves if this SDK can, since DIIP explicitly does
    ///     not forbid identifiers it does not require.
    ///   - httpGet: fetches a URL, returning the body or nil. Injected so a
    ///     host can supply its own client, pinning and caching.
    public init(
        profile: DiipProfile = .latest,
        httpGet: @escaping @Sendable (String) async -> Data?
    ) {
        self.profile = profile
        self.httpGet = httpGet
    }

    /// The methods `profile` requires a compliant wallet to resolve.
    public var requiredMethods: Set<DidMethod> { profile.resolvableDidMethods }

    /// Resolve any DID this SDK supports.
    public func resolve(_ did: String) async -> DidResolution {
        switch DidMethod.of(did) {
        case .jwk:
            return Did.resolveDidJwk(did)
        case .web:
            return await resolveWeb(did)
        case .webvh:
            // `did:webvh` is not resolved. Its whole value over `did:web` is
            // that the document's history is verifiable: every log entry
            // carries a Data Integrity proof and a hash linking it to its
            // predecessor, and a resolver that skips those checks offers
            // exactly the trust of `did:web` while looking like more. Failing
            // here is the safe default - a caller sees an unresolved DID
            // rather than an unverified document. The method is listed in
            // v6's `resolvableDidMethods` so the gap is visible, not silent.
            return .failed(
                did: did,
                reason: "did:webvh resolution requires verifying the DID log's proof chain, which is not yet implemented"
            )
        case .key:
            return .failed(did: did, reason: "did:key resolution is not implemented")
        case nil:
            return .failed(did: did, reason: "Not a DID, or an unsupported DID method: \(did)")
        }
    }

    private func resolveWeb(_ did: String) async -> DidResolution {
        guard let url = Did.didWebToUrl(did) else {
            return .failed(did: did, reason: "Malformed did:web identifier")
        }
        guard let body = await httpGet(url) else {
            return .failed(did: did, reason: "Could not fetch DID document from \(url)")
        }
        guard let root = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let document = Did.parseDidDocument(root)
        else {
            return .failed(did: did, reason: "DID document at \(url) is not a DID document")
        }
        guard document.id == did else {
            // A document that names a different subject would let any domain
            // serve a document for any DID.
            return .failed(did: did, reason: "DID document at \(url) declares id '\(document.id)'")
        }
        return .resolved(document)
    }
}

/// DID construction, resolution and parsing that needs no I/O.
public enum Did {

    /// Build a `did:jwk` from a public JWK.
    ///
    /// The method-specific identifier is the base64url encoding of the JWK, so
    /// the same key must always serialize identically: WebCrypto bookkeeping
    /// (`ext`, `key_ops`) and any private key material are stripped, and
    /// members are emitted in a fixed order.
    ///
    /// - SeeAlso: [did:jwk](https://github.com/quartzjer/did-jwk/blob/main/spec.md)
    public static func createDidJwk(_ publicKeyJwk: [String: String]) -> String {
        let canonical = canonicalPublicJwk(publicKeyJwk)
        let json = "{" + canonical.map { "\"\($0.0)\":\"\($0.1)\"" }.joined(separator: ",") + "}"
        return "did:jwk:" + EncryptedContainerBase64.urlEncode(Data(json.utf8))
    }

    /// The verification method id of a `did:jwk`'s only key.
    ///
    /// A did:jwk document has exactly one verification method, `#0`, which is
    /// why DIIP can say "a `kid` from the `authentication` relationship" and a
    /// wallet can produce it without resolving anything.
    public static func didJwkKeyId(_ did: String) -> String { did + "#0" }

    /// Resolve a `did:jwk` - no network, and no failure mode other than a
    /// malformed identifier, since the key is the identifier.
    public static func resolveDidJwk(_ did: String) -> DidResolution {
        guard did.hasPrefix("did:jwk:") else {
            return .failed(did: did, reason: "Not a did:jwk")
        }
        let encoded = did.dropFirst("did:jwk:".count)
            .prefix { $0 != "#" && $0 != "?" }
        let decoded = EncryptedContainerBase64.urlDecode(String(encoded))
        guard !decoded.isEmpty,
              let jwk = try? JSONSerialization.jsonObject(with: decoded) as? [String: Any]
        else {
            return .failed(did: did, reason: "did:jwk identifier is not a base64url-encoded JWK")
        }
        let vmId = didJwkKeyId(did)
        let method = VerificationMethod(
            id: vmId,
            type: "JsonWebKey2020",
            controller: did,
            publicKeyJwk: jwk.compactMapValues { $0 as? String }
        )
        return .resolved(
            DidDocument(
                id: did,
                verificationMethods: [vmId: method],
                authentication: [vmId],
                assertionMethod: [vmId]
            )
        )
    }

    /// Map a `did:web` identifier to the URL its document is served from.
    ///
    /// `did:web:example.com` -> `https://example.com/.well-known/did.json`;
    /// `did:web:example.com:a:b` -> `https://example.com/a/b/did.json`. A port
    /// is percent-encoded in the DID (`example.com%3A8443`).
    public static func didWebToUrl(_ did: String) -> String? {
        guard did.hasPrefix("did:web:") else { return nil }
        let idPart = did.dropFirst("did:web:".count).prefix { $0 != "#" && $0 != "?" }
        guard !idPart.isEmpty else { return nil }
        let segments = idPart.split(separator: ":", omittingEmptySubsequences: false)
            .map { $0.removingPercentEncoding ?? String($0) }
        guard let host = segments.first, !host.isEmpty else { return nil }
        let path = segments.dropFirst()
        if path.isEmpty {
            return "https://\(host)/.well-known/did.json"
        }
        return "https://\(host)/\(path.joined(separator: "/"))/did.json"
    }

    /// Parse a DID document JSON object into the subset this SDK reads.
    public static func parseDidDocument(_ root: [String: Any]) -> DidDocument? {
        guard let id = root["id"] as? String else { return nil }
        var methods: [String: VerificationMethod] = [:]

        func absolute(_ ref: String) -> String { ref.hasPrefix("#") ? id + ref : ref }

        // A relationship entry is either a reference to a verification method
        // declared elsewhere in the document, or the method inlined.
        func register(_ element: Any) -> String? {
            if let ref = element as? String { return absolute(ref) }
            guard let object = element as? [String: Any],
                  let rawId = object["id"] as? String
            else { return nil }
            let vmId = absolute(rawId)
            methods[vmId] = VerificationMethod(
                id: vmId,
                type: object["type"] as? String ?? "",
                controller: object["controller"] as? String ?? id,
                publicKeyJwk: (object["publicKeyJwk"] as? [String: Any])?.compactMapValues { $0 as? String }
            )
            return vmId
        }

        (root["verificationMethod"] as? [Any])?.forEach { _ = register($0) }

        func relationship(_ name: String) -> [String] {
            (root[name] as? [Any])?.compactMap { register($0) } ?? []
        }

        // Both relationships are resolved BEFORE the document is built: an
        // inlined verification method is registered as a side effect of
        // reading the relationship that carries it, so reading `methods` any
        // earlier would miss it.
        let authentication = relationship("authentication")
        let assertionMethod = relationship("assertionMethod")

        return DidDocument(
            id: id,
            verificationMethods: methods,
            authentication: authentication,
            assertionMethod: assertionMethod
        )
    }

    /// Strip a JWK down to the members that identify the public key, in a
    /// fixed order, so that the same key always yields the same `did:jwk`.
    ///
    /// The members kept are exactly RFC 7638's required ones for the key type
    /// - the same set a JWK thumbprint is computed over. That is what makes
    /// the mapping one-to-one: a key that also carries `alg`, `use`, `kid` or
    /// WebCrypto bookkeeping (`ext`, `key_ops`) must not get a different DID
    /// from the same key without them, or one wallet's `did:jwk` stops
    /// matching another's for the same key pair. Private members never reach a
    /// DID at all.
    ///
    /// The order is lexicographic, which is not an arbitrary choice either: it
    /// is both RFC 7638's canonicalization and what wallet-frontend ends up
    /// emitting (it stringifies a WebCrypto `exportKey("jwk")` result, which
    /// comes back alphabetically ordered, with `ext`/`key_ops` destructured
    /// away). The same key has to produce the same DID on every client that
    /// reads the shared `privatedata` container, so this has to match rather
    /// than merely be stable.
    static func canonicalPublicJwk(_ jwk: [String: String]) -> [(String, String)] {
        let required: [String]
        switch jwk["kty"] {
        case "EC": required = ["crv", "kty", "x", "y"]
        case "OKP": required = ["crv", "kty", "x"]
        case "RSA": required = ["e", "kty", "n"]
        case "oct": required = ["k", "kty"]
        // An unknown key type has no defined required set; keeping only what
        // is certainly part of every JWK is safer than guessing a wider one.
        default: required = ["kty"]
        }
        return required.compactMap { member in jwk[member].map { (member, $0) } }
    }

    /// The `kid` a credential's `cnf` claim binds it to.
    ///
    /// DIIP binds the Holder with a `cnf.kid` naming a verification method of
    /// their DID document. Credentials predating that carry `cnf.jwk` and are
    /// addressed by JWK thumbprint, which is what this SDK has always used as
    /// a local key id. Returns nil when the credential has no holder binding
    /// at all.
    public static func resolveCnfKid(
        _ cnf: [String: Any]?,
        thumbprintOf: ([String: Any]) -> String?
    ) -> String? {
        if let kid = cnf?["kid"] as? String { return kid }
        if let jwk = cnf?["jwk"] as? [String: Any] { return thumbprintOf(jwk) }
        return nil
    }
}

/// base64url without padding, kept here so `SirosCredentials` does not depend
/// on `SirosKeystore`'s copy - this module is the lower of the two.
enum EncryptedContainerBase64 {
    static func urlEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func urlDecode(_ string: String) -> Data {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder > 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        return Data(base64Encoded: base64) ?? Data()
    }
}

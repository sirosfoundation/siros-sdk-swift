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
        guard let name = methodName(of: did) else { return nil }
        return DidMethod(rawValue: name)
    }

    /// The method name of any syntactically valid DID, named here or not.
    ///
    /// Which DID methods actually resolve is go-trust's answer, not this
    /// SDK's. ``of(_:)`` only says whether this SDK knows a method by name -
    /// which is what a profile's list of required methods is about - and must
    /// not be used to decide what may be delegated.
    public static func methodName(of did: String) -> String? {
        guard did.hasPrefix("did:") else { return nil }
        let rest = did.dropFirst("did:".count)
        let method = rest.prefix { $0 != ":" }
        // A DID is `did:<method>:<id>`; a method with no identifier after it
        // is not one.
        guard !method.isEmpty, method.endIndex < rest.endIndex else { return nil }
        let identifier = rest[rest.index(after: method.endIndex)...]
        guard !identifier.isEmpty else { return nil }
        return String(method)
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
        // No fallback to "every verification method" for a NAMED relationship.
        // A key the controller did not place in `assertionMethod` is not
        // authorized to assert, and treating an empty relationship as "all
        // keys" would let an Issuer's DID document sign credentials with a key
        // it only published for, say, key agreement. Fail closed; `.any` is
        // the one caller that legitimately means "whichever key this document
        // has" (resolving a did:jwk back to its own key).
        let candidates = ids

        let match: String?
        if let kid {
            // A `kid` may be the absolute DID URL, or just the fragment.
            let wantedFragment = kid.firstIndex(of: "#").map { String(kid[kid.index(after: $0)...]) } ?? kid
            match = candidates.first { $0 == kid || $0.hasSuffix("#" + wantedFragment) }
        } else {
            // With no `kid` to go on, only one key is unambiguous. Taking the
            // first would make verification depend on document order: a token
            // signed by another of the issuer's assertion keys would be
            // rejected, and an unsigned-for key could be accepted instead.
            // Same rule as `selectIssuerKey` applies to a published JWKS.
            match = candidates.count == 1 ? candidates[0] : nil
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

/// How a DID that needs resolving is resolved.
///
/// Deliberately a protocol this SDK does not implement for the network
/// methods. DID method resolution is a trust decision - which document is
/// authoritative for an identifier - and in SIROS that lives in go-trust,
/// reached through go-wallet-backend's engine. A wallet that fetched
/// `did:web` documents itself would be making that decision locally, with its
/// own idea of which hosts to believe, and silently diverging from whatever
/// the deployment's trust registry says.
///
/// `SirosWallet` supplies an implementation backed by the backend's
/// `/v1/resolve`; a host composing the lower-level modules supplies its own.
///
/// Returns the resolved DID document as JSON, or nil if it could not be
/// resolved. Nil is a failure, never an empty success - see ``DidResolution``.
public typealias DidResolutionDelegate = @Sendable (String) async -> [String: Any]?

/// Resolves the DIDs a wallet encounters.
///
/// `did:jwk` is resolved here, locally and offline: the key *is* the
/// identifier, so there is no document to fetch, nobody to ask, and no trust
/// decision to delegate - the same reason wallet-frontend resolves it locally
/// too. Every other method is handed to the delegate, which routes it to
/// go-trust. This split is the whole design: the SDK answers only the question
/// that has an arithmetic answer, and never the one that needs a trust
/// registry.
public actor DidResolver {
    private let profile: DiipProfile
    private let delegate: DidResolutionDelegate?

    /// - Parameters:
    ///   - profile: decides which methods a compliant wallet must be able to
    ///     resolve, which is what ``requiredMethods`` reports. It does not
    ///     restrict what gets resolved: a method outside it - or one this SDK
    ///     does not know by name at all - is still delegated, since DIIP
    ///     explicitly does not forbid identifiers it does not require, and
    ///     which methods resolve is go-trust's answer rather than this SDK's.
    ///   - delegate: resolves everything except `did:jwk`. Nil means a wallet
    ///     with no resolution authority configured: `did:jwk` still works, and
    ///     anything else fails rather than being fetched directly.
    public init(profile: DiipProfile = .latest, delegate: DidResolutionDelegate? = nil) {
        self.profile = profile
        self.delegate = delegate
    }

    /// The methods `profile` requires a compliant wallet to resolve.
    public var requiredMethods: Set<DidMethod> { profile.resolvableDidMethods }

    /// Resolve any DID this wallet can.
    public func resolve(_ did: String) async -> DidResolution {
        // Any syntactically valid DID is resolvable as far as this SDK is
        // concerned. Enumerating the methods here would make the SDK the
        // authority on which of them exist, and it is not: go-trust is, and a
        // method it learns about must not need an SDK release.
        guard let method = DidMethod.methodName(of: did) else {
            return .failed(did: did, reason: "Not a DID: \(did)")
        }

        // did:jwk carries its own key. Sending it to a resolution service
        // would add a network round trip, a dependency, and a failure mode,
        // for an answer that is already in the identifier.
        if method == DidMethod.jwk.rawValue { return Did.resolveDidJwk(did) }

        guard let delegate else {
            return .failed(
                did: did,
                reason: "No DID resolution delegate configured; \(method) resolution is the backend's to perform"
            )
        }
        guard let document = await delegate(did) else {
            return .failed(did: did, reason: "Could not resolve \(did)")
        }
        guard let parsed = Did.parseDidDocument(document) else {
            return .failed(did: did, reason: "Resolution of \(did) did not return a DID document")
        }
        guard parsed.id == did else {
            // A document naming a different subject is not this DID's
            // document, whoever returned it.
            return .failed(did: did, reason: "Resolved document declares id '\(parsed.id)'")
        }
        return .resolved(parsed)
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

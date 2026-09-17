// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Represents a parsed OID4VP client_id_scheme with its normalized identifier.
///
/// The client_id on the wire uses a prefix convention (e.g., "x509_san_dns:hostname")
/// to indicate how the verifier identifies itself. This enum provides type-safe
/// access to the parsed components.
///
/// Two generations of that convention are in the field. OID4VP draft 28 wrote
/// a DID-identified Verifier as the bare DID, with the scheme carried out of
/// band in `client_id_scheme`. OID4VP 1.0 Final replaced that with Client
/// Identifier Prefixes, where the prefix is part of the `client_id` itself -
/// `decentralized_identifier:did:web:verifier.example`,
/// `redirect_uri:https://...`, `openid_federation:https://...`. DIIP requires
/// the `did` scheme, which is why the prefixed spelling has to parse, but a
/// wallet has to read both to talk to both generations of Verifier - see
/// `DiipProfile.clientIdStyle` for which one a given profile version says a
/// compliant Verifier sends.
public enum ClientIdScheme: Sendable {
    /// X.509 SAN DNS — verifier identified by hostname in certificate SAN.
    case x509SanDns(hostname: String)
    /// X.509 SAN URI — verifier identified by URI in certificate SAN.
    case x509SanUri(uri: String)
    /// DID-based — verifier identified by a Decentralized Identifier.
    case did(did: String, method: String)
    /// Verifier attestation — verifier authenticated via third-party attestation JWT.
    case verifierAttestation(subject: String)
    /// HTTPS URL — verifier identified by URL (redirect_uri scheme or unsigned).
    case https(url: String)
    /// OpenID Federation — verifier identified by an Entity Identifier whose
    /// trust chain resolves to a trust anchor. DIIP's optional trust
    /// establishment mechanism.
    case openIdFederation(entityId: String)
    /// X.509 certificate hash — the verifier's certificate identified by the
    /// base64url SHA-256 of its DER encoding, not by a name.
    case x509Hash(hash: String)
    /// Pre-registered or unknown scheme — catch-all.
    case preRegistered(clientId: String)

    /// The normalized identifier for this scheme.
    public var identifier: String {
        switch self {
        case .x509SanDns(let hostname): return hostname
        case .x509SanUri(let uri): return uri
        case .did(let did, _): return did
        case .verifierAttestation(let subject): return subject
        case .https(let url): return url
        case .openIdFederation(let entityId): return entityId
        case .x509Hash(let hash): return hash
        case .preRegistered(let clientId): return clientId
        }
    }

    /// A user-facing identifier with the scheme prefix stripped - a raw
    /// client_id like "x509_san_dns:verifier.multipaz.org" is meaningless to
    /// a user; the hostname alone is what matters. Falls back to
    /// `identifier` when no hostname can be extracted (e.g. a non-web DID, or
    /// an x509_hash-style value that's a certificate hash, not a name).
    public var displayName: String {
        switch self {
        case .x509SanDns(let hostname):
            return hostname
        case .x509SanUri(let uri):
            return URL(string: uri)?.host ?? uri
        case .https(let url):
            return URL(string: url)?.host ?? url
        case .did(let did, let method):
            // did:web:example.com[:path...] -> example.com - path segments
            // after the host are colon-separated per the did:web spec.
            if method == "web" {
                let rest = did.dropFirst("did:web:".count)
                return String(rest.split(separator: ":").first ?? Substring(rest))
            }
            return did
        case .openIdFederation(let entityId):
            return URL(string: entityId)?.host ?? entityId
        case .x509Hash(let hash):
            // A certificate digest; there is no name in it to show.
            return hash
        case .verifierAttestation(let subject):
            return subject
        case .preRegistered(let clientId):
            return clientId
        }
    }

    /// Parse a raw client_id string into a typed `ClientIdScheme`.
    ///
    /// Mirrors the parsing logic in wallet-frontend's `parseClientIdScheme`.
    public static func parse(_ clientId: String) -> ClientIdScheme {
        if clientId.hasPrefix("x509_san_dns:") {
            return .x509SanDns(hostname: String(clientId.dropFirst("x509_san_dns:".count)))
        }
        if clientId.hasPrefix("x509_san_uri:") {
            return .x509SanUri(uri: String(clientId.dropFirst("x509_san_uri:".count)))
        }
        if clientId.hasPrefix("x509_hash:") {
            return .x509Hash(hash: String(clientId.dropFirst("x509_hash:".count)))
        }
        // OID4VP 1.0 Final's prefix for a DID-identified Verifier. Checked
        // before the bare "did:" form, since the prefixed spelling contains it.
        if clientId.hasPrefix("decentralized_identifier:") {
            return didOf(String(clientId.dropFirst("decentralized_identifier:".count)))
        }
        if clientId.hasPrefix("did:") {
            return didOf(clientId)
        }
        if clientId.hasPrefix("verifier_attestation:") {
            return .verifierAttestation(subject: String(clientId.dropFirst("verifier_attestation:".count)))
        }
        if clientId.hasPrefix("openid_federation:") {
            return .openIdFederation(entityId: String(clientId.dropFirst("openid_federation:".count)))
        }
        if clientId.hasPrefix("redirect_uri:") {
            return .https(url: String(clientId.dropFirst("redirect_uri:".count)))
        }
        if clientId.hasPrefix("https://") || clientId.hasPrefix("http://") {
            return .https(url: clientId)
        }
        return .preRegistered(clientId: clientId)
    }

    private static func didOf(_ did: String) -> ClientIdScheme {
        let parts = did.split(separator: ":", maxSplits: 2)
        return .did(did: did, method: parts.count > 1 ? String(parts[1]) : "")
    }
}

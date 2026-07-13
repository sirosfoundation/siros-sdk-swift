// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Represents a parsed OID4VP client_id_scheme with its normalized identifier.
///
/// The client_id on the wire uses a prefix convention (e.g., "x509_san_dns:hostname")
/// to indicate how the verifier identifies itself. This enum provides type-safe
/// access to the parsed components.
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
        case .preRegistered(let clientId): return clientId
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
        if clientId.hasPrefix("did:") {
            let parts = clientId.split(separator: ":", maxSplits: 2)
            let method = parts.count > 1 ? String(parts[1]) : ""
            return .did(did: clientId, method: method)
        }
        if clientId.hasPrefix("verifier_attestation:") {
            return .verifierAttestation(subject: String(clientId.dropFirst("verifier_attestation:".count)))
        }
        if clientId.hasPrefix("https://") || clientId.hasPrefix("http://") {
            return .https(url: clientId)
        }
        return .preRegistered(clientId: clientId)
    }
}

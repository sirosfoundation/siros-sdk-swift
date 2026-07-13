// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Represents the result of a trust evaluation for a verifier or issuer.
///
/// Provides rich metadata about the trust decision beyond a simple boolean,
/// enabling host apps to render informative consent UIs with verifier identity,
/// trust framework information, and visual indicators.
public struct TrustResult: Sendable {
    /// Whether the entity is trusted.
    public let trusted: Bool

    /// Trust framework that evaluated the entity (e.g., "etsi-tl", "openid-federation", "lote").
    public let framework: String?

    /// Human-readable reason for the trust decision.
    public let reason: String?

    /// Display name of the verifier/issuer (from trust metadata or client_metadata).
    public let entityName: String?

    /// Logo URI for the verifier/issuer.
    public let entityLogo: String?

    /// The client_id_scheme used on the wire (e.g., "x509_san_dns", "did", "verifier_attestation").
    public let clientIdScheme: String?

    /// Normalized identifier (hostname for x509, DID for did:web, entity_id for federation).
    public let identifier: String?

    /// Domain extracted from the verifier identity.
    public let domain: String?

    public init(
        trusted: Bool,
        framework: String? = nil,
        reason: String? = nil,
        entityName: String? = nil,
        entityLogo: String? = nil,
        clientIdScheme: String? = nil,
        identifier: String? = nil,
        domain: String? = nil
    ) {
        self.trusted = trusted
        self.framework = framework
        self.reason = reason
        self.entityName = entityName
        self.entityLogo = entityLogo
        self.clientIdScheme = clientIdScheme
        self.identifier = identifier
        self.domain = domain
    }
}

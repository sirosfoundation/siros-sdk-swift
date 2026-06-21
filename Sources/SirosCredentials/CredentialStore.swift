// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Supported verifiable credential formats.
public enum CredentialFormat: String, Codable, Sendable {
    case sdJwtVc = "vc+sd-jwt"
    case dcSdJwt = "dc+sd-jwt"
    case msoMdoc = "mso_mdoc"
    case jwtVcJson = "jwt_vc_json"
}

/// A stored verifiable credential with parsed metadata.
public struct StoredCredential: Codable, Sendable, Equatable, Identifiable {
    public let id: String
    public let format: String
    public let raw: String
    public let metadata: CredentialMetadata?
    public let issuedAt: Int64?
    public let expiresAt: Int64?
    /// OID4VCI notification ID for credential lifecycle events.
    public let notificationId: String?
    /// Issuer's notification endpoint URL.
    public let notificationEndpoint: String?

    public init(
        id: String,
        format: String,
        raw: String,
        metadata: CredentialMetadata? = nil,
        issuedAt: Int64? = nil,
        expiresAt: Int64? = nil,
        notificationId: String? = nil,
        notificationEndpoint: String? = nil
    ) {
        self.id = id
        self.format = format
        self.raw = raw
        self.metadata = metadata
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.notificationId = notificationId
        self.notificationEndpoint = notificationEndpoint
    }

    enum CodingKeys: String, CodingKey {
        case id, format, raw, metadata
        case issuedAt = "issued_at"
        case expiresAt = "expires_at"
        case notificationId = "notification_id"
        case notificationEndpoint = "notification_endpoint"
    }
}

public struct CredentialMetadata: Codable, Sendable, Equatable {
    public let name: String?
    public let description: String?
    public let issuer: IssuerInfo?
    public let vct: String?
    public let doctype: String?
    public let backgroundColor: String?
    public let textColor: String?
    public let logo: LogoInfo?
    public let claims: [ClaimMeta]?

    public init(
        name: String? = nil,
        description: String? = nil,
        issuer: IssuerInfo? = nil,
        vct: String? = nil,
        doctype: String? = nil,
        backgroundColor: String? = nil,
        textColor: String? = nil,
        logo: LogoInfo? = nil,
        claims: [ClaimMeta]? = nil
    ) {
        self.name = name
        self.description = description
        self.issuer = issuer
        self.vct = vct
        self.doctype = doctype
        self.backgroundColor = backgroundColor
        self.textColor = textColor
        self.logo = logo
        self.claims = claims
    }

    enum CodingKeys: String, CodingKey {
        case name, description, issuer, vct, doctype, logo, claims
        case backgroundColor = "background_color"
        case textColor = "text_color"
    }
}

/// Metadata about an individual claim within a credential.
public struct ClaimMeta: Codable, Sendable, Equatable {
    /// JSON path elements selecting this claim in the credential.
    public let path: [String]
    /// Human-readable label for display.
    public let label: String?
    /// Human-readable description.
    public let description: String?
    /// Selective disclosure rule: "always", "allowed", or "never".
    public let sd: String?
    /// Whether this claim must be present in a presentation.
    public let mandatory: Bool

    public init(
        path: [String],
        label: String? = nil,
        description: String? = nil,
        sd: String? = nil,
        mandatory: Bool = false
    ) {
        self.path = path
        self.label = label
        self.description = description
        self.sd = sd
        self.mandatory = mandatory
    }
}

/// Information about the credential issuer.
public struct IssuerInfo: Codable, Sendable, Equatable {
    public let name: String?
    public let url: String?

    public init(name: String? = nil, url: String? = nil) {
        self.name = name
        self.url = url
    }
}

/// Logo image reference for a credential or issuer.
public struct LogoInfo: Codable, Sendable, Equatable {
    public let uri: String?
    public let altText: String?

    public init(uri: String? = nil, altText: String? = nil) {
        self.uri = uri
        self.altText = altText
    }

    enum CodingKeys: String, CodingKey {
        case uri
        case altText = "alt_text"
    }
}

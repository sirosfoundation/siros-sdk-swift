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
    /// A randomly-generated uint32-range identifier, matching wallet-frontend's
    /// `credentialId: number` (privatedata-spec §6) - not a UUID. Cross-client
    /// interop (the same encrypted container read by either client) requires
    /// this to be a genuine JSON number on the wire, not a string.
    public let id: Int64
    public let format: String
    public let raw: String
    /// Key ID (JWK thumbprint) of the keypair bound to this credential.
    public let kid: String?
    public let metadata: CredentialMetadata?
    public let issuedAt: Int64?
    public let expiresAt: Int64?
    /// OID4VCI §10 notification identifier returned by the issuer at issuance
    /// time, if any. Stored client-side only; echoed back to the backend in a
    /// credential_notification message when a lifecycle event occurs.
    public let notificationId: String?
    /// Issuer identifier this credential was obtained from - part of
    /// privatedata-spec's normative `S.credentials[]` fields
    /// (`WalletSessionEventNewCredential` in wallet-frontend), needed to
    /// re-fetch VCTM display metadata after a fresh login (wallet-frontend
    /// doesn't persist `metadata` either - it re-fetches/derives display info
    /// live rather than snapshotting it into the encrypted container).
    public let credentialIssuerIdentifier: String?
    /// Credential configuration ID (issuance scope) this credential was
    /// requested under - part of privatedata-spec's normative fields, needed
    /// (alongside `credentialIssuerIdentifier`) to re-fetch VCTM after login.
    public let credentialConfigurationId: String?
    /// Identifier shared by every copy issued in the same OID4VCI response
    /// (`batch_credential_issuance`/key-attestation multi-proof issuance) -
    /// privatedata-spec's normative `S.credentials[].batchId` (`number`).
    /// Mirrors wallet-frontend exactly: ALWAYS assigned a fresh value per
    /// issuance response, even for a single-credential issuance - there is no
    /// "no batch" sentinel on either client, since every issuance response is
    /// itself a batch of at least one.
    public let batchId: Int64
    /// 0-based position of this copy within its `batchId`.
    public let instanceId: Int

    public init(
        id: Int64,
        format: String,
        raw: String,
        kid: String? = nil,
        metadata: CredentialMetadata? = nil,
        issuedAt: Int64? = nil,
        expiresAt: Int64? = nil,
        notificationId: String? = nil,
        credentialIssuerIdentifier: String? = nil,
        credentialConfigurationId: String? = nil,
        batchId: Int64,
        instanceId: Int
    ) {
        self.id = id
        self.format = format
        self.raw = raw
        self.kid = kid
        self.metadata = metadata
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.notificationId = notificationId
        self.credentialIssuerIdentifier = credentialIssuerIdentifier
        self.credentialConfigurationId = credentialConfigurationId
        self.batchId = batchId
        self.instanceId = instanceId
    }

    enum CodingKeys: String, CodingKey {
        case id, format, raw, kid, metadata
        case issuedAt = "issued_at"
        case expiresAt = "expires_at"
        case notificationId = "notification_id"
        case credentialIssuerIdentifier = "credential_issuer_identifier"
        case credentialConfigurationId = "credential_configuration_id"
        case batchId = "batch_id"
        case instanceId = "instance_id"
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
    /// VCTM SVG rendering templates, if the issuer's VCTM published any.
    public let svgTemplates: [SvgTemplateInfo]?

    public init(
        name: String? = nil,
        description: String? = nil,
        issuer: IssuerInfo? = nil,
        vct: String? = nil,
        doctype: String? = nil,
        backgroundColor: String? = nil,
        textColor: String? = nil,
        logo: LogoInfo? = nil,
        claims: [ClaimMeta]? = nil,
        svgTemplates: [SvgTemplateInfo]? = nil
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
        self.svgTemplates = svgTemplates
    }

    enum CodingKeys: String, CodingKey {
        case name, description, issuer, vct, doctype, logo, claims
        case backgroundColor = "background_color"
        case textColor = "text_color"
        case svgTemplates = "svg_templates"
    }
}

/// A VCTM SVG rendering template reference (VCTM section 6, `rendering.svg_templates`).
public struct SvgTemplateInfo: Codable, Sendable, Equatable {
    public let uri: String
    public let colorScheme: String?
    public let contrast: String?
    public let orientation: String?

    public init(uri: String, colorScheme: String? = nil, contrast: String? = nil, orientation: String? = nil) {
        self.uri = uri
        self.colorScheme = colorScheme
        self.contrast = contrast
        self.orientation = orientation
    }

    enum CodingKeys: String, CodingKey {
        case uri, contrast
        case colorScheme = "color_scheme"
        case orientation
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
    /// VCTM SVG template placeholder ID this claim fills, if any.
    public let svgId: String?

    public init(
        path: [String],
        label: String? = nil,
        description: String? = nil,
        sd: String? = nil,
        mandatory: Bool = false,
        svgId: String? = nil
    ) {
        self.path = path
        self.label = label
        self.description = description
        self.sd = sd
        self.mandatory = mandatory
        self.svgId = svgId
    }

    enum CodingKeys: String, CodingKey {
        case path, label, description, sd, mandatory
        case svgId = "svg_id"
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

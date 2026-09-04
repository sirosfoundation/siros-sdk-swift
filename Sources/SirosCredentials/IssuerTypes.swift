// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

public struct IssuerEntry: Codable, Sendable, Equatable, Identifiable {
    public let id: Int64
    public let tenantId: String?
    public let credentialIssuerIdentifier: String
    public let clientId: String?
    public let visible: Bool

    public init(
        id: Int64,
        tenantId: String? = nil,
        credentialIssuerIdentifier: String,
        clientId: String? = nil,
        visible: Bool = true
    ) {
        self.id = id
        self.tenantId = tenantId
        self.credentialIssuerIdentifier = credentialIssuerIdentifier
        self.clientId = clientId
        self.visible = visible
    }
}

public struct IssuerMetadata: Codable, Sendable, Equatable {
    public let credentialIssuer: String
    public let credentialEndpoint: String?
    public let authorizationServers: [String]?
    public let display: [IssuerDisplay]?
    public let credentialConfigurationsSupported: [String: CredentialConfiguration]
    /// The metadata document signed as a JWS by the issuer's access
    /// certificate (ETSI TS 119 472-3). Verifying it is the backend's job -
    /// its presence here is for display and diagnostics only.
    public let signedMetadata: String?
    /// Where a PID or attestation provider publishes its registration
    /// certificate (ETSI TS 119 472-3).
    public let issuerInfo: [IssuerInfoEntry]?

    public init(
        credentialIssuer: String,
        credentialEndpoint: String? = nil,
        authorizationServers: [String]? = nil,
        display: [IssuerDisplay]? = nil,
        credentialConfigurationsSupported: [String: CredentialConfiguration] = [:],
        signedMetadata: String? = nil,
        issuerInfo: [IssuerInfoEntry]? = nil
    ) {
        self.credentialIssuer = credentialIssuer
        self.credentialEndpoint = credentialEndpoint
        self.authorizationServers = authorizationServers
        self.display = display
        self.credentialConfigurationsSupported = credentialConfigurationsSupported
        self.signedMetadata = signedMetadata
        self.issuerInfo = issuerInfo
    }

    enum CodingKeys: String, CodingKey {
        case display
        case credentialIssuer = "credential_issuer"
        case credentialEndpoint = "credential_endpoint"
        case authorizationServers = "authorization_servers"
        case credentialConfigurationsSupported = "credential_configurations_supported"
        case signedMetadata = "signed_metadata"
        case issuerInfo = "issuer_info"
    }
}

public struct IssuerDisplay: Codable, Sendable, Equatable {
    public let name: String?
    public let locale: String?
    public let logo: LogoInfo?
    public let backgroundColor: String?
    public let textColor: String?

    public init(
        name: String? = nil,
        locale: String? = nil,
        logo: LogoInfo? = nil,
        backgroundColor: String? = nil,
        textColor: String? = nil
    ) {
        self.name = name
        self.locale = locale
        self.logo = logo
        self.backgroundColor = backgroundColor
        self.textColor = textColor
    }

    enum CodingKeys: String, CodingKey {
        case name, locale, logo
        case backgroundColor = "background_color"
        case textColor = "text_color"
    }
}

public struct CredentialConfiguration: Codable, Sendable, Equatable {
    public let format: String
    public let vct: String?
    public let doctype: String?
    public let scope: String?
    public let credentialMetadata: CredentialDisplayMetadata?

    public init(
        format: String,
        vct: String? = nil,
        doctype: String? = nil,
        scope: String? = nil,
        credentialMetadata: CredentialDisplayMetadata? = nil
    ) {
        self.format = format
        self.vct = vct
        self.doctype = doctype
        self.scope = scope
        self.credentialMetadata = credentialMetadata
    }

    enum CodingKeys: String, CodingKey {
        case format, vct, doctype, scope
        case credentialMetadata = "credential_metadata"
    }
}

public struct CredentialDisplayMetadata: Codable, Sendable, Equatable {
    public let display: [CredentialDisplayEntry]?

    public init(display: [CredentialDisplayEntry]? = nil) {
        self.display = display
    }
}

public struct CredentialDisplayEntry: Codable, Sendable, Equatable {
    public let name: String
    public let description: String?
    public let locale: String?
    public let backgroundColor: String?
    public let textColor: String?
    public let backgroundImage: BackgroundImage?
    public let logo: LogoInfo?

    public init(
        name: String,
        description: String? = nil,
        locale: String? = nil,
        backgroundColor: String? = nil,
        textColor: String? = nil,
        backgroundImage: BackgroundImage? = nil,
        logo: LogoInfo? = nil
    ) {
        self.name = name
        self.description = description
        self.locale = locale
        self.backgroundColor = backgroundColor
        self.textColor = textColor
        self.backgroundImage = backgroundImage
        self.logo = logo
    }

    enum CodingKeys: String, CodingKey {
        case name, description, locale, logo
        case backgroundColor = "background_color"
        case textColor = "text_color"
        case backgroundImage = "background_image"
    }
}

public struct BackgroundImage: Codable, Sendable, Equatable {
    public let uri: String?

    public init(uri: String? = nil) {
        self.uri = uri
    }
}

public struct CredentialOffer: Sendable, Equatable {
    public let credentialConfigurationId: String
    public let credentialIssuerIdentifier: String
    public let credentialName: String
    public let credentialDescription: String?
    public let issuerName: String
    public let backgroundColor: String?
    public let textColor: String?
    public let logoUri: String?
    public let issuerLogoUri: String?
    public let preAuthorizedCode: String?
    public let txCode: String?

    /// The SD-JWT VC `vct` this configuration issues, when the issuer's
    /// `credential_configurations_supported` entry declared one - known
    /// upfront from issuer metadata, before any credential is actually
    /// issued. Lets `VctmFetcher.fetch` try its registry-service strategy
    /// immediately instead of only after a credential has been received.
    public let vct: String?

    /// The ISO 18013-5 mdoc `doctype` this configuration issues, when the
    /// issuer's `credential_configurations_supported` entry declared one -
    /// the mdoc analogue of `vct` above, used the same way by
    /// `MddlSchemaFetcher.fetch`.
    public let doctype: String?

    public init(
        credentialConfigurationId: String,
        credentialIssuerIdentifier: String,
        credentialName: String,
        credentialDescription: String? = nil,
        issuerName: String,
        backgroundColor: String? = nil,
        textColor: String? = nil,
        logoUri: String? = nil,
        issuerLogoUri: String? = nil,
        preAuthorizedCode: String? = nil,
        txCode: String? = nil,
        vct: String? = nil,
        doctype: String? = nil
    ) {
        self.credentialConfigurationId = credentialConfigurationId
        self.credentialIssuerIdentifier = credentialIssuerIdentifier
        self.credentialName = credentialName
        self.credentialDescription = credentialDescription
        self.issuerName = issuerName
        self.backgroundColor = backgroundColor
        self.textColor = textColor
        self.logoUri = logoUri
        self.issuerLogoUri = issuerLogoUri
        self.preAuthorizedCode = preAuthorizedCode
        self.txCode = txCode
        self.vct = vct
        self.doctype = doctype
    }

    /// Unique identity across issuers - unlike `credentialConfigurationId`
    /// alone (issuers commonly reuse configuration IDs like "identity" or
    /// "default"), pairing it with `credentialIssuerIdentifier` can't
    /// collide. Use this, not `credentialConfigurationId`, as a SwiftUI
    /// `ForEach` identity for a list of offers from multiple issuers.
    ///
    /// Length-prefixes `credentialIssuerIdentifier` rather than joining with
    /// a plain separator - a bare `"\(issuer)#\(configId)"` could still
    /// collide if either component itself contains `#` (e.g. issuer `"x#y"`
    /// + config `"z"` vs. issuer `"x"` + config `"y#z"`).
    public var offerIdentity: String {
        "\(credentialIssuerIdentifier.count):\(credentialIssuerIdentifier)#\(credentialConfigurationId)"
    }
}

/// One entry of an issuer's `issuer_info` (ETSI TS 119 472-3), which is where a
/// PID or attestation provider publishes its registration certificate.
public struct IssuerInfoEntry: Codable, Sendable, Equatable {
    /// `registration_cert` for a WRPRC, `registrar_dataset` for the dataset form.
    public let format: String
    /// The credential itself - a compact `rc-wrp+jwt` for `registration_cert`.
    public let credential: String?

    public init(format: String, credential: String? = nil) {
        self.format = format
        self.credential = credential
    }
}

/// What the backend concluded about a provider's entitlement to issue what it
/// is offering (ARF v3.0.0 section 6.6.2.3).
///
/// `evaluated` is deliberately separate from `allowed`: "not checked" must
/// never read as "checked and fine". A decision that was not evaluated carries
/// no assurance at all, whatever `allowed` says.
public struct IssuerEntitlement: Codable, Sendable, Equatable {
    /// Whether issuance may proceed. Stays true in warn mode even with findings.
    public let allowed: Bool
    /// `warn`, `fail` or `off` - which mode produced this decision, so a caller
    /// can tell "passed" from "would have failed but we are in warn mode".
    public let mode: String
    /// False when there was nothing to evaluate against.
    public let evaluated: Bool
    public let findings: [IssuerEntitlementFinding]
    /// What the registration certificate claimed, for display.
    public let entitlements: [String]
    /// The provider identifier from the registration certificate.
    public let subject: String?

    public init(
        allowed: Bool,
        mode: String = "warn",
        evaluated: Bool = false,
        findings: [IssuerEntitlementFinding] = [],
        entitlements: [String] = [],
        subject: String? = nil
    ) {
        self.allowed = allowed
        self.mode = mode
        self.evaluated = evaluated
        self.findings = findings
        self.entitlements = entitlements
        self.subject = subject
    }

    enum CodingKeys: String, CodingKey {
        case allowed, mode, evaluated, findings, entitlements, subject
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        // `allowed` is required, deliberately. Defaulting it to true would mean
        // a response that omits or misnames the field - a truncated body, a
        // renamed key, a tampered one - decodes as a decision to allow. A
        // decision that is not present is not a decision: failing to decode
        // leaves the caller with nil, which is "not checked", and the one thing
        // nil never does is read as a pass.
        //
        // Matches siros-sdk-kotlin, where `allowed` has no default, and
        // wallet-frontend, which discards a decision carrying no `allowed`
        // boolean.
        allowed = try c.decode(Bool.self, forKey: .allowed)
        mode = try c.decodeIfPresent(String.self, forKey: .mode) ?? "warn"
        evaluated = try c.decodeIfPresent(Bool.self, forKey: .evaluated) ?? false
        findings = try c.decodeIfPresent([IssuerEntitlementFinding].self, forKey: .findings) ?? []
        entitlements = try c.decodeIfPresent([String].self, forKey: .entitlements) ?? []
        subject = try c.decodeIfPresent(String.self, forKey: .subject)
    }
}

/// One thing that did not check out about a provider's registration.
public struct IssuerEntitlementFinding: Codable, Sendable, Equatable {
    /// A stable identifier, so a caller can act on the reason rather than parse
    /// a sentence - e.g. `attestation_type_not_registered`.
    public let code: String
    public let message: String
    /// The offered type, when the finding is about one.
    public let credentialType: String?

    public init(code: String, message: String, credentialType: String? = nil) {
        self.code = code
        self.message = message
        self.credentialType = credentialType
    }

    enum CodingKeys: String, CodingKey {
        case code, message
        case credentialType = "credential_type"
    }
}

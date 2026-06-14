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

    public init(
        credentialIssuer: String,
        credentialEndpoint: String? = nil,
        authorizationServers: [String]? = nil,
        display: [IssuerDisplay]? = nil,
        credentialConfigurationsSupported: [String: CredentialConfiguration] = [:]
    ) {
        self.credentialIssuer = credentialIssuer
        self.credentialEndpoint = credentialEndpoint
        self.authorizationServers = authorizationServers
        self.display = display
        self.credentialConfigurationsSupported = credentialConfigurationsSupported
    }

    enum CodingKeys: String, CodingKey {
        case display
        case credentialIssuer = "credential_issuer"
        case credentialEndpoint = "credential_endpoint"
        case authorizationServers = "authorization_servers"
        case credentialConfigurationsSupported = "credential_configurations_supported"
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
        txCode: String? = nil
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
    }
}

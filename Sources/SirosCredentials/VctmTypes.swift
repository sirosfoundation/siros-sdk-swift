// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// SD-JWT VC Type Metadata (VCTM) per draft-ietf-oauth-sd-jwt-vc section 6.
public struct Vctm: Codable, Sendable, Equatable {
    public let vct: String
    public let name: String?
    public let description: String?
    public let display: [VctmDisplay]?
    public let claims: [VctmClaim]?
    public let extends: String?
    public let schemaUri: String?

    public init(
        vct: String,
        name: String? = nil,
        description: String? = nil,
        display: [VctmDisplay]? = nil,
        claims: [VctmClaim]? = nil,
        extends: String? = nil,
        schemaUri: String? = nil
    ) {
        self.vct = vct
        self.name = name
        self.description = description
        self.display = display
        self.claims = claims
        self.extends = extends
        self.schemaUri = schemaUri
    }

    enum CodingKeys: String, CodingKey {
        case vct, name, description, display, claims, extends
        case schemaUri = "schema_uri"
    }
}

public struct VctmDisplay: Codable, Sendable, Equatable {
    public let locale: String
    public let name: String
    public let description: String?
    public let rendering: VctmRendering?

    public init(
        locale: String,
        name: String,
        description: String? = nil,
        rendering: VctmRendering? = nil
    ) {
        self.locale = locale
        self.name = name
        self.description = description
        self.rendering = rendering
    }
}

public struct VctmRendering: Codable, Sendable, Equatable {
    public let simple: VctmSimpleRendering?
    public let svgTemplates: [VctmSvgTemplate]?

    public init(
        simple: VctmSimpleRendering? = nil,
        svgTemplates: [VctmSvgTemplate]? = nil
    ) {
        self.simple = simple
        self.svgTemplates = svgTemplates
    }

    enum CodingKeys: String, CodingKey {
        case simple
        case svgTemplates = "svg_templates"
    }
}

public struct VctmSimpleRendering: Codable, Sendable, Equatable {
    public let logo: VctmLogo?
    public let backgroundImage: VctmLogo?
    public let backgroundColor: String?
    public let textColor: String?

    public init(
        logo: VctmLogo? = nil,
        backgroundImage: VctmLogo? = nil,
        backgroundColor: String? = nil,
        textColor: String? = nil
    ) {
        self.logo = logo
        self.backgroundImage = backgroundImage
        self.backgroundColor = backgroundColor
        self.textColor = textColor
    }

    enum CodingKeys: String, CodingKey {
        case logo
        case backgroundImage = "background_image"
        case backgroundColor = "background_color"
        case textColor = "text_color"
    }
}

public struct VctmLogo: Codable, Sendable, Equatable {
    public let uri: String
    public let uriIntegrity: String?
    public let altText: String?

    public init(uri: String, uriIntegrity: String? = nil, altText: String? = nil) {
        self.uri = uri
        self.uriIntegrity = uriIntegrity
        self.altText = altText
    }

    enum CodingKeys: String, CodingKey {
        case uri
        case uriIntegrity = "uri#integrity"
        case altText = "alt_text"
    }
}

public struct VctmSvgTemplate: Codable, Sendable, Equatable {
    public let uri: String
    public let uriIntegrity: String?
    public let properties: VctmSvgProperties?

    public init(uri: String, uriIntegrity: String? = nil, properties: VctmSvgProperties? = nil) {
        self.uri = uri
        self.uriIntegrity = uriIntegrity
        self.properties = properties
    }

    enum CodingKeys: String, CodingKey {
        case uri, properties
        case uriIntegrity = "uri#integrity"
    }
}

public struct VctmSvgProperties: Codable, Sendable, Equatable {
    public let orientation: String?
    public let colorScheme: String?
    public let contrast: String?

    public init(orientation: String? = nil, colorScheme: String? = nil, contrast: String? = nil) {
        self.orientation = orientation
        self.colorScheme = colorScheme
        self.contrast = contrast
    }

    enum CodingKeys: String, CodingKey {
        case orientation, contrast
        case colorScheme = "color_scheme"
    }
}

public struct VctmClaim: Codable, Sendable, Equatable {
    public let path: [String?]
    public let display: [VctmClaimDisplay]?
    public let sd: String?
    public let mandatory: Bool?
    public let svgId: String?

    public init(
        path: [String?],
        display: [VctmClaimDisplay]? = nil,
        sd: String? = nil,
        mandatory: Bool? = nil,
        svgId: String? = nil
    ) {
        self.path = path
        self.display = display
        self.sd = sd
        self.mandatory = mandatory
        self.svgId = svgId
    }

    enum CodingKeys: String, CodingKey {
        case path, display, sd, mandatory
        case svgId = "svg_id"
    }
}

public struct VctmClaimDisplay: Codable, Sendable, Equatable {
    public let locale: String
    public let label: String
    public let description: String?

    public init(locale: String, label: String, description: String? = nil) {
        self.locale = locale
        self.label = label
        self.description = description
    }
}

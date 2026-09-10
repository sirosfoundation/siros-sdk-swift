// GENERATED from spec/bridge-capabilities.json by tools/gen_bridge_capabilities.py - do not edit.
// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Versions of the vocabulary and of the descriptor schema this SDK was generated from.
public enum BridgeVocabulary {
    public static let version = 1
    public static let descriptorVersion = 1
}

/// Capability ids. Stable once published; retired ids stay here with a `deprecated` note.
public enum BridgeCapabilityId {
    /// Native WebAuthn create()/get() in place of the WebView's, so security keys reach the page over the SDK's own CTAP2 transports and platform passkeys carry the PRF extension.
    public static let webauthn = "webauthn"
    /// The host is a W3C Digital Credentials API provider on this device and mirrors the page's credential list into the platform registry; presentation responses are returned through the host.
    public static let dcApi = "dc_api"
    /// Physical identity document scanning and face match, started from the page and returned as an identity-verification result.
    public static let idvPhysicalId = "idv.physical_id"
    /// Host-mediated OpenID Connect login: the authorization request opens in a system browser tab and the response is handed back to the page.
    public static let oidc = "oidc"
    /// Raw Bluetooth LE byte pipe (client and server) with the ISO 18013-5 session layer implemented by the page.
    public static let proximityBytePipe = "proximity.byte_pipe"
    /// ISO 18013-5 proximity presentation run natively as a session: device engagement, transport, session encryption and reader authentication in the host; the page supplies credentials, consent and device signatures through callbacks.
    public static let proximitySession = "proximity.session"
    /// Zero-knowledge presentation proofs generated natively. The page decides a proof is needed and supplies credential bytes and transcript; the host resolves the circuit, proves, and calls back for the witness signature.
    public static let zk = "zk"
    /// Key operations performed natively on a container the page imports and exports around each session: generate, sign, attest, over the SDK's key manager and its WSCD plugins.
    public static let keys = "keys"
    /// Credential matching (DCQL) and presentation assembly performed natively over the imported container.
    public static let credentials = "credentials"
    /// Authentication and PRF-derived container ownership held natively; the page no longer derives the unwrap key.
    public static let auth = "auth"
    /// A native Wallet Messaging Protocol engine. Reserved so that, if it ever exists, it is one more advertised capability rather than a new detection mechanism.
    public static let engine = "engine"

    public static let all: [String] = [webauthn, dcApi, idvPhysicalId, oidc, proximityBytePipe, proximitySession, zk, keys, credentials, auth, engine]
    /// Deprecated ids and why.
    public static let deprecated: [String: String] = [
        proximityBytePipe: "Superseded by proximity.session; removed once every shipped wrapper advertises the session capability.",
    ]
}

/// A capability's parameters, encodable into the descriptor's capability map.
public protocol BridgeCapabilityParams: Codable, Sendable {
    static var capabilityId: String { get }
}

/// Native WebAuthn create()/get() in place of the WebView's, so security keys reach the page over the SDK's own CTAP2 transports and platform passkeys carry the PRF extension.
///
/// Stage: reached.
public struct WebauthnCapability: BridgeCapabilityParams {
    public static let capabilityId = BridgeCapabilityId.webauthn
    /// Assertions can return the WebAuthn PRF extension output.
    public var prf: Bool?
    /// CTAP2 transports available to the page: `usb`, `nfc`, `ble`, `hybrid`.
    public var securityKeyTransports: [String]?
    public init(prf: Bool? = nil, securityKeyTransports: [String]? = nil) {
        self.prf = prf
        self.securityKeyTransports = securityKeyTransports
    }
    enum CodingKeys: String, CodingKey {
        case prf
        case securityKeyTransports = "security_key_transports"
    }
}

/// The host is a W3C Digital Credentials API provider on this device and mirrors the page's credential list into the platform registry; presentation responses are returned through the host.
///
/// Stage: reached.
public struct DcApiCapability: BridgeCapabilityParams {
    public static let capabilityId = BridgeCapabilityId.dcApi
    /// Version of the siros-dc-matcher the host registers.
    public var matcherVersion: String?
    /// Credential formats the registry accepts: `mso_mdoc`, `dc+sd-jwt`.
    public var formats: [String]?
    public init(matcherVersion: String? = nil, formats: [String]? = nil) {
        self.matcherVersion = matcherVersion
        self.formats = formats
    }
    enum CodingKeys: String, CodingKey {
        case matcherVersion = "matcher_version"
        case formats
    }
}

/// Physical identity document scanning and face match, started from the page and returned as an identity-verification result.
///
/// Stage: reached.
public struct IdvPhysicalIdCapability: BridgeCapabilityParams {
    public static let capabilityId = BridgeCapabilityId.idvPhysicalId
    /// Vendor of the capture SDK, e.g. `facetec`.
    public var provider: String?
    public init(provider: String? = nil) {
        self.provider = provider
    }
}

/// Host-mediated OpenID Connect login: the authorization request opens in a system browser tab and the response is handed back to the page.
///
/// Stage: reached.
public struct OidcCapability: BridgeCapabilityParams {
    public static let capabilityId = BridgeCapabilityId.oidc
    public init() {}
}

/// Raw Bluetooth LE byte pipe (client and server) with the ISO 18013-5 session layer implemented by the page.
///
/// Stage: reached. DEPRECATED: Superseded by proximity.session; removed once every shipped wrapper advertises the session capability.
public struct ProximityBytePipeCapability: BridgeCapabilityParams {
    public static let capabilityId = BridgeCapabilityId.proximityBytePipe
    /// `client`, `server`.
    public var roles: [String]?
    public init(roles: [String]? = nil) {
        self.roles = roles
    }
}

/// ISO 18013-5 proximity presentation run natively as a session: device engagement, transport, session encryption and reader authentication in the host; the page supplies credentials, consent and device signatures through callbacks.
///
/// Stage: A.
public struct ProximitySessionCapability: BridgeCapabilityParams {
    public static let capabilityId = BridgeCapabilityId.proximitySession
    /// `ble_central`, `ble_peripheral`, `nfc`.
    public var transports: [String]?
    /// NFC static handover to BLE is available.
    public var nfcStaticHandover: Bool?
    /// Reader authentication against the configured trust lists is evaluated natively.
    public var readerAuth: Bool?
    public init(transports: [String]? = nil, nfcStaticHandover: Bool? = nil, readerAuth: Bool? = nil) {
        self.transports = transports
        self.nfcStaticHandover = nfcStaticHandover
        self.readerAuth = readerAuth
    }
    enum CodingKeys: String, CodingKey {
        case transports
        case nfcStaticHandover = "nfc_static_handover"
        case readerAuth = "reader_auth"
    }
}

/// Zero-knowledge presentation proofs generated natively. The page decides a proof is needed and supplies credential bytes and transcript; the host resolves the circuit, proves, and calls back for the witness signature.
///
/// Stage: A.
public struct ZkCapability: BridgeCapabilityParams {
    public static let capabilityId = BridgeCapabilityId.zk
    /// Proof system ids the host can prove for, e.g. `longfellow-libzk-v1`, `vega-mdoc-v1`. From the SDK's ZkMdocPresentation.systemIds().
    public var systems: [String]?
    /// Circuits are cached on disk across launches.
    public var circuitCache: Bool?
    public init(systems: [String]? = nil, circuitCache: Bool? = nil) {
        self.systems = systems
        self.circuitCache = circuitCache
    }
    enum CodingKeys: String, CodingKey {
        case systems
        case circuitCache = "circuit_cache"
    }
}

/// Key operations performed natively on a container the page imports and exports around each session: generate, sign, attest, over the SDK's key manager and its WSCD plugins.
///
/// Stage: B.
public struct KeysCapability: BridgeCapabilityParams {
    public static let capabilityId = BridgeCapabilityId.keys
    /// Registered WSCD plugin ids.
    public var wscdPlugins: [String]?
    public init(wscdPlugins: [String]? = nil) {
        self.wscdPlugins = wscdPlugins
    }
    enum CodingKeys: String, CodingKey {
        case wscdPlugins = "wscd_plugins"
    }
}

/// Credential matching (DCQL) and presentation assembly performed natively over the imported container.
///
/// Stage: C.
public struct CredentialsCapability: BridgeCapabilityParams {
    public static let capabilityId = BridgeCapabilityId.credentials
    /// `mso_mdoc`, `dc+sd-jwt`.
    public var formats: [String]?
    public init(formats: [String]? = nil) {
        self.formats = formats
    }
}

/// Authentication and PRF-derived container ownership held natively; the page no longer derives the unwrap key.
///
/// Stage: D.
public struct AuthCapability: BridgeCapabilityParams {
    public static let capabilityId = BridgeCapabilityId.auth
    public init() {}
}

/// A native Wallet Messaging Protocol engine. Reserved so that, if it ever exists, it is one more advertised capability rather than a new detection mechanism.
///
/// Stage: never.
public struct EngineCapability: BridgeCapabilityParams {
    public static let capabilityId = BridgeCapabilityId.engine
    /// WMP capability names, as WmpRegistry.allCapabilities() reports them: `oid4vci`, `oid4vp`, ...
    public var wmpCapabilities: [String]?
    public init(wmpCapabilities: [String]? = nil) {
        self.wmpCapabilities = wmpCapabilities
    }
    enum CodingKeys: String, CodingKey {
        case wmpCapabilities = "wmp_capabilities"
    }
}

/// The host application advertising the bridge.
public struct BridgeHost: Codable, Sendable {
    /// Host application id (Android applicationId / iOS bundle id).
    public var name: String
    /// Host application version string.
    public var version: String
    /// SIROS SDK version the host links.
    public var sdkVersion: String
    public init(name: String, version: String, sdkVersion: String) {
        self.name = name
        self.version = version
        self.sdkVersion = sdkVersion
    }
    enum CodingKeys: String, CodingKey {
        case name
        case version
        case sdkVersion = "sdk_version"
    }
}

public struct BridgeMeta: Codable, Sendable {
    public var version: Int = BridgeVocabulary.descriptorVersion
    public init(version: Int = BridgeVocabulary.descriptorVersion) { self.version = version }
}

/// What a host advertises to the page. `bridge` is the descriptor schema itself; `vocabulary` says which version of this file the ids come from, so a page can tell 'unknown id' from 'older host'.
///
/// Build one with `BridgeDescriptorBuilder`; the page consumes the JSON form.
public struct BridgeDescriptor: Codable, Sendable {
    public var bridge: BridgeMeta = BridgeMeta()
    public var vocabulary: Int = BridgeVocabulary.version
    /// `android` or `ios`.
    public var platform: String
    public var host: BridgeHost
    /// Capability id to its parameters. Present means offered.
    public var capabilities: [String: AnyCodable]
    public init(platform: String, host: BridgeHost, capabilities: [String: AnyCodable]) {
        self.platform = platform
        self.host = host
        self.capabilities = capabilities
    }
}

/// Typed, one method per capability; the descriptor's capability map is built from what was offered.
public final class BridgeDescriptorBuilder {
    private let platform: String
    private let host: BridgeHost
    private var offered: [String: AnyCodable] = [:]

    public init(platform: String, host: BridgeHost) {
        self.platform = platform
        self.host = host
    }

    private func offer<P: BridgeCapabilityParams>(_ params: P) throws {
        // Re-decode through the codec's own AnyCodable so the map holds
        // plain JSON values whatever the parameter struct's shape.
        let data = try JSONEncoder().encode(params)
        offered[P.capabilityId] = try JSONDecoder().decode(AnyCodable.self, from: data)
    }

    @discardableResult
    public func webauthn(_ params: WebauthnCapability = WebauthnCapability()) throws -> BridgeDescriptorBuilder {
        try offer(params)
        return self
    }
    @discardableResult
    public func dcApi(_ params: DcApiCapability = DcApiCapability()) throws -> BridgeDescriptorBuilder {
        try offer(params)
        return self
    }
    @discardableResult
    public func idvPhysicalId(_ params: IdvPhysicalIdCapability = IdvPhysicalIdCapability()) throws -> BridgeDescriptorBuilder {
        try offer(params)
        return self
    }
    @discardableResult
    public func oidc(_ params: OidcCapability = OidcCapability()) throws -> BridgeDescriptorBuilder {
        try offer(params)
        return self
    }
    @discardableResult
    public func proximityBytePipe(_ params: ProximityBytePipeCapability = ProximityBytePipeCapability()) throws -> BridgeDescriptorBuilder {
        try offer(params)
        return self
    }
    @discardableResult
    public func proximitySession(_ params: ProximitySessionCapability = ProximitySessionCapability()) throws -> BridgeDescriptorBuilder {
        try offer(params)
        return self
    }
    @discardableResult
    public func zk(_ params: ZkCapability = ZkCapability()) throws -> BridgeDescriptorBuilder {
        try offer(params)
        return self
    }
    @discardableResult
    public func keys(_ params: KeysCapability = KeysCapability()) throws -> BridgeDescriptorBuilder {
        try offer(params)
        return self
    }
    @discardableResult
    public func credentials(_ params: CredentialsCapability = CredentialsCapability()) throws -> BridgeDescriptorBuilder {
        try offer(params)
        return self
    }
    @discardableResult
    public func auth(_ params: AuthCapability = AuthCapability()) throws -> BridgeDescriptorBuilder {
        try offer(params)
        return self
    }
    @discardableResult
    public func engine(_ params: EngineCapability = EngineCapability()) throws -> BridgeDescriptorBuilder {
        try offer(params)
        return self
    }

    public func build() -> BridgeDescriptor {
        BridgeDescriptor(platform: platform, host: host, capabilities: offered)
    }

    /// The JSON the page receives.
    public func encode() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return String(decoding: try encoder.encode(build()), as: UTF8.self)
    }
}

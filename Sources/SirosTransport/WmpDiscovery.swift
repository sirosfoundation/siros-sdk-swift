// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Where the well-known configuration of a domain-based WMP identifier is
/// found (WMP Core 7.5.1): a host and, for a tenant of a host that serves
/// several providers, the tenant's path.
public struct WmpDiscoveryBase: Equatable, Sendable {
    /// The host, with its port when the identifier names one.
    public let host: String
    /// Empty for the whole host; otherwise starts with `/` and has no
    /// trailing `/`.
    public let tenantPath: String

    /// The URL of the configuration: the well-known segment inserted between
    /// the host and the tenant path, as RFC 8414 Section 3.1 does.
    public var wellKnownURL: String {
        "https://\(host)/.well-known/wmp-configuration\(tenantPath)"
    }

    /// The base as the `https` URL a configuration carries in
    /// `discovery_base`.
    public var url: String { "https://\(host)\(tenantPath)" }

    /// The discovery base of an identifier, or `nil` when it has none.
    ///
    ///     x509:san:dns:example.com                -> example.com
    ///     https://example.com/tenant1             -> example.com, /tenant1
    ///     x509:san:uri:https://example.com/tenant -> example.com, /tenant
    ///     did:web:example.com                     -> example.com
    ///
    /// A `did:web` identifier with a path has none: the did:web method
    /// resolves it through its DID Document, whose `WMPMessaging` service
    /// names the endpoint (WMP Core 7.5.4). An identifier with a query, a
    /// fragment, userinfo or a `.` or `..` path segment has none either.
    public init?(identifier: String) {
        var base: WmpDiscoveryBase?
        if identifier.hasPrefix("x509:san:dns:") {
            base = Self.ofHost(String(identifier.dropFirst("x509:san:dns:".count)))
        } else if identifier.hasPrefix("x509:san:uri:") {
            base = Self.ofURL(String(identifier.dropFirst("x509:san:uri:".count)))
        } else if identifier.hasPrefix("https://") {
            base = Self.ofURL(identifier)
        } else if identifier.hasPrefix("did:web:") {
            let parts = identifier.dropFirst("did:web:".count)
                .split(separator: ":", omittingEmptySubsequences: false)
            if parts.count == 1, let host = Self.percentDecode(String(parts[0])) {
                base = Self.ofHost(host)
            }
        }
        guard let base else { return nil }
        self = base
    }

    private init(host: String, tenantPath: String) {
        self.host = host
        self.tenantPath = tenantPath
    }

    /// Whether a configuration that carries `discoveryBase` describes this
    /// base. A configuration for a tenant path must name the base; one for a
    /// whole host may leave it out (`nil`).
    public func isDescribed(by discoveryBase: String?) -> Bool {
        guard let discoveryBase, !discoveryBase.isEmpty else { return tenantPath.isEmpty }
        // The scheme compares case-insensitively, like the host.
        let scheme = "https:"
        var normalized = discoveryBase
        if discoveryBase.prefix(scheme.count).lowercased() == scheme {
            normalized = scheme + discoveryBase.dropFirst(scheme.count)
        }
        guard let got = Self.ofURL(normalized) else { return false }
        return got.host.lowercased() == host.lowercased() && got.tenantPath == tenantPath
    }

    // MARK: - Parsing

    private static func isDigit(_ c: UInt8) -> Bool { c >= 0x30 && c <= 0x39 }

    private static func isAlnum(_ c: UInt8) -> Bool {
        isDigit(c) || (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A)
    }

    private static func isValidPort(_ port: Substring) -> Bool {
        (1...5).contains(port.utf8.count) && port.utf8.allSatisfy(isDigit)
    }

    /// A DNS name or IPv4 address (labels of letters, digits and inner
    /// hyphens) or a bracketed IPv6 address, with an optional port.
    private static func isValidHost(_ host: String) -> Bool {
        var name = Substring(host)
        if name.hasPrefix("[") {
            guard let close = name.firstIndex(of: "]") else { return false }
            let address = name[name.index(after: name.startIndex)..<close]
            guard !address.isEmpty,
                  address.utf8.allSatisfy({ hexValue($0) != nil || $0 == 0x3A || $0 == 0x2E })
            else { return false }
            let after = name[name.index(after: close)...]
            return after.isEmpty || (after.hasPrefix(":") && isValidPort(after.dropFirst()))
        }
        if let colon = name.firstIndex(of: ":") {
            guard isValidPort(name[name.index(after: colon)...]) else { return false }
            name = name[..<colon]
        }
        let labels = name.split(separator: ".", omittingEmptySubsequences: false)
        return !labels.isEmpty && labels.allSatisfy { label in
            let bytes = Array(label.utf8)
            guard let first = bytes.first, let last = bytes.last else { return false }
            return isAlnum(first) && isAlnum(last) && bytes.allSatisfy { isAlnum($0) || $0 == 0x2D }
        }
    }

    private static func ofHost(_ host: String) -> WmpDiscoveryBase? {
        guard host.utf8.count <= 259, isValidHost(host) else { return nil }
        return WmpDiscoveryBase(host: host, tenantPath: "")
    }

    /// The base of an `https` URL, read from the string as written: a URL
    /// parser would resolve dot segments, and the identifier is what the
    /// tenant path is compared with.
    private static func ofURL(_ raw: String) -> WmpDiscoveryBase? {
        guard raw.hasPrefix("https://") else { return nil }
        guard !raw.unicodeScalars.contains(where: {
            $0 == "?" || $0 == "#" || $0 == "\\" || $0.properties.isWhitespace
        }) else { return nil }
        let rest = raw.dropFirst("https://".count)
        let slash = rest.firstIndex(of: "/")
        guard let base = ofHost(String(slash.map { rest[..<$0] } ?? rest)) else { return nil }
        var tenantPath = slash.map { String(rest[$0...]) } ?? ""
        while tenantPath.hasSuffix("/") { tenantPath.removeLast() }
        for segment in tenantPath.split(separator: "/", omittingEmptySubsequences: false) {
            guard let decoded = percentDecode(String(segment)),
                  decoded != ".", decoded != ".." else { return nil }
        }
        return WmpDiscoveryBase(host: base.host, tenantPath: tenantPath)
    }

    /// Percent-decodes a path segment; `nil` when an escape is malformed.
    private static func percentDecode(_ s: String) -> String? {
        guard s.contains("%") else { return s }
        var bytes: [UInt8] = []
        let utf8 = Array(s.utf8)
        var i = 0
        while i < utf8.count {
            if utf8[i] == 0x25 {
                guard i + 2 < utf8.count,
                      let hi = hexValue(utf8[i + 1]), let lo = hexValue(utf8[i + 2]) else { return nil }
                bytes.append(hi * 16 + lo)
                i += 3
            } else {
                bytes.append(utf8[i])
                i += 1
            }
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    private static func hexValue(_ c: UInt8) -> UInt8? {
        switch c {
        case 0x30...0x39: return c - 0x30
        case 0x41...0x46: return c - 0x41 + 10
        case 0x61...0x66: return c - 0x61 + 10
        default: return nil
        }
    }
}

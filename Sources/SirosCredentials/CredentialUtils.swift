// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(os)
import os
private let logger = Logger(subsystem: "org.siros.sdk", category: "CredentialUtils")
#endif

/// A user-facing claim extracted from a credential payload.
public struct DisplayClaim: Sendable, Equatable {
    public let key: String
    public let label: String
    public let value: String
    public let description: String?
    public let mandatory: Bool
    /// VCTM SVG template placeholder ID this claim fills, if any.
    public let svgId: String?

    public init(
        key: String,
        label: String,
        value: String,
        description: String? = nil,
        mandatory: Bool = false,
        svgId: String? = nil
    ) {
        self.key = key
        self.label = label
        self.value = value
        self.description = description
        self.mandatory = mandatory
        self.svgId = svgId
    }
}

/// The individually-decoded parts of a raw SD-JWT VC string, for display.
///
/// Each field is the decoded JSON text (not yet pretty-printed - callers
/// typically feed these straight into ``CredentialUtils/prettyPrintJson(_:)``
/// or an equivalent renderer).
public struct SdJwtParts: Sendable, Equatable {
    public let header: String?
    public let payload: String?
    /// Each disclosure is a JSON array (`[salt, name, value]` or `[salt, value]`)
    /// per the SD-JWT spec - one raw JSON string per disclosure, not one opaque blob.
    public let disclosures: [String]

    public init(header: String?, payload: String?, disclosures: [String]) {
        self.header = header
        self.payload = payload
        self.disclosures = disclosures
    }
}

public enum CredentialUtils {

    private static let jwtSkipKeys: Set<String> = [
        "iss", "sub", "aud", "exp", "nbf", "iat", "jti",
        "_sd", "_sd_alg", "cnf", "vct", "status", "client_status", "type",
    ]

    /// Parse the payload of a JWT (or the JWT part of an SD-JWT).
    public static func parseJwtPayload(_ raw: String) -> [String: Any]? {
        let jwtPart = raw.split(separator: "~", maxSplits: 1).first.map(String.init) ?? raw
        let parts = jwtPart.split(separator: ".")
        guard parts.count >= 2 else { return nil }

        guard let data = base64UrlDecode(String(parts[1])) else {
            #if canImport(os)
            logger.warning("Failed to base64url-decode JWT payload")
            #endif
            return nil
        }

        do {
            guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                return nil
            }
            return json
        } catch {
            #if canImport(os)
            logger.warning("Failed to parse JWT payload: \(error.localizedDescription)")
            #endif
            return nil
        }
    }

    /// Split a raw SD-JWT VC (`<jwt>~<disclosure>~<disclosure>~...`) into its
    /// individually-decoded parts, for display purposes (e.g. a "Raw" debug
    /// tab) - each disclosure is a separate JSON array per the SD-JWT spec, not
    /// part of one opaque blob.
    public static func parseSdJwtParts(_ raw: String) -> SdJwtParts {
        let segments = raw.split(separator: "~", omittingEmptySubsequences: false).map(String.init)
        let jwtSegments = segments.first?.split(separator: ".").map(String.init) ?? []
        let header = jwtSegments.first.flatMap { decodeJsonSegmentText($0) }
        let payload = jwtSegments.count > 1 ? decodeJsonSegmentText(jwtSegments[1]) : nil
        let disclosures = segments.dropFirst()
            .filter { !$0.isEmpty }
            .compactMap { decodeJsonSegmentText($0) }
        return SdJwtParts(header: header, payload: payload, disclosures: disclosures)
    }

    /// Pretty-print a JSON string with 2-space indentation. Returns the input
    /// unchanged if it doesn't parse as JSON - callers can feed arbitrary
    /// claim values through this safely.
    public static func prettyPrintJson(_ text: String) -> String {
        guard let data = text.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data),
              let pretty = try? JSONSerialization.data(
                withJSONObject: obj,
                options: [.prettyPrinted, .sortedKeys]
              ),
              let prettyString = String(data: pretty, encoding: .utf8) else {
            return text
        }
        return prettyString
    }

    /// Pretty-print an XML/SVG document with simple per-element indentation.
    ///
    /// This is not a validating parser - it's a light tokenizer good enough to
    /// make a VCTM SVG rendering template (or any other XML blob) readable in
    /// a "Raw"/debug view, mirroring what ``prettyPrintJson(_:)`` does for
    /// JSON. Self-closing tags (`<foo/>`), the XML declaration, and comments
    /// are handled; malformed input degrades to returning the original text
    /// unchanged rather than throwing.
    public static func prettyPrintXml(_ xml: String) -> String {
        var result = ""
        var depth = 0
        var index = xml.startIndex
        while index < xml.endIndex {
            guard let tagStart = xml[index...].firstIndex(of: "<") else {
                let remainder = xml[index...].trimmingCharacters(in: .whitespacesAndNewlines)
                if !remainder.isEmpty { result += remainder }
                break
            }
            let text = xml[index..<tagStart].trimmingCharacters(in: .whitespacesAndNewlines)
            guard let tagEnd = xml[tagStart...].firstIndex(of: ">") else {
                return xml
            }
            let tag = xml[tagStart...tagEnd]
            if !text.isEmpty {
                result += String(repeating: "  ", count: depth) + text + "\n"
            }
            let isClosing = tag.hasPrefix("</")
            let isSelfClosing = tag.hasSuffix("/>") || tag.hasPrefix("<?") || tag.hasPrefix("<!--")
            if isClosing { depth = max(0, depth - 1) }
            result += String(repeating: "  ", count: depth) + tag + "\n"
            if !isClosing && !isSelfClosing { depth += 1 }
            index = xml.index(after: tagEnd)
        }
        return result.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Extract user-facing claims from a stored credential.
    ///
    /// VCTM claim paths can be arbitrarily nested (e.g. a diploma's ELM schema
    /// nests everything under `credentialSubject`) - each claim is resolved by
    /// walking its own full path, not just matched by its first segment
    /// against a top-level key.
    public static func extractClaims(_ credential: StoredCredential) -> [DisplayClaim] {
        guard let payload = parseJwtPayload(credential.raw) else { return [] }
        let vctmClaims = credential.metadata?.claims ?? []

        let vctmResolved: [DisplayClaim] = vctmClaims.compactMap { claim in
            guard !claim.path.isEmpty, let value = resolveClaimPath(payload, claim.path) else { return nil }
            return DisplayClaim(
                key: claim.path.joined(separator: "."),
                label: claim.label ?? formatClaimKey(claim.path.last ?? ""),
                value: formatClaimValue(value),
                description: claim.description,
                mandatory: claim.mandatory,
                svgId: claim.svgId
            )
        }

        // Top-level keys already resolved (as an ancestor) via a VCTM path
        // shouldn't ALSO be dumped raw - e.g. once "credentialSubject.foo" is
        // resolved, don't separately dump the whole "credentialSubject" blob.
        let coveredTopLevelKeys = Set(vctmClaims.compactMap { $0.path.first })
        let uncovered = payload.keys.sorted().compactMap { key -> DisplayClaim? in
            guard !jwtSkipKeys.contains(key), !coveredTopLevelKeys.contains(key) else { return nil }
            return DisplayClaim(
                key: key,
                label: formatClaimKey(key),
                value: formatClaimValue(payload[key])
            )
        }

        return vctmResolved + uncovered
    }

    /// Walk a VCTM claim path (e.g. `["credentialSubject", "hasClaim", "awardedBy"]`)
    /// through nested JSON to the leaf value it selects. Returns nil if any
    /// segment is missing - the claim just isn't present in this credential.
    private static func resolveClaimPath(_ root: [String: Any], _ path: [String]) -> Any? {
        var current: Any = root
        for segment in path {
            guard let dict = current as? [String: Any], let next = dict[segment] else { return nil }
            current = next
        }
        return current
    }

    /// Build credential metadata from an offer, optional VCTM, and raw credential.
    public static func buildMetadata(
        offer: CredentialOffer,
        vctm: Vctm? = nil,
        rawCredential: String? = nil
    ) -> CredentialMetadata {
        let locale = Locale.current.identifier.replacingOccurrences(of: "_", with: "-")
        let vctmDisplay = vctm?.display.flatMap { displays in
            displays.first(where: { $0.locale == locale })
                ?? displays.first(where: { $0.locale.hasPrefix(String(locale.prefix(2))) })
                ?? displays.first
        }

        let simple = vctmDisplay?.rendering?.simple

        let payload = rawCredential.flatMap { parseJwtPayload($0) }
        let vct = payload?["vct"] as? String

        let claims: [ClaimMeta]? = vctm?.claims?.map { claim in
            let claimDisplay = claim.display.flatMap { displays in
                displays.first(where: { $0.locale == locale })
                    ?? displays.first(where: { $0.locale.hasPrefix(String(locale.prefix(2))) })
                    ?? displays.first
            }
            return ClaimMeta(
                path: claim.path.compactMap { $0 },
                label: claimDisplay?.label,
                description: claimDisplay?.description,
                sd: claim.sd,
                mandatory: claim.mandatory ?? false,
                svgId: claim.svgId
            )
        }

        let svgTemplates: [SvgTemplateInfo]? = vctmDisplay?.rendering?.svgTemplates?.map { template in
            SvgTemplateInfo(
                uri: template.uri,
                colorScheme: template.properties?.colorScheme,
                contrast: template.properties?.contrast,
                orientation: template.properties?.orientation
            )
        }

        return CredentialMetadata(
            name: vctmDisplay?.name ?? offer.credentialName,
            description: vctmDisplay?.description ?? offer.credentialDescription,
            issuer: IssuerInfo(
                name: offer.issuerName,
                url: offer.credentialIssuerIdentifier
            ),
            vct: vct,
            backgroundColor: simple?.backgroundColor ?? offer.backgroundColor,
            textColor: simple?.textColor ?? offer.textColor,
            logo: simple?.logo.map { LogoInfo(uri: $0.uri, altText: $0.altText) }
                ?? offer.logoUri.map { LogoInfo(uri: $0) },
            claims: claims,
            svgTemplates: svgTemplates
        )
    }

    /// Format a snake_case or kebab-case key as a human-readable label.
    public static func formatClaimKey(_ key: String) -> String {
        key.split(omittingEmptySubsequences: true, whereSeparator: { $0 == "_" || $0 == "-" })
            .map { $0.prefix(1).uppercased() + $0.dropFirst() }
            .joined(separator: " ")
    }

    // MARK: - Private

    private static func decodeJsonSegmentText(_ base64url: String) -> String? {
        guard let data = base64UrlDecode(base64url),
              let obj = try? JSONSerialization.jsonObject(with: data),
              let reencoded = try? JSONSerialization.data(withJSONObject: obj),
              let text = String(data: reencoded, encoding: .utf8) else {
            return nil
        }
        return text
    }

    private static func formatClaimValue(_ value: Any?) -> String {
        switch value {
        case let s as String: return s
        case let n as NSNumber: return n.stringValue
        case let b as Bool: return b ? "true" : "false"
        default: return String(describing: value ?? "")
        }
    }

    private static func base64UrlDecode(_ string: String) -> Data? {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder != 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        return Data(base64Encoded: base64)
    }
}

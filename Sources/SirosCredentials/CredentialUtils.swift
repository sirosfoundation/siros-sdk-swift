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

    public init(key: String, label: String, value: String, description: String? = nil, mandatory: Bool = false) {
        self.key = key
        self.label = label
        self.value = value
        self.description = description
        self.mandatory = mandatory
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

    /// Extract user-facing claims from a stored credential.
    public static func extractClaims(_ credential: StoredCredential) -> [DisplayClaim] {
        guard let payload = parseJwtPayload(credential.raw) else { return [] }
        let claimLabels = buildClaimLabelMap(credential.metadata?.claims)

        return payload.keys.sorted().compactMap { key in
            guard !jwtSkipKeys.contains(key) else { return nil }
            let labelInfo = claimLabels[key]
            return DisplayClaim(
                key: key,
                label: labelInfo?.label ?? formatClaimKey(key),
                value: formatClaimValue(payload[key]),
                description: labelInfo?.description,
                mandatory: labelInfo?.mandatory ?? false
            )
        }
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
                mandatory: claim.mandatory ?? false
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
            claims: claims
        )
    }

    /// Format a snake_case or kebab-case key as a human-readable label.
    public static func formatClaimKey(_ key: String) -> String {
        key.split(omittingEmptySubsequences: true, whereSeparator: { $0 == "_" || $0 == "-" })
            .map { $0.prefix(1).uppercased() + $0.dropFirst() }
            .joined(separator: " ")
    }

    // MARK: - Private

    private static func buildClaimLabelMap(_ claims: [ClaimMeta]?) -> [String: ClaimMeta] {
        guard let claims else { return [:] }
        var map: [String: ClaimMeta] = [:]
        for claim in claims where !claim.path.isEmpty {
            map[claim.path[0]] = claim
        }
        return map
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

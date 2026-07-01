// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials

// MARK: - Token Access Control

/// Token Access Control permission flags.
///
/// | Flag | Purpose  |
/// |------|----------|
/// | `r`  | read     |
/// | `w`  | write    |
/// | `l`  | list     |
/// | `i`  | insert   |
/// | `d`  | delete   |
/// | `k`  | delegate |
/// | `a`  | admin    |
public enum TacPermission: Character, Sendable, CaseIterable {
    case read = "r"
    case write = "w"
    case list = "l"
    case insert = "i"
    case delete = "d"
    case delegate = "k"
    case admin = "a"

    /// Parse a TAC string like "rwl" into a set of permissions.
    public static func parse(_ tac: String) -> Set<TacPermission> {
        Set(tac.compactMap { TacPermission(rawValue: $0) })
    }
}

/// Authentication Context Class Reference.
public enum Acr: String, Sendable, Codable {
    case passkey = "urn:siros:acr:passkey"
    case oidc = "urn:siros:acr:oidc"
}

// MARK: - Access Token

/// JWT payload from the AS token endpoint.
private struct AccessTokenPayload: Decodable {
    let sub: String
    let aud: String
    let tenantId: String
    let tac: String
    let acr: String
    let exp: Int

    private enum CodingKeys: String, CodingKey {
        case sub, aud, tac, acr, exp
        case tenantId = "tenant_id"
    }
}

/// Parsed access token with claims and utility methods.
///
/// Mirrors the TypeScript `AccessToken` from wallet-frontend.
public struct AccessToken: Sendable {
    /// Raw JWT string for use in Authorization headers.
    public let raw: String

    /// Subject — user ID this token represents.
    public let sub: String

    /// Audience — service this token is valid for.
    public let aud: String

    /// Tenant ID for multi-tenant isolation.
    public let tenantId: String

    /// Token Access Control permissions.
    public let tac: Set<TacPermission>

    /// Authentication context — how the user authenticated.
    public let acr: Acr

    /// Token expiration date.
    public let expiresAt: Date

    /// Parse an access token from a raw JWT string.
    public init(jwt: String) throws {
        let parts = jwt.split(separator: ".")
        guard parts.count == 3 else {
            throw SirosError.auth(message: "Invalid JWT format")
        }
        let payloadData = Self.base64UrlDecode(String(parts[1]))
        let payload = try JSONDecoder().decode(AccessTokenPayload.self, from: payloadData)

        self.raw = jwt
        self.sub = payload.sub
        self.aud = payload.aud
        self.tenantId = payload.tenantId
        self.tac = TacPermission.parse(payload.tac)
        guard let acr = Acr(rawValue: payload.acr) else {
            throw SirosError.auth(message: "Unknown ACR value: \(payload.acr)")
        }
        self.acr = acr
        self.expiresAt = Date(timeIntervalSince1970: TimeInterval(payload.exp))
    }

    /// True if the token is expired (with a 10-second safety margin).
    public func isExpired() -> Bool {
        Date().timeIntervalSince1970 >= expiresAt.timeIntervalSince1970 - 10
    }

    /// Returns the raw JWT for use in Authorization headers.
    public func token() -> String { raw }

    // MARK: - Base64URL

    private static func base64UrlDecode(_ string: String) -> Data {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder != 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        return Data(base64Encoded: base64) ?? Data()
    }
}

// MARK: - Token Response

/// Response from the AS token endpoint.
public struct TokenResponse: Codable, Sendable {
    public let accessToken: String
    public let tokenType: String
    public let expiresIn: Int

    private enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
    }
}



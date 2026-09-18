// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(os)
import os
private let statusLogger = Logger(subsystem: "org.siros.sdk", category: "CredentialStatus")
#endif

/// Why a credential cannot currently be used, or ``valid`` when it can.
///
/// These are the outcomes of DIIP's Validity and Revocation Algorithm: the
/// `validFrom` / `validUntil` window, and the issuer's Token Status List.
///
/// This is deliberately one enum rather than a set of booleans. A wallet shows
/// one reason a credential is unusable, and an `isExpired` flag alongside an
/// `isRevoked` flag invites UI that shows the wrong one, or both.
public enum CredentialStatus: String, Sendable, CaseIterable {
    /// Inside its validity window and not revoked or suspended.
    case valid

    /// `validFrom` / `nbf` lies in the future.
    case notYetValid

    /// `validUntil` / `exp` has passed.
    case expired

    /// The issuer's Token Status List marks this credential invalid.
    case revoked

    /// This wallet cannot say. Either the credential's own validity data
    /// would not parse, or the issuer's Status List published a value this
    /// wallet does not recognise.
    ///
    /// Deliberately not ``valid``: an unreachable status list leaves a
    /// credential usable - that is what keeps a wallet working offline - but
    /// data that is present and not understood is a different thing, and
    /// calling it valid would be a claim this wallet cannot support.
    case unknown

    /// The issuer's Token Status List marks this credential suspended -
    /// temporary, unlike ``revoked``.
    case suspended

    /// Whether the credential can be presented.
    public var isUsable: Bool { self == .valid }
}

/// The window a credential is valid in.
///
/// `validFrom` / `validUntil` are the W3C VCDM 2.0 properties; `nbf` / `exp`
/// are their JWT-native equivalents. An absent bound means "no bound" - the
/// VCDM reads a missing `validUntil` as valid indefinitely, not as expired.
public struct ValidityWindow: Sendable, Equatable {
    public let validFrom: Date?
    public let validUntil: Date?
    /// When the credential was signed (`iat`), for display only.
    public let signed: Date?

    public init(validFrom: Date? = nil, validUntil: Date? = nil, signed: Date? = nil) {
        self.validFrom = validFrom
        self.validUntil = validUntil
        self.signed = signed
    }
}

/// Reads and checks credential validity windows.
public enum CredentialValidity {

    /// Derive the validity window from a credential's claims.
    ///
    /// The VCDM 2.0 dateTime properties win over the numeric JWT claims when
    /// both are present: a VCDM credential's own `validFrom` / `validUntil`
    /// are authoritative, and `exp` on such a credential is the enveloping
    /// JWT's lifetime, which may be shorter.
    public static func extract(from claims: [String: Any]) -> ValidityWindow {
        ValidityWindow(
            validFrom: parseDateTime(claims["validFrom"]) ?? parseEpochSeconds(claims["nbf"]),
            validUntil: parseDateTime(claims["validUntil"]) ?? parseEpochSeconds(claims["exp"]),
            signed: parseEpochSeconds(claims["iat"])
        )
    }

    /// Check a window against the current time.
    ///
    /// - Parameter clockTolerance: leeway, matching the tolerance used for
    ///   signature verification - a credential is not shown as expired because
    ///   of a few seconds of clock skew.
    public static func check(
        _ window: ValidityWindow,
        clockTolerance: TimeInterval = 0,
        now: Date = Date()
    ) -> CredentialStatus {
        if let validUntil = window.validUntil,
           validUntil.timeIntervalSince1970 + clockTolerance < now.timeIntervalSince1970 {
            return .expired
        }
        if let validFrom = window.validFrom,
           validFrom.timeIntervalSince1970 - clockTolerance > now.timeIntervalSince1970 {
            return .notYetValid
        }
        return .valid
    }

    private static let isoFormatters: [ISO8601DateFormatter] = {
        let withFractional = ISO8601DateFormatter()
        withFractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        return [plain, withFractional]
    }()

    private static func parseDateTime(_ value: Any?) -> Date? {
        guard let text = value as? String, !text.isEmpty else { return nil }
        for formatter in isoFormatters {
            if let date = formatter.date(from: text) { return date }
        }
        return nil
    }

    private static func parseEpochSeconds(_ value: Any?) -> Date? {
        guard let seconds = (value as? NSNumber)?.doubleValue else { return nil }
        return Date(timeIntervalSince1970: seconds)
    }
}

/// Runs DIIP's Validity and Revocation Algorithm over a credential.
///
/// Construct one per wallet session and share it: it holds the Token Status
/// List cache, so a list covering many credentials is fetched once.
public actor CredentialStatusEvaluator {
    private let statusListClient: TokenStatusListClient?
    private let clockTolerance: TimeInterval
    private let now: @Sendable () -> Date

    /// - Parameters:
    ///   - statusListClient: looks up revocation. Nil disables the revocation
    ///     half - the validity window is still checked, which is what an
    ///     offline-only wallet can do.
    ///   - clockTolerance: leeway applied to both halves.
    public init(
        statusListClient: TokenStatusListClient? = nil,
        clockTolerance: TimeInterval = 0,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.statusListClient = statusListClient
        self.clockTolerance = clockTolerance
        self.now = now
    }

    /// Evaluate a credential from its claims.
    ///
    /// The validity window is checked first and short-circuits: an expired
    /// credential is expired whether or not its status list is reachable, and
    /// saying so needs no network.
    ///
    /// A status list that cannot be reached is a warning, not a revocation -
    /// refusing to show a credential because the issuer's status endpoint is
    /// down would make the wallet unusable offline. That is a deliberate
    /// choice, and it matches wallet-frontend.
    /// - Parameter credentialIssuer: the issuer this credential was stored
    ///   under, used when the claims themselves name none. An mdoc's
    ///   normalised claims carry no `iss`, and without this the Status List
    ///   Token's issuer binding would be skipped for every mdoc - letting a
    ///   token served from the credential's own status URI claim to be from
    ///   any issuer at all.
    public func evaluate(claims: [String: Any], credentialIssuer: String? = nil) async -> CredentialStatus {
        let windowStatus = CredentialValidity.check(
            CredentialValidity.extract(from: claims),
            clockTolerance: clockTolerance,
            now: now()
        )
        guard windowStatus == .valid else { return windowStatus }

        guard let statusListClient,
              let reference = TokenStatusList.extractReference(from: claims)
        else { return .valid }

        // The credential's own `iss` wins - it is signed - and the stored
        // issuer identifier stands in only when there is none.
        let resolution = await statusListClient.resolve(
            reference,
            expectedIssuer: Self.issuer(of: claims) ?? credentialIssuer,
            clockTolerance: clockTolerance
        )
        switch resolution {
        case .unavailable(let reason):
            #if canImport(os)
            statusLogger.warning("Could not determine revocation status: \(reason, privacy: .public)")
            #endif
            return .valid
        case .found(let status):
            switch status {
            case TokenStatusList.Status.valid: return .valid
            case TokenStatusList.Status.invalid: return .revoked
            case TokenStatusList.Status.suspended: return .suspended
            // The issuer published something this wallet does not know.
            // Reading that as "valid" would be fail-open: the draft reserves
            // further values, and an application-specific one means whatever
            // the issuer's ecosystem says, not "fine".
            default:
                #if canImport(os)
                statusLogger.warning("Status list published an unrecognised status \(status, privacy: .public)")
                #endif
                return .unknown
            }
        }
    }

    /// The issuer identifier of a credential.
    ///
    /// SD-JWT VC and JWT VC JSON use the JOSE `iss` claim. A W3C VCDM 2.0
    /// credential secured with SD-JWT (VC-JOSE-COSE §3.2.1) instead carries
    /// the VCDM `issuer` property, which is either an identifier string or an
    /// object with an `id`.
    static func issuer(of claims: [String: Any]) -> String? {
        if let iss = claims["iss"] as? String { return iss }
        if let issuer = claims["issuer"] as? String { return issuer }
        if let issuer = claims["issuer"] as? [String: Any] { return issuer["id"] as? String }
        return nil
    }
}

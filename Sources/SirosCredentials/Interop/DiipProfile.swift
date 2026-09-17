// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Which DIIP profile version a wallet targets.
///
/// DIIP (Decentralized Identity Interop Profile) is not a specification but a
/// *profile*: it pins the versions of OID4VCI, OID4VP, SD-JWT VC and the Token
/// Status List that an implementation must support, and removes optionality
/// inside them. Because it pins versions, a new DIIP release moves wire
/// details a wallet has to get right - so the profile is a value the SDK
/// carries and branches on, not a set of hardcoded constants.
///
/// The profile is released roughly twice a year. ``latest`` is what a wallet
/// gets by default; an older one stays selectable for an ecosystem that has
/// not moved yet, which is the whole point of naming versions.
///
/// - SeeAlso: [FIDEScommunity/DIIP](https://github.com/FIDEScommunity/DIIP)
public enum DiipProfile: String, Sendable, CaseIterable, Comparable {
    /// DIIP v4 - OID4VCI draft 15, OID4VP draft 28, SD-JWT VC draft 08,
    /// Token Status List draft 10. No trust establishment mechanism.
    case v4

    /// DIIP v5, approved by the FIDES Community on 2026-01-15 - OID4VCI 1.0
    /// Final, OID4VP 1.0 Final, SD-JWT VC draft 13, Token Status List draft
    /// 15, and OpenID Federation DCP as an OPTIONAL trust establishment
    /// mechanism.
    case v5

    /// DIIP v6 - a FIDES Community draft. Its release text is at present
    /// identical to ``v5``; what it adds here is the profile's own signposted
    /// Future Directions, which are the changes a wallet can prepare for
    /// without waiting for the text: `did:webvh` alongside `did:web`, the
    /// Digital Credentials API, and OpenID Federation support in Wallets
    /// (not only in Issuer and Verifier Agents).
    ///
    /// Everything v6 adds is additive - a v6 wallet is a superset of a v5 one
    /// - which is why it is safe to make it the default.
    case v6

    /// The newest profile this SDK implements, and the default for a wallet
    /// that does not pick one. Each version is additive over the one before,
    /// so defaulting forward does not drop support for an ecosystem still on
    /// an older release.
    public static let latest: DiipProfile = .v6

    /// The profile version as it is written, e.g. `"v5"`.
    public var version: String { rawValue }

    /// Parse a profile version as written in configuration - `"v5"`, `"V5"` or
    /// `"5"` all work. Returns nil for anything else, so a caller can fall
    /// back to ``latest`` rather than crash on a typo.
    public static func from(version: String?) -> DiipProfile? {
        guard let normalized = version?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .drop(while: { $0 == "v" }),
            !normalized.isEmpty
        else { return nil }
        return allCases.first { $0.rawValue.dropFirst() == normalized }
    }

    public static func < (lhs: DiipProfile, rhs: DiipProfile) -> Bool {
        guard let l = allCases.firstIndex(of: lhs), let r = allCases.firstIndex(of: rhs) else {
            return false
        }
        return l < r
    }

    // MARK: - Identifiers

    /// The DID method a Holder's own credential keys are identified by.
    ///
    /// Every DIIP version requires `did:jwk` for Holders. `did:key` is not a
    /// DIIP identifier at all - it is what this SDK and wallet-frontend used
    /// before DIIP, and a wallet still holding credentials bound to one keeps
    /// working, but it is never what a new key gets.
    public var holderDidMethod: DidMethod { .jwk }

    /// DID methods whose documents this profile requires a wallet to resolve -
    /// to find an Issuer's signing key, or to check a Verifier's identity.
    public var resolvableDidMethods: Set<DidMethod> {
        switch self {
        case .v4, .v5:
            return [.jwk, .web]
        case .v6:
            // Future Directions: "A near-future version of DIIP will probably
            // require support for did:webvh instead of did:web." Resolving
            // both is strictly more interoperable than resolving either.
            return [.jwk, .web, .webvh]
        }
    }

    // MARK: - Issuance (OID4VCI)

    /// Whether the Authorization Request must be able to carry
    /// `authorization_details` with a `credential_configuration_id`.
    ///
    /// Required of Wallets by every DIIP version; `scope` must be supported
    /// too, so this is about being *able* to send it, not about choosing.
    public var supportsAuthorizationDetails: Bool { true }

    /// The `.well-known` suffix an SD-JWT VC issuer publishes its signing keys
    /// under. Renamed by SD-JWT VC between draft 08 and draft 13, so it moves
    /// with the profile version rather than being a constant.
    public var sdJwtVcIssuerMetadataPath: String {
        switch self {
        case .v4: return "/.well-known/jwt-vc-issuer"
        case .v5, .v6: return "/.well-known/vc-issuer"
        }
    }

    // MARK: - Presentation (OID4VP)

    /// How a Verifier's `client_id` names its scheme.
    ///
    /// OID4VP draft 28 wrote a DID-identified Verifier as the bare DID
    /// (`did:web:verifier.example`), with the scheme carried out of band in
    /// `client_id_scheme`. OID4VP 1.0 Final replaced that with Client
    /// Identifier Prefixes, where the prefix is part of the `client_id` itself
    /// (`decentralized_identifier:did:web:verifier.example`). A wallet has to
    /// read both to talk to both generations of Verifier - see
    /// `ClientIdScheme.parse`, which does - but only one of them is what this
    /// profile says a compliant Verifier sends.
    public var clientIdStyle: ClientIdStyle {
        switch self {
        case .v4: return .bareScheme
        case .v5, .v6: return .prefixed
        }
    }

    /// Whether the profile requires the W3C Digital Credentials API as a
    /// presentation channel. v5 explicitly lists it as *not* required; it is a
    /// v6 Future Direction.
    public var requiresDigitalCredentialsApi: Bool { self >= .v6 }

    // MARK: - Validity and revocation

    /// The Token Status List draft a compliant Issuer publishes. The bit
    /// packing and the `status_list` claim shape this SDK reads have not
    /// changed across these drafts, so this is informational - it is what an
    /// interop report should cite, not a branch in the reader.
    public var tokenStatusListDraft: Int {
        switch self {
        case .v4: return 10
        case .v5, .v6: return 15
        }
    }

    // MARK: - Trust establishment

    /// Whether a *Wallet* is expected to take part in OpenID Federation.
    ///
    /// v5 requires Entity Configurations of Issuer and Verifier Agents only,
    /// and makes the whole section OPTIONAL. Making Wallets participate is a
    /// signposted Future Direction.
    public var requiresWalletFederation: Bool { self >= .v6 }
}

/// How a Verifier's `client_id` names the scheme it is identified under.
public enum ClientIdStyle: Sendable {
    /// OID4VP draft 28 and earlier: the bare identifier, e.g. `did:web:x`.
    case bareScheme

    /// OID4VP 1.0 Final: `<prefix>:<identifier>`, e.g.
    /// `decentralized_identifier:did:web:x`.
    case prefixed
}

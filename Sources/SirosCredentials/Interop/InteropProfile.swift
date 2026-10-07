// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Which OpenID4VC interoperability profile a wallet is speaking.
///
/// This SDK implements both, and a wallet holds credentials from both at once.
/// They agree on almost everything - OID4VCI, OID4VP, SD-JWT VC, the Token
/// Status List - and disagree on exactly one thing a wallet must decide before
/// it signs: **how the Holder's key is named**.
///
/// - ``haip`` identifies the Holder by the key itself. The OID4VCI `jwt` proof
///   carries the public key in its `jwk` header, and the Issuer binds the
///   credential with a `cnf.jwk`.
/// - ``diip`` identifies the Holder by a `did:jwk`. The proof carries that DID
///   as `iss` and *names* the key with a `kid`, and the Issuer binds the
///   credential with a `cnf.kid`.
///
/// OID4VCI allows only one of `jwk` and `kid` in a proof header, so this is a
/// genuine choice rather than something a wallet can hedge on. It is made per
/// *issuance*, not once per wallet: an Issuer that does not resolve DIDs cannot
/// verify a DIIP-shaped proof, and a DIIP conformance suite will not accept a
/// HAIP-shaped one.
///
/// Presentation needs no such choice, and this type has no say in it: the
/// credential's own `cnf` states how its Holder key is named, so a wallet
/// presents a HAIP credential and a DIIP credential correctly whatever profile
/// it was configured with. That is what makes the two coexist rather than
/// merely both being implemented.
public enum InteropProfile: String, Sendable, CaseIterable {
    /// OpenID4VC High Assurance Interoperability Profile - the EUDI/ARF
    /// profile, and what this SDK spoke before DIIP was added. Device-bound
    /// credentials, mdoc and SD-JWT VC, holder key carried by value.
    case haip

    /// Decentralized Identity Interop Profile - see ``DiipProfile`` for the
    /// version. Adds W3C VCDM 2.0 and DID-identified actors; holder key named
    /// by a `did:jwk` verification method.
    case diip

    /// The profile a wallet speaks when nothing more specific is known.
    ///
    /// ``haip``, because that is what this SDK has always sent and what the
    /// SIROS ID issuers expect; switching every wallet's proof shape as a side
    /// effect of adding DIIP support would be a wire change nobody asked for.
    /// In practice this is rarely reached - the Issuer's own metadata decides,
    /// see ``HolderBinding/negotiate(_:)``.
    public static let `default`: InteropProfile = .haip

    /// How this profile names the Holder's key in an OID4VCI proof.
    public var holderBinding: HolderBinding {
        switch self {
        case .haip: return .embeddedJwk
        case .diip: return .didJwk
        }
    }

    /// Parse the value as written in configuration; nil if unrecognised.
    public static func from(id: String?) -> InteropProfile? {
        guard let normalized = id?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() else {
            return nil
        }
        return InteropProfile(rawValue: normalized)
    }
}

/// How the Holder's key is named in an OID4VCI `jwt` proof, and therefore how
/// the Issuer will bind the credential it issues.
public enum HolderBinding: Sendable, Equatable {
    /// The proof header carries the public key as a `jwk`; the Issuer binds
    /// with `cnf.jwk`. What HAIP requires, and what any Issuer that does not
    /// resolve DIDs can verify.
    case embeddedJwk

    /// The proof carries the Holder's `did:jwk` as `iss` and names the key with
    /// a `kid` from that DID document; the Issuer binds with `cnf.kid`. What
    /// DIIP requires.
    case didJwk

    /// The OID4VCI `cryptographic_binding_methods_supported` value this binding
    /// corresponds to, for matching against what an Issuer advertises.
    public var bindingMethod: String {
        switch self {
        case .embeddedJwk: return "jwk"
        case .didJwk: return "did:jwk"
        }
    }

    /// Work out how to bind the Holder's key from what the Issuer says it
    /// accepts - OID4VCI's `cryptographic_binding_methods_supported` on the
    /// credential configuration being issued.
    ///
    /// This is what lets one wallet serve a HAIP ecosystem and a DIIP ecosystem
    /// side by side without asking anyone to choose: the Issuer already
    /// declares which identifier it can verify, so the wallet reads it rather
    /// than being configured. A HAIP Issuer advertises `jwk`; a DIIP Issuer
    /// advertises `did:jwk` (or a bare `did`, meaning any DID method).
    ///
    /// `did:jwk` wins when an Issuer advertises both (changed from preferring
    /// `jwk` - see sirosfoundation/siros-sdk-swift#147's review discussion).
    /// A wallet that only ever speaks DIIP has no "configured profile" at
    /// all - it emits did:jwk whenever an Issuer accepts it, because that is
    /// what DIIP requires. Converging on that is converging on the wider
    /// DIIP ecosystem's actual behavior, not a SIROS-specific tie-break;
    /// it also costs an Issuer nothing extra, since did:jwk is
    /// self-certifying and needs no network DID resolution. The reverse
    /// rule (`jwk` always wins) made `interopProfile = .diip` practically
    /// unreachable against any Issuer that also advertises `jwk` - every
    /// SIROS Issuer - leaving the per-issuer `holderBinding` override as the
    /// only way DIIP ever activated. A caller that needs a guaranteed
    /// embedded-key proof regardless of what the Issuer advertises (e.g.
    /// HAIP conformance testing) still has that explicit per-call override;
    /// this only changes what the *default* negotiation picks.
    ///
    /// Returns nil when the Issuer advertises nothing usable - it said nothing
    /// about binding at all, or named only methods this wallet cannot produce
    /// (`cose_key`, a DID method other than `did:jwk`). The caller then falls
    /// back to its configured profile rather than guessing, since a wrong guess
    /// is a failed issuance either way.
    public static func negotiate(_ advertisedMethods: [String]?) -> HolderBinding? {
        guard let advertisedMethods, !advertisedMethods.isEmpty else { return nil }
        let methods = Set(
            advertisedMethods.map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
        )
        // `did` on its own means "any DID method"; DIIP names `did:jwk`.
        // Another DID method is not a match: did:jwk is the only one a Holder
        // key can be published under here.
        if methods.contains("did") || methods.contains("did:jwk") { return .didJwk }
        if methods.contains("jwk") { return .embeddedJwk }
        return nil
    }
}

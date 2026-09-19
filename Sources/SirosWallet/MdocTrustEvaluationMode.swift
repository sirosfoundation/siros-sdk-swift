// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// How an mdoc trust question is answered: by asking go-trust, by validating
/// against locally configured roots, or by asking go-trust with the local
/// roots as a fallback.
///
/// The same choice applies to both mdoc trust registries, independently:
/// RICAL for readers (`SirosWallet.evaluateReaderTrust`, ISO/IEC 18013-5
/// second edition Annex F) and VICAL for issuers
/// (`SirosWallet.evaluateIssuerTrust`, Annex C).
///
/// ## What the two paths actually are
///
/// The **remote** path is an AuthZEN evaluation against go-trust, which is
/// the only path that honors a registry's temporary and dynamic trust roots
/// — go-trust's own cache and refresh handle freshness, so the wallet just
/// asks fresh each time. It also enforces RICAL `trustConstraints` and
/// VICAL's per-certificate `docType`.
///
/// The **local** path is plain X.509 path validation against configured PEM
/// roots (`WalletConfig.readerTrustRootCertificatesPem` /
/// `issuerTrustRootCertificatesPem`). It parses no RICAL/VICAL CBOR and
/// enforces none of those constraints. It exists for the stable,
/// known-in-advance official roots — it is deliberately not a
/// reimplementation of the registries, and it is the weaker of the two.
///
/// Because local is weaker, which one runs is a security decision rather
/// than a performance one, which is why it is spelled out as a mode instead
/// of inferred.
public enum MdocTrustEvaluationMode: String, Sendable, Codable, CaseIterable {
    /// Ask go-trust; fall back to the local roots only when it could not be
    /// reached. The default, and the behavior every previous release had.
    ///
    /// A backend that answers "no" is a denial and is returned as one. A
    /// backend that *refuses the caller* — any 4xx, e.g. an expired token
    /// producing a 403 — is also not a fallback condition: it means the
    /// backend was reachable and rejected us, not the trust question. Only a
    /// transport failure or a 5xx falls back. See
    /// `SirosWallet.isRemoteTrustEvaluationUnreachable`.
    case remoteWithLocalFallback

    /// Ask go-trust, and fail closed if it cannot be reached.
    ///
    /// For deployments that would rather deny a presentation than accept one
    /// on the strength of a check that skips `trustConstraints` and `docType`
    /// enforcement. Nothing is silently downgraded in this mode.
    case remoteOnly

    /// Never ask go-trust; validate against the configured roots.
    ///
    /// For an offline deployment, an event with no connectivity, or a host
    /// app honoring a user who explicitly opted into local-only evaluation.
    /// With no roots configured this reports untrusted rather than silently
    /// no-oping.
    case localOnly
}

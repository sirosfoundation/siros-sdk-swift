// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosKeystore
@preconcurrency import SwiftCBOR
#if canImport(Security)
import Security
#endif

extension SirosWallet {
    /// Evaluates an mdoc credential's issuer authenticated identity for trust
    /// (ISO/IEC 18013-5 Annex C, `issuerAuth`) - the wallet-side counterpart
    /// to `evaluateReaderTrust`, called defensively when a newly-issued
    /// `mso_mdoc` credential is about to be stored, before it's trusted.
    /// Mirrors `evaluateReaderTrust`'s exact remote-then-local-fallback
    /// shape with a `"mdoc-issuer-auth"` action name against go-trust's
    /// `vical` registry. Only ever called with an x5chain whose `issuerAuth`
    /// COSE_Sign1 signature has ALREADY verified locally (see
    /// `MdocCose.verify1`) - this method is purely the trust decision.
    /// Ported from the Kotlin SDK's `SirosWallet.evaluateIssuerTrust`.
    ///
    /// Defaults to the remote AuthZEN call - this is the only path that
    /// honors VICAL's dynamic updates, since go-trust's own registry
    /// cache/refresh handles freshness and the wallet just calls it fresh
    /// each time. Falls back to local X.509 path validation against
    /// `WalletConfig.issuerTrustRootCertificatesPem` if the remote call
    /// throws (backend unreachable), or unconditionally if
    /// `WalletConfig.preferLocalIssuerTrustEvaluation` is set.
    ///
    /// - Parameter x5chain: the issuer's DER-encoded certificate chain, leaf first.
    /// - Parameter docType: the credential's mdoc doctype (e.g.
    ///   `"org.iso.18013.5.1.mDL"`), used for VICAL's per-certificate
    ///   docType enforcement - only enforced remotely (go-trust's `vical`
    ///   registry skips, not denies, if omitted); the local fallback never
    ///   enforces it, same as RICAL's fallback skipping `trustConstraints`.
    public func evaluateIssuerTrust(_ x5chain: [[UInt8]], docType: String?) async -> TrustResult {
        guard !x5chain.isEmpty else {
            return TrustResult(trusted: false, reason: "issuerAuth has no certificate chain")
        }
        if config.preferLocalIssuerTrustEvaluation {
            return evaluateIssuerTrustLocally(x5chain)
        }
        do {
            return try await evaluateIssuerTrustRemote(x5chain, docType: docType)
        } catch {
            return evaluateIssuerTrustLocally(x5chain)
        }
    }

    private func evaluateIssuerTrustRemote(_ x5chain: [[UInt8]], docType: String?) async throws -> TrustResult {
        try await evaluateMdocTrustRemote(
            x5chain: x5chain,
            actionName: "mdoc-issuer-auth",
            defaultFramework: "vical",
            extraContext: docType.map { ["doc_type": $0] }
        )
    }

    /// Plain X.509 path validation against
    /// `WalletConfig.issuerTrustRootCertificatesPem` - no VICAL CBOR
    /// parsing, no per-certificate `docType` enforcement, since this path
    /// exists purely as an offline/unreachable-backend fallback for the
    /// stable, known-in-advance official root(s), not a full
    /// reimplementation of go-trust's `vical` registry.
    private func evaluateIssuerTrustLocally(_ x5chain: [[UInt8]]) -> TrustResult {
        evaluateMdocTrustLocally(
            x5chain: x5chain,
            rootCertificatesPem: config.issuerTrustRootCertificatesPem,
            frameworkLabel: "local-vical-root",
            entityLabel: "issuer",
            registryName: "VICAL"
        )
    }

    /// Verifies an mdoc credential's `issuerAuth` COSE_Sign1 (ISO 18013-5
    /// Annex C) against its own embedded x5chain, then hands that chain to
    /// `evaluateIssuerTrust` for the actual trust decision - the issuance-
    /// time counterpart to `MdocProximitySession`'s presentation-time
    /// readerAuth check. Returns nil (skip, don't block storage) if
    /// `issuerAuth` has no x5chain or its signature doesn't verify,
    /// mirroring that same "no badge, not untrusted" convention for a check
    /// that can't even be attempted.
    ///
    /// - Parameter issuerAuth: the credential's `issuerAuth` COSE_Sign1 4-element array.
    /// - Parameter docType: the credential's mdoc doctype, for VICAL docType enforcement.
    func verifyAndEvaluateIssuerTrust(_ issuerAuth: CBOR, docType: String) async -> TrustResult? {
        #if canImport(Security)
        let chain = MdocCose.extractX5Chain(issuerAuth)
        guard !chain.isEmpty else { return nil }
        guard let issuerCert = SecCertificateCreateWithData(nil, Data(chain[0]) as CFData),
              let secKey = SecCertificateCopyKey(issuerCert) else { return nil }
        var error: Unmanaged<CFError>?
        guard let publicKeyX963 = SecKeyCopyExternalRepresentation(secKey, &error) as Data? else { return nil }

        guard case .array(let arr) = issuerAuth, arr.count == 4, case .byteString(let msoBytes) = arr[2] else { return nil }
        guard MdocCose.verify1(issuerAuth, payload: msoBytes, publicKeyX963: [UInt8](publicKeyX963)) else { return nil }

        return await evaluateIssuerTrust(chain, docType: docType)
        #else
        return nil
        #endif
    }
}

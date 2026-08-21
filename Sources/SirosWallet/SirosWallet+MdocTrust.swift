// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosAuth
import SirosCredentials
import SirosKeystore
#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(Security)
import Security
#endif

/// Shared remote-AuthZEN-call and local-X.509-fallback implementation for
/// `SirosWallet.evaluateReaderTrust` (RICAL, action `mdoc-reader-auth`) and
/// `SirosWallet.evaluateIssuerTrust` (VICAL, action `mdoc-issuer-auth`) -
/// both mirror the same request/response shape, differing only in the
/// action name, the default `framework` label (used when go-trust's
/// response omits its own), an optional `context` block (VICAL's `doc_type`
/// enforcement hint), and the local-fallback framework/entity/registry
/// labels. Extracted into this file (rather than duplicating both trust
/// checks end to end) to avoid the Kotlin SDK's own first-pass mistake of
/// writing VICAL as a near-verbatim copy of RICAL and only refactoring
/// afterward under SonarCloud's duplication gate - see the Kotlin SDK's
/// `evaluateMdocTrustRemote`/`evaluateMdocTrustLocally` for the reference
/// this file ports.
extension SirosWallet {
    func evaluateMdocTrustRemote(
        x5chain: [[UInt8]],
        actionName: String,
        defaultFramework: String,
        extraContext: [String: Any]? = nil
    ) async throws -> TrustResult {
        lock.lock(); let client = apiClient; lock.unlock()
        guard let client else { throw SirosError.wallet(message: "Not connected") }

        let subjectId = sha256Hex(x5chain[0])
        let x5c = x5chain.map { Data($0).base64EncodedString() }

        var evaluationRequest: [String: Any] = [
            "subject": ["type": "key", "id": subjectId],
            "resource": ["type": "x5c", "id": subjectId, "key": x5c],
            "action": ["name": actionName],
        ]
        if let extraContext {
            evaluationRequest["context"] = extraContext
        }

        let response = try await client.evaluateTrust(evaluationRequest)
        let decision = response["decision"] as? Bool ?? false
        let respContext = response["context"] as? [String: Any]

        return TrustResult(
            trusted: decision,
            framework: (respContext?["framework"] as? String) ?? defaultFramework,
            reason: (respContext?["reason"] as? String) ?? (respContext?["message"] as? String),
            entityName: respContext?["entity_name"] as? String,
            identifier: subjectId
        )
    }

    /// Plain X.509 path validation against `rootCertificatesPem` - no
    /// RICAL/VICAL CBOR parsing, no `trustConstraints`/`docType`
    /// enforcement, since this path exists purely as an offline/unreachable-
    /// backend fallback for the stable, known-in-advance official root(s),
    /// not a full reimplementation of go-trust's `mdocrical`/`vical`
    /// registries.
    ///
    /// Distinguishes "nothing configured" from "configured but every entry
    /// failed to parse" - matching the Kotlin port's identical distinction
    /// (a single message here would otherwise mask misconfiguration, since
    /// unparsable PEM entries are silently dropped by the caller after
    /// logging the parse failure at the point it occurs).
    func evaluateMdocTrustLocally(
        x5chain: [[UInt8]],
        rootCertificatesPem: [String],
        frameworkLabel: String,
        entityLabel: String,
        registryName: String
    ) -> TrustResult {
        let subjectId = sha256Hex(x5chain[0])
        #if canImport(Security)
        let roots = mdocTrustRootCertificates(fromPem: rootCertificatesPem)
        guard !roots.isEmpty else {
            let reason = rootCertificatesPem.isEmpty
                ? "Local \(entityLabel) trust evaluation is unavailable: no \(registryName) root certificate configured"
                : "Local \(entityLabel) trust evaluation is unavailable: \(rootCertificatesPem.count) " +
                    "\(registryName) root certificate(s) configured but none could be parsed"
            return TrustResult(trusted: false, framework: frameworkLabel, reason: reason, identifier: subjectId)
        }
        guard let certificates = certificateChain(from: x5chain) else {
            return TrustResult(
                trusted: false,
                framework: frameworkLabel,
                reason: "Failed to parse the certificate chain",
                identifier: subjectId
            )
        }

        var trust: SecTrust?
        let policy = SecPolicyCreateBasicX509()
        guard SecTrustCreateWithCertificates(certificates as CFTypeRef, policy, &trust) == errSecSuccess,
              let trust else {
            return TrustResult(
                trusted: false,
                framework: frameworkLabel,
                reason: "Failed to build a certificate trust object",
                identifier: subjectId
            )
        }
        SecTrustSetAnchorCertificates(trust, roots as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, true)

        var trustError: CFError?
        if SecTrustEvaluateWithError(trust, &trustError) {
            let leafName = (SecCertificateCopySubjectSummary(certificates[0]) as String?)
            return TrustResult(
                trusted: true,
                framework: frameworkLabel,
                reason: "Validated locally against a configured \(registryName) root certificate",
                entityName: leafName,
                identifier: subjectId
            )
        } else {
            return TrustResult(
                trusted: false,
                framework: frameworkLabel,
                reason: "Local \(registryName) root validation failed: \(trustError.map { String(describing: $0) } ?? "unknown error")",
                identifier: subjectId
            )
        }
        #else
        return TrustResult(
            trusted: false,
            framework: frameworkLabel,
            reason: "Local \(entityLabel) trust evaluation requires the Security framework (unsupported on this platform)",
            identifier: subjectId
        )
        #endif
    }

    #if canImport(Security)
    func certificateChain(from x5chain: [[UInt8]]) -> [SecCertificate]? {
        var certificates: [SecCertificate] = []
        for der in x5chain {
            guard let cert = SecCertificateCreateWithData(nil, Data(der) as CFData) else { return nil }
            certificates.append(cert)
        }
        return certificates
    }

    private func mdocTrustRootCertificates(fromPem pems: [String]) -> [SecCertificate] {
        pems.compactMap { pem in
            guard let der = Self.decodePem(pem) else { return nil }
            return SecCertificateCreateWithData(nil, der as CFData)
        }
    }

    /// Strips PEM armor (`-----BEGIN/END CERTIFICATE-----`) and base64-decodes
    /// the body - `SecCertificateCreateWithData` requires raw DER bytes.
    /// Trims whitespace/CR from each line before joining: PEM pasted from
    /// many sources (e.g. Windows-authored files, copy-paste) carries `\r`
    /// or trailing spaces, which `Data(base64Encoded:)` rejects outright.
    static func decodePem(_ pem: String) -> Data? {
        let lines = pem
            .split(whereSeparator: { $0 == "\n" || $0 == "\r\n" || $0 == "\r" })
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("-----") }
        return Data(base64Encoded: lines.joined())
    }
    #endif

    func sha256Hex(_ bytes: [UInt8]) -> String {
        #if canImport(CryptoKit)
        let digest = SHA256.hash(data: Data(bytes))
        return digest.map { String(format: "%02x", $0) }.joined()
        #else
        return bytes.map { String(format: "%02x", $0) }.joined()
        #endif
    }
}

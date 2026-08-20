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

extension SirosWallet {
    /// Evaluates a proximity reader's authenticated identity for trust - the
    /// `evaluateReaderTrust` dependency `MdocProximitySession` expects, for
    /// wiring into `BlePeripheralServer`/`BleCentralClient`. Only ever called
    /// with an x5chain whose `readerAuth` COSE_Sign1 signature has ALREADY
    /// verified locally (see `MdocCose.verify1`) - this method is purely the
    /// trust decision, mirroring `evaluateTrustDirect`'s request shape with a
    /// new `"mdoc-reader-auth"` action name against go-trust's `mdocrical`
    /// registry. Ported from the Kotlin SDK's `SirosWallet.evaluateReaderTrust`.
    ///
    /// Defaults to the remote AuthZEN call - this is the only path that
    /// honors RICAL's temporary/dynamic trust roots, since go-trust's own
    /// registry cache/refresh handles freshness and the wallet just calls it
    /// fresh each time. Falls back to local X.509 path validation against
    /// `WalletConfig.readerTrustRootCertificatesPem` if the remote call
    /// throws (backend unreachable), or unconditionally if
    /// `WalletConfig.preferLocalReaderTrustEvaluation` is set.
    ///
    /// - Parameter x5chain: the reader's DER-encoded certificate chain, leaf first.
    public func evaluateReaderTrust(_ x5chain: [[UInt8]]) async -> TrustResult {
        guard !x5chain.isEmpty else {
            return TrustResult(trusted: false, reason: "readerAuth has no certificate chain")
        }
        if config.preferLocalReaderTrustEvaluation {
            return evaluateReaderTrustLocally(x5chain)
        }
        do {
            return try await evaluateReaderTrustRemote(x5chain)
        } catch {
            return evaluateReaderTrustLocally(x5chain)
        }
    }

    private func evaluateReaderTrustRemote(_ x5chain: [[UInt8]]) async throws -> TrustResult {
        lock.lock(); let client = apiClient; lock.unlock()
        guard let client else { throw SirosError.wallet(message: "Not connected") }

        let subjectId = sha256Hex(x5chain[0])
        let x5c = x5chain.map { Data($0).base64EncodedString() }

        let evaluationRequest: [String: Any] = [
            "subject": ["type": "key", "id": subjectId],
            "resource": ["type": "x5c", "id": subjectId, "key": x5c],
            "action": ["name": "mdoc-reader-auth"],
        ]

        let response = try await client.evaluateTrust(evaluationRequest)
        let decision = response["decision"] as? Bool ?? false
        let respContext = response["context"] as? [String: Any]

        return TrustResult(
            trusted: decision,
            framework: (respContext?["framework"] as? String) ?? "mdocrical",
            reason: (respContext?["reason"] as? String) ?? (respContext?["message"] as? String),
            entityName: respContext?["entity_name"] as? String,
            identifier: subjectId
        )
    }

    /// Plain X.509 path validation against
    /// `WalletConfig.readerTrustRootCertificatesPem` - no RICAL CBOR
    /// parsing, no `trustConstraints` enforcement, since this path exists
    /// purely as an offline/unreachable-backend fallback for the stable,
    /// known-in-advance official root(s), not a full reimplementation of
    /// go-trust's `mdocrical` registry.
    private func evaluateReaderTrustLocally(_ x5chain: [[UInt8]]) -> TrustResult {
        let subjectId = sha256Hex(x5chain[0])
        #if canImport(Security)
        let roots = readerTrustRootCertificates()
        guard !roots.isEmpty else {
            return TrustResult(
                trusted: false,
                framework: "local-rical-root",
                reason: "Local reader trust evaluation is unavailable: no RICAL root certificate configured",
                identifier: subjectId
            )
        }
        guard let certificates = certificateChain(from: x5chain) else {
            return TrustResult(
                trusted: false,
                framework: "local-rical-root",
                reason: "Failed to parse readerAuth's certificate chain",
                identifier: subjectId
            )
        }

        var trust: SecTrust?
        let policy = SecPolicyCreateBasicX509()
        guard SecTrustCreateWithCertificates(certificates as CFTypeRef, policy, &trust) == errSecSuccess,
              let trust else {
            return TrustResult(
                trusted: false,
                framework: "local-rical-root",
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
                framework: "local-rical-root",
                reason: "Validated locally against a configured RICAL root certificate",
                entityName: leafName,
                identifier: subjectId
            )
        } else {
            return TrustResult(
                trusted: false,
                framework: "local-rical-root",
                reason: "Local RICAL root validation failed: \(trustError.map { String(describing: $0) } ?? "unknown error")",
                identifier: subjectId
            )
        }
        #else
        return TrustResult(
            trusted: false,
            framework: "local-rical-root",
            reason: "Local reader trust evaluation requires the Security framework (unsupported on this platform)",
            identifier: subjectId
        )
        #endif
    }

    #if canImport(Security)
    private func certificateChain(from x5chain: [[UInt8]]) -> [SecCertificate]? {
        var certificates: [SecCertificate] = []
        for der in x5chain {
            guard let cert = SecCertificateCreateWithData(nil, Data(der) as CFData) else { return nil }
            certificates.append(cert)
        }
        return certificates
    }

    private func readerTrustRootCertificates() -> [SecCertificate] {
        config.readerTrustRootCertificatesPem.compactMap { pem in
            guard let der = Self.decodePem(pem) else { return nil }
            return SecCertificateCreateWithData(nil, der as CFData)
        }
    }

    /// Strips PEM armor (`-----BEGIN/END CERTIFICATE-----`) and base64-decodes
    /// the body - `SecCertificateCreateWithData` requires raw DER bytes.
    private static func decodePem(_ pem: String) -> Data? {
        let lines = pem.split(separator: "\n").filter { !$0.hasPrefix("-----") }
        return Data(base64Encoded: lines.joined())
    }
    #endif

    private func sha256Hex(_ bytes: [UInt8]) -> String {
        #if canImport(CryptoKit)
        let digest = SHA256.hash(data: Data(bytes))
        return digest.map { String(format: "%02x", $0) }.joined()
        #else
        return bytes.map { String(format: "%02x", $0) }.joined()
        #endif
    }
}

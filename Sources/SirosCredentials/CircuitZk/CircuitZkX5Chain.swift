// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
@preconcurrency import SwiftCBOR

/// The `x5chain` member of a `circuit_zk` presentation: the issuer certificate chain the HOLDER supplies,
/// RFC 7515 `x5c` style (docs/circuit_zk_response.md in siros-dc-matcher, rule 5a). The verifier validates
/// it through its trust evaluation and takes the issuer's key from the validated leaf; it never looks up
/// issuer keys itself.
///
/// The chain is the credential's own: the Document Signer chain in `issuerAuth`'s unprotected header
/// (COSE label 33, RFC 9360), leaf first, re-encoded as the STANDARD base64 of each DER certificate, WITH
/// padding. Certificates are not parsed here. A chain that breaks a limit is never sent (it would be
/// refused by the verifier): the build returns nil.
public enum CircuitZkX5Chain {
    /// Most certificates a chain may carry.
    public static let maxCertificates = 8
    /// Largest certificate, in decoded (DER) bytes.
    public static let maxCertificateBytes = 4096

    /// COSE header label `x5chain`.
    private static let label: CBOR = .unsignedInt(33)

    /// The DER certificates of `issuerAuth` (a COSE_Sign1), leaf first, or nil when it carries no chain or
    /// the chain is not usable: no `x5chain`, anything but a byte string or a non-empty array of byte
    /// strings, an empty certificate, more than ``maxCertificates`` or one over ``maxCertificateBytes``.
    public static func certificates(issuerAuth: CBOR) -> [[UInt8]]? {
        guard case .array(let sign1) = issuerAuth, sign1.count == 4, case .map(let unprotected) = sign1[1],
              let chain = unprotected[label] else { return nil }
        let certificates: [[UInt8]]
        switch chain {
        case .byteString(let single):
            certificates = [single]
        case .array(let items):
            var out: [[UInt8]] = []
            for item in items {
                guard case .byteString(let der) = item else { return nil }
                out.append(der)
            }
            certificates = out
        default:
            return nil
        }
        guard !certificates.isEmpty, certificates.count <= maxCertificates,
              certificates.allSatisfy({ !$0.isEmpty && $0.count <= maxCertificateBytes }) else { return nil }
        return certificates
    }

    /// The `x5chain` member value: the certificates as padded standard base64 strings, leaf first.
    public static func encoded(issuerAuth: CBOR) -> [String]? {
        certificates(issuerAuth: issuerAuth)?.map { Data($0).base64EncodedString() }
    }

    /// The `x5chain` of a stored mdoc credential (its stored raw form), or nil when unreadable.
    public static func encoded(ofMdocRaw raw: String) -> [String]? {
        CredentialUtils.parseMdocDocument(raw).flatMap { encoded(issuerAuth: $0.issuerSigned.issuerAuth) }
    }
}

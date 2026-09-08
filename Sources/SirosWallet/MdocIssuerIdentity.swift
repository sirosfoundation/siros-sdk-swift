// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// The identity an mdoc issuer is known by, read from its document signer
/// (DS) certificate.
///
/// Trust registries for mdoc issuers are keyed on the issuer's URL, not on
/// its certificate: go-trust's `mdociaca` registry takes `subject.id` as the
/// issuer URL, checks it against its allowlist, fetches that issuer's IACAs
/// from its published `mdoc_iacas_uri` and only then path-validates the
/// chain. Handing it a certificate hash as the subject can never match, and
/// the wallet's issuer-trust check then answered "not trusted" on every
/// deployment without a VICAL registry - which is every deployment today.
///
/// Derived the same way the verifier side (vc's `extractMDocIssuerID`) and
/// the Kotlin SDK (`MdocIssuerIdentity`) derive it, so every party asks the
/// registry about the same subject:
///  1. the first URI SAN with an `https` scheme, or an `http` one lifted to
///     `https` (metadata discovery is https-only);
///  2. else the first non-wildcard DNS SAN, as `https://<host>`;
///  3. else nothing - the caller falls back to identifying the certificate
///     itself.
///
/// Reads the DER directly. Neither Foundation nor Security exposes a
/// certificate's subject alternative names on iOS (`SecCertificateCopyValues`
/// is macOS-only), and this is the only X.509 field the SDK needs to read,
/// so a dependency on a full X.509 library is not worth taking for it.
public enum MdocIssuerIdentity {

    /// The issuer URL named by the DER-encoded certificate's subject
    /// alternative names, or nil if it names none (or does not parse).
    public static func fromDer(_ der: [UInt8]) -> String? {
        guard let names = subjectAlternativeNames(der) else { return nil }
        for raw in names.uris {
            guard let url = URL(string: raw), let scheme = url.scheme?.lowercased() else { continue }
            if scheme == "https" { return raw }
            if scheme == "http" { return "https" + raw.dropFirst(scheme.count) }
        }
        return names.dnsNames.first { !$0.hasPrefix("*.") }.map { "https://\($0)" }
    }

    // MARK: - DER

    struct SubjectAlternativeNames: Equatable {
        var uris: [String] = []
        var dnsNames: [String] = []
    }

    /// id-ce-subjectAltName, 2.5.29.17.
    private static let subjectAltNameOID: [UInt8] = [0x55, 0x1D, 0x11]

    private struct TLV {
        let tag: UInt8
        let content: ArraySlice<UInt8>
        let end: Int
    }

    /// One tag-length-value at `offset`, or nil if the bytes there are not a
    /// well-formed definite-length element that fits in `bytes`.
    private static func readTLV(_ bytes: ArraySlice<UInt8>, at offset: Int) -> TLV? {
        var i = offset
        guard i < bytes.endIndex else { return nil }
        let tag = bytes[i]
        i += 1
        // Multi-byte tags do not occur in a certificate; treat them as malformed.
        guard tag & 0x1F != 0x1F, i < bytes.endIndex else { return nil }
        var length = Int(bytes[i])
        i += 1
        if length & 0x80 != 0 {
            let count = length & 0x7F
            guard count >= 1, count <= 4, i + count <= bytes.endIndex else { return nil }
            length = 0
            for _ in 0..<count {
                length = (length << 8) | Int(bytes[i])
                i += 1
            }
        }
        guard length >= 0, i + length <= bytes.endIndex else { return nil }
        return TLV(tag: tag, content: bytes[i..<(i + length)], end: i + length)
    }

    /// Every element in a constructed value's content, in order.
    private static func children(of content: ArraySlice<UInt8>) -> [TLV]? {
        var out: [TLV] = []
        var i = content.startIndex
        while i < content.endIndex {
            guard let tlv = readTLV(content, at: i) else { return nil }
            out.append(tlv)
            i = tlv.end
        }
        return out
    }

    /// Walks Certificate → tbsCertificate → [3] extensions → the
    /// subjectAltName extension → GeneralNames, collecting dNSName ([2]) and
    /// uniformResourceIdentifier ([6]) entries. Nil if the certificate does
    /// not parse; an empty result if it parses but has no such extension.
    static func subjectAlternativeNames(_ der: [UInt8]) -> SubjectAlternativeNames? {
        let bytes = der[...]
        guard let certificate = readTLV(bytes, at: bytes.startIndex), certificate.tag == 0x30,
              let tbs = readTLV(certificate.content, at: certificate.content.startIndex), tbs.tag == 0x30,
              let tbsFields = children(of: tbs.content)
        else { return nil }

        // extensions is the EXPLICIT [3] field, and the only one tagged so.
        guard let extensionsField = tbsFields.first(where: { $0.tag == 0xA3 }),
              let extensionsSeq = readTLV(extensionsField.content, at: extensionsField.content.startIndex),
              extensionsSeq.tag == 0x30,
              let extensions = children(of: extensionsSeq.content)
        else { return SubjectAlternativeNames() }

        for ext in extensions where ext.tag == 0x30 {
            guard let fields = children(of: ext.content), let oid = fields.first, oid.tag == 0x06,
                  Array(oid.content) == subjectAltNameOID
            else { continue }
            // Extension ::= SEQUENCE { extnID, critical BOOLEAN OPTIONAL, extnValue OCTET STRING }
            guard let value = fields.last, value.tag == 0x04,
                  let generalNames = readTLV(value.content, at: value.content.startIndex), generalNames.tag == 0x30,
                  let names = children(of: generalNames.content)
            else { return nil }
            var result = SubjectAlternativeNames()
            for name in names {
                switch name.tag {
                case 0x82: // [2] dNSName, IA5String
                    if let s = String(bytes: name.content, encoding: .ascii) { result.dnsNames.append(s) }
                case 0x86: // [6] uniformResourceIdentifier, IA5String
                    if let s = String(bytes: name.content, encoding: .ascii) { result.uris.append(s) }
                default:
                    continue
                }
            }
            return result
        }
        return SubjectAlternativeNames()
    }
}

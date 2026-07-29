// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
@preconcurrency import SwiftCBOR
import SirosCredentials
#if canImport(CryptoKit)
import CryptoKit
#endif

/// Builds an ISO 18013-5 DeviceResponse for mDoc credential presentation
/// via OID4VP (OpenID for Verifiable Presentations).
///
/// The credential's raw bytes are a full DeviceResponse-shaped envelope as
/// issued (`{documents: [{docType, issuerSigned}], ...}` - confirmed via
/// `sirosfoundation/wallet-frontend#191`), not a bare IssuerSigned blob; this
/// builder parses that envelope with `MdocCbor`, applies real selective
/// disclosure by filtering `issuerSigned.nameSpaces` down to `disclosedClaims`
/// (preserving each kept item's original tag-24-wrapped bytes so the issuer's
/// MSO digests remain valid - disclosure selects a subset of already-digested
/// items, it never re-hashes), and signs a fresh device authentication over
/// the OpenID4VPHandover session transcript.
public final class MdocDeviceResponseBuilder: @unchecked Sendable {

    /// Raw credential bytes: a full DeviceResponse-shaped envelope as issued.
    private let credentialBytes: [UInt8]
    /// Algorithm for signing (ES256, ES384, or EdDSA).
    private let algorithm: String

    public init(credentialBytes: [UInt8], algorithm: String = "ES256") {
        self.credentialBytes = credentialBytes
        self.algorithm = algorithm
    }

    public convenience init(issuerSignedBytes: Data, algorithm: String = "ES256") {
        self.init(credentialBytes: [UInt8](issuerSignedBytes), algorithm: algorithm)
    }

    /// Build the CBOR-encoded DeviceResponse.
    ///
    /// - Parameters:
    ///   - nonce: Verifier nonce from the sign request.
    ///   - audience: Verifier client ID.
    ///   - responseUri: Response endpoint URI.
    ///   - verifierJwkThumbprint: Optional JWK thumbprint of the verifier key.
    ///   - disclosedClaims: Element identifiers to disclose (nil = disclose all namespaces/elements).
    ///   - signer: Function that signs raw bytes with the device key; must return a raw (not DER) signature.
    /// - Returns: CBOR-encoded DeviceResponse bytes.
    public func build(
        nonce: String,
        audience: String,
        responseUri: String,
        verifierJwkThumbprint: String?,
        disclosedClaims: [String]?,
        signer: @Sendable @escaping (Data) async throws -> Data
    ) async throws -> Data {
        let disclosedDocument = try parseAndFilter(disclosedClaims)
        let sessionTranscript = buildSessionTranscript(
            clientId: audience,
            nonce: nonce,
            responseUri: responseUri,
            verifierJwkThumbprint: verifierJwkThumbprint
        )
        let deviceAuthBytes = buildDeviceAuthentication(docType: disclosedDocument.docType, sessionTranscript: sessionTranscript)
        let coseSign1 = try await MdocCose.sign1Detached(algorithm: algorithm, externalAad: deviceAuthBytes) { bytes in
            try await Array(signer(Data(bytes)))
        }
        return Data(assembleFinalResponse(document: disclosedDocument, coseSign1: coseSign1))
    }

    /// Build the CBOR-encoded DeviceResponse for a W3C Digital Credentials API
    /// (DC API) presentation, using the `OpenID4VPDCAPIHandover` session
    /// transcript (OpenID4VP 1.0 Appendix B.2.6) instead of the redirect
    /// flow's `OpenID4VPHandover` - there is no `responseUri`/`clientId` in
    /// this flow (the response is returned via the browser's synchronous
    /// `navigator.credentials.get()` callback, not an HTTP POST), and the
    /// handover binds to the verified browser origin instead.
    ///
    /// - Parameters:
    ///   - nonce: Verifier nonce from the request.
    ///   - origin: The verified browser/page origin that called `navigator.credentials.get()`.
    ///   - encryptionPublicJwkThumbprint: JWK thumbprint of the verifier's
    ///     response-encryption key (present when `response_mode=dc_api.jwt`), nil otherwise.
    ///   - disclosedClaims: Element identifiers to disclose (nil = disclose all namespaces/elements).
    ///   - signer: Function that signs raw bytes with the device key; must return a raw (not DER) signature.
    /// - Returns: CBOR-encoded DeviceResponse bytes.
    public func buildForDCAPI(
        nonce: String,
        origin: String,
        encryptionPublicJwkThumbprint: String?,
        disclosedClaims: [String]?,
        signer: @Sendable @escaping (Data) async throws -> Data
    ) async throws -> Data {
        let disclosedDocument = try parseAndFilter(disclosedClaims)
        let sessionTranscript = buildDCAPISessionTranscript(
            origin: origin,
            nonce: nonce,
            encryptionPublicJwkThumbprint: encryptionPublicJwkThumbprint
        )
        let deviceAuthBytes = buildDeviceAuthentication(docType: disclosedDocument.docType, sessionTranscript: sessionTranscript)
        let coseSign1 = try await MdocCose.sign1Detached(algorithm: algorithm, externalAad: deviceAuthBytes) { bytes in
            try await Array(signer(Data(bytes)))
        }
        return Data(assembleFinalResponse(document: disclosedDocument, coseSign1: coseSign1))
    }

    private func parseAndFilter(_ disclosedClaims: [String]?) throws -> DocumentMdoc {
        let document = try MdocCbor.parseStoredCredential(credentialBytes)
        guard let disclosedClaims else { return document }
        let filteredNameSpaces = filterNamespaces(document.issuerSigned.nameSpaces, disclosedClaims: disclosedClaims)
        return DocumentMdoc(
            docType: document.docType,
            issuerSigned: IssuerSignedMdoc(nameSpaces: filteredNameSpaces, issuerAuth: document.issuerSigned.issuerAuth)
        )
    }

    /// Filter each namespace's items down to those whose `elementIdentifier`
    /// is in `disclosedClaims`, preserving each kept item's ORIGINAL
    /// tag-24-wrapped `CBOR` (never re-encoded from the parsed model - the
    /// issuer's MSO digests were computed over those exact bytes). Namespaces
    /// with no disclosed elements are dropped entirely.
    private func filterNamespaces(
        _ nameSpaces: [String: [NamespaceItem]],
        disclosedClaims: [String]
    ) -> [String: [NamespaceItem]] {
        let disclosed = Set(disclosedClaims)
        var result: [String: [NamespaceItem]] = [:]
        for (namespace, items) in nameSpaces {
            let kept = items.filter { disclosed.contains($0.item.elementIdentifier) }
            if !kept.isEmpty { result[namespace] = kept }
        }
        return result
    }

    /// Build the OpenID4VPHandover session transcript per OID4VP mdoc profile.
    ///
    /// SessionTranscript = [
    ///   null,  // reserved
    ///   null,  // reserved
    ///   [
    ///     "OpenID4VPHandover",
    ///     SHA-256([clientId, nonce, verifierJwkThumbprint, responseUri])
    ///   ]
    /// ]
    private func buildSessionTranscript(
        clientId: String,
        nonce: String,
        responseUri: String,
        verifierJwkThumbprint: String?
    ) -> [UInt8] {
        let handoverInfo: CBOR = .array([
            .utf8String(clientId),
            .utf8String(nonce),
            verifierJwkThumbprint.map { CBOR.utf8String($0) } ?? .null,
            .utf8String(responseUri),
        ])
        let handoverHash = sha256(handoverInfo.encode())

        let handover: CBOR = .array([
            .utf8String("OpenID4VPHandover"),
            .byteString(handoverHash),
        ])

        return CBOR.array([.null, .null, handover]).encode()
    }

    /// Build the OpenID4VPDCAPIHandover session transcript per OID4VP 1.0
    /// Appendix B.2.6 (Digital Credentials API).
    ///
    /// SessionTranscript = [
    ///   null,  // reserved
    ///   null,  // reserved
    ///   [
    ///     "OpenID4VPDCAPIHandover",
    ///     SHA-256([origin, nonce, encryptionPublicJwkThumbprint])
    ///   ]
    /// ]
    ///
    /// Unlike `buildSessionTranscript` (the redirect flow's OpenID4VPHandover),
    /// there is no clientId or responseUri here - the handover binds to the
    /// browser-verified origin instead, since the response never travels over
    /// HTTP to a responseUri.
    private func buildDCAPISessionTranscript(
        origin: String,
        nonce: String,
        encryptionPublicJwkThumbprint: String?
    ) -> [UInt8] {
        let handoverInfo: CBOR = .array([
            .utf8String(origin),
            .utf8String(nonce),
            encryptionPublicJwkThumbprint.map { CBOR.utf8String($0) } ?? .null,
        ])
        let handoverHash = sha256(handoverInfo.encode())

        let handover: CBOR = .array([
            .utf8String("OpenID4VPDCAPIHandover"),
            .byteString(handoverHash),
        ])

        return CBOR.array([.null, .null, handover]).encode()
    }

    /// DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, DocType]
    private func buildDeviceAuthentication(docType: String, sessionTranscript: [UInt8]) -> [UInt8] {
        // sessionTranscript is already CBOR-encoded; decode it back to embed
        // as a nested CBOR item rather than a byte string.
        let decodedTranscript: CBOR = (try? CBOR.decode(sessionTranscript)).flatMap { $0 } ?? .null
        let deviceAuth: CBOR = .array([
            .utf8String("DeviceAuthentication"),
            decodedTranscript,
            .utf8String(docType),
        ])
        return deviceAuth.encode()
    }

    /// Assemble the final DeviceResponse CBOR structure.
    ///
    /// DeviceResponse = { "version": "1.0", "documents": [Document], "status": 0 }
    /// Document = { "docType", "issuerSigned" (filtered), "deviceSigned" }
    private func assembleFinalResponse(document: DocumentMdoc, coseSign1: CBOR) -> [UInt8] {
        guard case .map(var documentMap) = MdocCbor.encodeDocument(document) else {
            preconditionFailure("MdocCbor.encodeDocument always returns a map")
        }

        let deviceSignatureMap: CBOR = .map([.utf8String("deviceSignature"): coseSign1])
        let emptyMapTag24: CBOR = .tagged(.encodedCBORDataItem, .byteString(CBOR.map([:]).encode()))
        let deviceSignedMap: CBOR = .map([
            .utf8String("nameSpaces"): emptyMapTag24,
            .utf8String("deviceAuth"): deviceSignatureMap,
        ])
        documentMap[.utf8String("deviceSigned")] = deviceSignedMap

        let response: CBOR = .map([
            .utf8String("version"): .utf8String("1.0"),
            .utf8String("documents"): .array([.map(documentMap)]),
            .utf8String("status"): .unsignedInt(0),
        ])
        return response.encode()
    }

    private func sha256(_ data: [UInt8]) -> [UInt8] {
        #if canImport(CryptoKit)
        return Array(SHA256.hash(data: data))
        #else
        fatalError("CryptoKit required for mDoc DeviceResponse. Not available on this platform.")
        #endif
    }
}

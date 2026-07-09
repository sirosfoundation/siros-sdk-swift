// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

/// Builds an ISO 18013-5 DeviceResponse for mDoc credential presentation
/// via OID4VP (OpenID for Verifiable Presentations).
///
/// Constructs a CBOR-encoded DeviceResponse containing:
/// - version: "1.0"
/// - documents: array of Document objects with IssuerSigned + DeviceSigned
/// - DeviceAuth with COSE_Sign1 over the OpenID4VPHandover session transcript
public final class MdocDeviceResponseBuilder: @unchecked Sendable {

    /// Raw credential bytes (IssuerSigned CBOR).
    private let issuerSignedBytes: Data

    /// Signing algorithm (ES256, ES384, EdDSA).
    private let algorithm: String

    public init(issuerSignedBytes: Data, algorithm: String = "ES256") {
        self.issuerSignedBytes = issuerSignedBytes
        self.algorithm = algorithm
    }

    /// Build the CBOR-encoded DeviceResponse.
    ///
    /// - Parameters:
    ///   - nonce: Verifier nonce from the sign request.
    ///   - audience: Verifier client ID.
    ///   - responseUri: Response endpoint URI.
    ///   - verifierJwkThumbprint: Optional JWK thumbprint of the verifier key.
    ///   - disclosedClaims: Claim names to disclose (nil = all).
    ///   - signer: Function that signs raw bytes. Returns raw signature bytes.
    /// - Returns: CBOR-encoded DeviceResponse bytes.
    public func build(
        nonce: String,
        audience: String,
        responseUri: String,
        verifierJwkThumbprint: String?,
        disclosedClaims: [String]?,
        signer: (Data) async throws -> Data
    ) async throws -> Data {
        // Step 1: Build the OpenID4VPHandover session transcript
        let sessionTranscript = buildSessionTranscript(
            clientId: audience,
            nonce: nonce,
            responseUri: responseUri,
            verifierJwkThumbprint: verifierJwkThumbprint
        )

        // Step 2: Extract docType
        let docType = extractDocType(from: issuerSignedBytes) ?? "org.iso.18013.5.1.mDL"

        // Step 3: Build DeviceAuthentication
        let deviceAuth = buildDeviceAuthentication(docType: docType, sessionTranscript: sessionTranscript)

        // Step 4: Sign with COSE_Sign1
        let coseSign1 = try await buildCoseSign1(deviceAuthBytes: deviceAuth, signer: signer)

        // Step 5: Assemble DeviceResponse
        return assembleFinalResponse(
            docType: docType,
            issuerSigned: issuerSignedBytes,
            coseSign1: coseSign1,
            disclosedClaims: disclosedClaims
        )
    }

    // MARK: - Session Transcript

    /// Build the OpenID4VPHandover session transcript per OID4VP §7.3.1.
    private func buildSessionTranscript(
        clientId: String,
        nonce: String,
        responseUri: String,
        verifierJwkThumbprint: String?
    ) -> Data {
        let handoverInfoItems: [Data]
        if let thumbprint = verifierJwkThumbprint {
            handoverInfoItems = [
                encodeCborTextString(clientId),
                encodeCborTextString(nonce),
                encodeCborTextString(thumbprint),
                encodeCborTextString(responseUri),
            ]
        } else {
            handoverInfoItems = [
                encodeCborTextString(clientId),
                encodeCborTextString(nonce),
                encodeCborNull(),
                encodeCborTextString(responseUri),
            ]
        }
        let handoverInfoBytes = encodeCborArray(handoverInfoItems)
        let handoverHash = sha256(handoverInfoBytes)

        let handoverArray = encodeCborArray([
            encodeCborTextString("OpenID4VPHandover"),
            encodeCborByteString(handoverHash),
        ])

        return encodeCborArray([
            encodeCborNull(),
            encodeCborNull(),
            handoverArray,
        ])
    }

    // MARK: - DeviceAuthentication

    private func buildDeviceAuthentication(docType: String, sessionTranscript: Data) -> Data {
        encodeCborArray([
            encodeCborTextString("DeviceAuthentication"),
            sessionTranscript,
            encodeCborTextString(docType),
        ])
    }

    // MARK: - COSE_Sign1

    private func buildCoseSign1(deviceAuthBytes: Data, signer: (Data) async throws -> Data) async throws -> Data {
        let algValue: Int
        switch algorithm.uppercased() {
        case "ES256": algValue = -7
        case "ES384": algValue = -35
        case "EDDSA", "ED25519": algValue = -8
        default: algValue = -7
        }

        let protectedHeader = encodeCborIntMap([1: algValue])

        let sigStructure = encodeCborArray([
            encodeCborTextString("Signature1"),
            encodeCborByteString(protectedHeader),
            encodeCborByteString(deviceAuthBytes),
            encodeCborByteString(Data()),
        ])

        let signature = try await signer(sigStructure)

        return encodeCborArray([
            encodeCborByteString(protectedHeader),
            encodeCborEmptyMap(),
            encodeCborNull(),
            encodeCborByteString(signature),
        ])
    }

    // MARK: - Final Assembly

    private func assembleFinalResponse(
        docType: String,
        issuerSigned: Data,
        coseSign1: Data,
        disclosedClaims: [String]?
    ) -> Data {
        let deviceSignatureMap = encodeCborStringMap([
            "deviceSignature": coseSign1,
        ])
        let deviceSignedMap = encodeCborStringMap([
            "nameSpaces": encodeCborTag(24, encodeCborEmptyMap()),
            "deviceAuth": deviceSignatureMap,
        ])
        let document = encodeCborStringMap([
            "docType": encodeCborTextString(docType),
            "issuerSigned": issuerSigned,
            "deviceSigned": deviceSignedMap,
        ])
        return encodeCborStringMap([
            "version": encodeCborTextString("1.0"),
            "documents": encodeCborArray([document]),
            "status": encodeCborUnsignedInt(0),
        ])
    }

    // MARK: - CBOR Encoding Primitives

    private func encodeCborTextString(_ s: String) -> Data {
        let bytes = Data(s.utf8)
        return encodeCborMajor(3, bytes.count) + bytes
    }

    private func encodeCborByteString(_ b: Data) -> Data {
        encodeCborMajor(2, b.count) + b
    }

    private func encodeCborUnsignedInt(_ v: Int) -> Data {
        encodeCborMajor(0, v)
    }

    private func encodeCborNull() -> Data { Data([0xF6]) }

    private func encodeCborEmptyMap() -> Data { Data([0xA0]) }

    private func encodeCborArray(_ items: [Data]) -> Data {
        var out = encodeCborMajor(4, items.count)
        items.forEach { out.append($0) }
        return out
    }

    private func encodeCborIntMap(_ entries: [Int: Int]) -> Data {
        var out = encodeCborMajor(5, entries.count)
        for (k, v) in entries {
            if k >= 0 { out.append(encodeCborMajor(0, k)) }
            else { out.append(encodeCborMajor(1, -1 - k)) }
            if v >= 0 { out.append(encodeCborMajor(0, v)) }
            else { out.append(encodeCborMajor(1, -1 - v)) }
        }
        return out
    }

    private func encodeCborStringMap(_ entries: [(key: String, value: Data)]) -> Data {
        var out = encodeCborMajor(5, entries.count)
        for (k, v) in entries {
            out.append(encodeCborTextString(k))
            out.append(v)
        }
        return out
    }

    /// Helper for ordered string map using array of tuples.
    private func encodeCborStringMap(_ entries: [String: Data]) -> Data {
        let sorted = entries.sorted { $0.key < $1.key }
        return encodeCborStringMap(sorted.map { (key: $0.key, value: $0.value) })
    }

    private func encodeCborTag(_ tag: Int, _ content: Data) -> Data {
        encodeCborMajor(6, tag) + content
    }

    private func encodeCborMajor(_ majorType: Int, _ argument: Int) -> Data {
        let major = majorType << 5
        if argument < 24 {
            return Data([UInt8(major | argument)])
        } else if argument < 256 {
            return Data([UInt8(major | 24), UInt8(argument)])
        } else if argument < 65536 {
            return Data([UInt8(major | 25), UInt8(argument >> 8), UInt8(argument & 0xFF)])
        } else {
            return Data([
                UInt8(major | 26),
                UInt8((argument >> 24) & 0xFF),
                UInt8((argument >> 16) & 0xFF),
                UInt8((argument >> 8) & 0xFF),
                UInt8(argument & 0xFF),
            ])
        }
    }

    // MARK: - Helpers

    private func sha256(_ data: Data) -> Data {
        #if canImport(CryptoKit)
        Data(SHA256.hash(data: data))
        #else
        fatalError("CryptoKit required for mDoc DeviceResponse. Not available on this platform.")
        #endif
    }

    private func extractDocType(from issuerSigned: Data) -> String? {
        let knownDoctypes = [
            "org.iso.18013.5.1.mDL",
            "eu.europa.ec.eudi.pid.1",
            "org.iso.23220.1",
        ]
        let text = String(data: issuerSigned, encoding: .utf8) ?? ""
        return knownDoctypes.first { text.contains($0) }
    }
}

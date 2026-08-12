// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore
@testable import SirosCredentials

#if canImport(CryptoKit)
import CryptoKit
@preconcurrency import SwiftCBOR

/// Tests for `MdocDeviceResponseBuilder` against a hand-built, synthetic
/// DeviceResponse-shaped credential envelope - mirroring the exact stored
/// shape confirmed via `sirosfoundation/wallet-frontend#191`
/// (`{documents: [{docType, issuerSigned: {nameSpaces, issuerAuth}}], ...}`,
/// with each namespace item tag-24-wrapped), and the Kotlin SDK's
/// `MdocDeviceResponseBuilderTest.kt` (same fixture, same assertions) - since
/// no real signed-mdoc test vectors with matching digests are available
/// locally.
final class MdocDeviceResponseBuilderTest: XCTestCase {

    private let docType = "org.iso.18013.5.1.mDL"
    private let namespace = "org.iso.18013.5.1"

    /// Build a tag-24-wrapped IssuerSignedItem: {digestID, random, elementIdentifier, elementValue}.
    private func buildItem(digestId: UInt64, elementIdentifier: String, elementValue: String) -> CBOR {
        let item: CBOR = .map([
            .utf8String("digestID"): .unsignedInt(digestId),
            .utf8String("random"): .byteString([UInt8](repeating: 0, count: 16)),
            .utf8String("elementIdentifier"): .utf8String(elementIdentifier),
            .utf8String("elementValue"): .utf8String(elementValue),
        ])
        return .tagged(.encodedCBORDataItem, .byteString(item.encode()))
    }

    /// Build a synthetic stored-credential envelope: DeviceResponseMdoc{documents:[{docType, issuerSigned}]}.
    private func buildStoredCredential() -> [UInt8] {
        let familyNameItem = buildItem(digestId: 0, elementIdentifier: "family_name", elementValue: "Doe")
        let givenNameItem = buildItem(digestId: 1, elementIdentifier: "given_name", elementValue: "Jane")
        let issueDateItem = buildItem(digestId: 2, elementIdentifier: "issue_date", elementValue: "2020-01-01")
        let mdlNamespace: CBOR = .array([familyNameItem, givenNameItem, issueDateItem])

        let otherNamespaceItem = buildItem(digestId: 0, elementIdentifier: "some_other_claim", elementValue: "value")
        let otherNamespace: CBOR = .array([otherNamespaceItem])

        let nameSpaces: CBOR = .map([
            .utf8String(namespace): mdlNamespace,
            .utf8String("com.example.other"): otherNamespace,
        ])

        // issuerAuth is opaque to the wallet - a placeholder 4-element array is enough.
        let issuerAuth: CBOR = .array([.byteString([]), .map([:]), .byteString([]), .byteString([])])

        let issuerSigned: CBOR = .map([
            .utf8String("nameSpaces"): nameSpaces,
            .utf8String("issuerAuth"): issuerAuth,
        ])
        let document: CBOR = .map([
            .utf8String("docType"): .utf8String(docType),
            .utf8String("issuerSigned"): issuerSigned,
        ])
        let envelope: CBOR = .map([
            .utf8String("documents"): .array([document]),
            .utf8String("status"): .unsignedInt(0),
        ])
        return envelope.encode()
    }

    func testParseStoredCredential_unwrapsEnvelopeAndDecodesItems() throws {
        let bytes = buildStoredCredential()
        let document = try MdocCbor.parseStoredCredential(bytes)

        XCTAssertEqual(docType, document.docType)
        XCTAssertEqual(2, document.issuerSigned.nameSpaces.count)

        let mdlItems = try XCTUnwrap(document.issuerSigned.nameSpaces[namespace])
        XCTAssertEqual(3, mdlItems.count)
        let familyName = try XCTUnwrap(mdlItems.first { $0.item.elementIdentifier == "family_name" })
        guard case .utf8String(let value) = familyName.item.elementValue else {
            return XCTFail("expected a utf8String elementValue")
        }
        XCTAssertEqual("Doe", value)
        XCTAssertEqual(0, familyName.item.digestId)
        XCTAssertEqual(16, familyName.item.random.count)
    }

    func testBuild_selectiveDisclosure_filtersToDisclosedElementsOnly() async throws {
        let credentialBytes = buildStoredCredential()
        let builder = MdocDeviceResponseBuilder(credentialBytes: credentialBytes, algorithm: "ES256")

        let response = try await builder.build(
            nonce: "test-nonce",
            audience: "https://verifier.example.com",
            responseUri: "https://verifier.example.com/response",
            verifierJwkThumbprint: "thumbprint-abc",
            disclosedClaims: ["family_name", "given_name"]
        ) { _ in Data((0..<64).map { UInt8($0) }) }

        guard let decoded = try CBOR.decode([UInt8](response)) else {
            return XCTFail("expected decodable CBOR")
        }
        XCTAssertEqual(decoded["version"], .utf8String("1.0"))
        guard case .array(let documents)? = decoded["documents"], documents.count == 1 else {
            return XCTFail("expected a single document")
        }
        let doc = documents[0]
        XCTAssertEqual(doc["docType"], .utf8String(docType))

        guard case .map(let nameSpaces)? = doc["issuerSigned"]?["nameSpaces"] else {
            return XCTFail("expected issuerSigned.nameSpaces map")
        }
        // com.example.other's only element wasn't disclosed - namespace must be dropped entirely.
        XCTAssertNil(nameSpaces[.utf8String("com.example.other")])

        guard case .array(let mdlItems)? = nameSpaces[.utf8String(namespace)] else {
            return XCTFail("expected the disclosed namespace to be present")
        }
        XCTAssertEqual(2, mdlItems.count)
        let disclosedIds = Set(try mdlItems.map { tagged -> String in
            guard case .tagged(_, let content) = tagged, case .byteString(let bytes) = content,
                  let inner = try CBOR.decode(bytes), case .utf8String(let id)? = inner["elementIdentifier"] else {
                throw MdocError.malformed("unexpected disclosed item shape")
            }
            return id
        })
        XCTAssertEqual(Set(["family_name", "given_name"]), disclosedIds)
        XCTAssertFalse(disclosedIds.contains("issue_date"), "issue_date must not be disclosed")

        // issuerAuth must be passed through completely untouched.
        guard case .array(let issuerAuth)? = doc["issuerSigned"]?["issuerAuth"] else {
            return XCTFail("expected issuerAuth array")
        }
        XCTAssertEqual(4, issuerAuth.count)
    }

    func testBuild_nullDisclosedClaims_keepsAllNamespacesAndElements() async throws {
        let credentialBytes = buildStoredCredential()
        let builder = MdocDeviceResponseBuilder(credentialBytes: credentialBytes, algorithm: "ES256")

        let response = try await builder.build(
            nonce: "n",
            audience: "aud",
            responseUri: "https://verifier.example.com/response",
            verifierJwkThumbprint: nil,
            disclosedClaims: nil
        ) { _ in Data(repeating: 0, count: 64) }

        guard let decoded = try CBOR.decode([UInt8](response)),
              case .map(let nameSpaces)? = decoded["documents"]?[0]?["issuerSigned"]?["nameSpaces"] else {
            return XCTFail("expected issuerSigned.nameSpaces map")
        }
        XCTAssertEqual(2, nameSpaces.count)
        guard case .array(let mdlItems)? = nameSpaces[.utf8String(namespace)] else {
            return XCTFail("expected the mdl namespace to be present")
        }
        XCTAssertEqual(3, mdlItems.count)
    }

    func testBuild_preservesOriginalTaggedBytesForDisclosedItems() async throws {
        let credentialBytes = buildStoredCredential()
        let originalDocument = try MdocCbor.parseStoredCredential(credentialBytes)
        let originalFamilyNameBytes = try XCTUnwrap(
            originalDocument.issuerSigned.nameSpaces[namespace]?.first { $0.item.elementIdentifier == "family_name" }
        ).original.encode()

        let builder = MdocDeviceResponseBuilder(credentialBytes: credentialBytes, algorithm: "ES256")
        let response = try await builder.build(
            nonce: "n",
            audience: "aud",
            responseUri: "https://verifier.example.com/response",
            verifierJwkThumbprint: nil,
            disclosedClaims: ["family_name"]
        ) { _ in Data(repeating: 0, count: 64) }

        guard let decoded = try CBOR.decode([UInt8](response)),
              case .array(let mdlItems)? = decoded["documents"]?[0]?["issuerSigned"]?["nameSpaces"]?[.utf8String(namespace)] else {
            return XCTFail("expected the disclosed namespace to be present")
        }
        XCTAssertEqual(1, mdlItems.count)
        // Byte-for-byte identical to the original tag-24-wrapped item - never re-encoded.
        XCTAssertEqual(originalFamilyNameBytes, mdlItems[0].encode())
    }

    func testBuildForDCAPI_selectiveDisclosure_filtersToDisclosedElementsOnly() async throws {
        let credentialBytes = buildStoredCredential()
        let builder = MdocDeviceResponseBuilder(credentialBytes: credentialBytes, algorithm: "ES256")

        let response = try await builder.buildForDCAPI(
            nonce: "dc-api-nonce",
            origin: "https://relying-party.example",
            encryptionPublicJwkThumbprint: "enc-thumbprint",
            disclosedClaims: ["family_name", "given_name"]
        ) { _ in Data((0..<64).map { UInt8($0) }) }

        guard let decoded = try CBOR.decode([UInt8](response)),
              case .map(let nameSpaces)? = decoded["documents"]?[0]?["issuerSigned"]?["nameSpaces"] else {
            return XCTFail("expected issuerSigned.nameSpaces map")
        }
        XCTAssertNil(nameSpaces[.utf8String("com.example.other")])
        guard case .array(let mdlItems)? = nameSpaces[.utf8String(namespace)] else {
            return XCTFail("expected the disclosed namespace to be present")
        }
        XCTAssertEqual(2, mdlItems.count)
    }

    /// Recompute the expected handover hash independently from the raw
    /// origin/nonce/thumbprint inputs, then confirm the DeviceAuthentication
    /// Sig_structure fed to the signer embeds that exact SessionTranscript -
    /// proves the transcript is built from {origin, nonce, thumbprint} via
    /// the "OpenID4VPDCAPIHandover" name, not the redirect flow's
    /// "OpenID4VPHandover"/clientId/responseUri shape. Also confirms the
    /// signer receives the COSE Sig_structure (["Signature1", protected,
    /// external_aad, payload]) with the real DeviceAuthentication bytes in
    /// `payload` (index 3, itself tag-24-wrapped) and empty `external_aad`
    /// (index 2) - the inverse of the bug fixed in `MdocCose.sign1Detached`.
    func testBuildForDCAPI_sessionTranscriptUsesOpenID4VPDCAPIHandoverAndOrigin() async throws {
        let credentialBytes = buildStoredCredential()
        let builder = MdocDeviceResponseBuilder(credentialBytes: credentialBytes, algorithm: "ES256")

        let origin = "https://relying-party.example"
        let nonce = "dc-api-nonce"
        let thumbprint = "enc-thumbprint"

        let handoverInfo: CBOR = .array([
            .utf8String(origin), .utf8String(nonce),
            .byteString([UInt8](EncryptedContainer.base64UrlDecode(thumbprint))),
        ])
        let expectedHash = Array(SHA256.hash(data: handoverInfo.encode()))

        var signingInput: [UInt8]?
        _ = try await builder.buildForDCAPI(
            nonce: nonce,
            origin: origin,
            encryptionPublicJwkThumbprint: thumbprint,
            disclosedClaims: nil
        ) { data in signingInput = [UInt8](data); return Data(repeating: 0, count: 64) }

        guard let sigStructure = try CBOR.decode(try XCTUnwrap(signingInput)), case .array(let sigArray) = sigStructure else {
            return XCTFail("expected the Sig_structure array")
        }
        guard case .byteString(let externalAad) = sigArray[2] else {
            return XCTFail("expected external_aad to be a byte string")
        }
        XCTAssertEqual(0, externalAad.count)

        guard case .byteString(let payloadBytes) = sigArray[3],
              let outerTag = try CBOR.decode(payloadBytes),
              case .tagged(_, let content) = outerTag, case .byteString(let deviceAuthBytes) = content,
              let deviceAuth = try CBOR.decode(deviceAuthBytes), case .array(let deviceAuthArray) = deviceAuth else {
            return XCTFail("expected payload to be a tag-24-wrapped DeviceAuthentication array")
        }
        XCTAssertEqual(4, deviceAuthArray.count)
        XCTAssertEqual(deviceAuthArray[0], .utf8String("DeviceAuthentication"))

        guard case .array(let sessionTranscript) = deviceAuthArray[1] else {
            return XCTFail("expected SessionTranscript array")
        }
        XCTAssertEqual(sessionTranscript[0], .null)
        XCTAssertEqual(sessionTranscript[1], .null)
        guard case .array(let handover) = sessionTranscript[2] else {
            return XCTFail("expected handover array")
        }
        XCTAssertEqual(handover[0], .utf8String("OpenID4VPDCAPIHandover"))
        guard case .byteString(let handoverHash) = handover[1] else {
            return XCTFail("expected handover hash byte string")
        }
        XCTAssertEqual(expectedHash, handoverHash)
    }

    func testBuildForDCAPI_nullEncryptionThumbprint_encodesAsCborNull() async throws {
        let credentialBytes = buildStoredCredential()
        let builder = MdocDeviceResponseBuilder(credentialBytes: credentialBytes, algorithm: "ES256")

        var signingInput: [UInt8]?
        // Unencrypted dc_api response mode has no verifier encryption key -
        // must not crash, and must encode the thumbprint slot as CBOR null.
        _ = try await builder.buildForDCAPI(
            nonce: "n",
            origin: "https://relying-party.example",
            encryptionPublicJwkThumbprint: nil,
            disclosedClaims: nil
        ) { data in signingInput = [UInt8](data); return Data(repeating: 0, count: 64) }

        guard let sigStructure = try CBOR.decode(try XCTUnwrap(signingInput)), case .array(let sigArray) = sigStructure,
              case .byteString(let payloadBytes) = sigArray[3],
              let outerTag = try CBOR.decode(payloadBytes), case .tagged(_, let content) = outerTag,
              case .byteString(let deviceAuthBytes) = content, let deviceAuth = try CBOR.decode(deviceAuthBytes),
              case .array(let deviceAuthArray) = deviceAuth, case .array(let sessionTranscript) = deviceAuthArray[1],
              case .array(let handover) = sessionTranscript[2] else {
            return XCTFail("expected a decodable DeviceAuthentication with a handover array")
        }
        XCTAssertEqual(handover[0], .utf8String("OpenID4VPDCAPIHandover"))
    }
}

#endif

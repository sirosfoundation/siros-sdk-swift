// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials
@preconcurrency import SwiftCBOR

/// Tests for `MdocCbor.parseStoredCredential` against both stored-credential
/// shapes seen in practice:
/// - `sirosfoundation/vc`'s own DeviceResponse-shaped envelope (`{documents:
///   [{docType, issuerSigned}], ...}`), confirmed via wallet-frontend#191.
/// - A bare `IssuerSigned` structure (`{nameSpaces, issuerAuth}`) with no
///   enclosing envelope, confirmed against geneva2026.mdoc.online's OID4VCI
///   conformance suite - docType has to come from the MSO embedded in
///   issuerAuth instead of a `docType` field (IssuerSigned has none).
final class MdocCborTests: XCTestCase {

    private func buildItem(digestId: UInt64, elementIdentifier: String, elementValue: String) -> CBOR {
        let item: CBOR = .map([
            .utf8String("digestID"): .unsignedInt(digestId),
            .utf8String("random"): .byteString([UInt8](repeating: 0, count: 16)),
            .utf8String("elementIdentifier"): .utf8String(elementIdentifier),
            .utf8String("elementValue"): .utf8String(elementValue),
        ])
        return .tagged(.encodedCBORDataItem, .byteString(item.encode()))
    }

    private func buildNameSpaces(namespace: String) -> CBOR {
        let items: CBOR = .array([
            buildItem(digestId: 0, elementIdentifier: "family_name", elementValue: "Doe"),
            buildItem(digestId: 1, elementIdentifier: "given_name", elementValue: "Jane"),
        ])
        return .map([.utf8String(namespace): items])
    }

    /// Build a COSE_Sign1 array whose payload carries an MSO with `docType`,
    /// matching the REAL wire encoding (ISO 18013-5 §9.1.2.4): the payload
    /// slot is a `byteString` whose content decodes to a tag-24-wrapped
    /// byteString, which itself decodes to the actual MSO map - two nested
    /// decode steps, not one. (An earlier version of this fixture built the
    /// payload as an in-memory tagged CBOR value directly instead of a real
    /// double-encoded byte string, which matched a bug in the
    /// implementation instead of catching it - confirmed broken against a
    /// real geneva2026.mdoc.online credential.)
    private func buildIssuerAuth(docType: String) -> CBOR {
        let mso: CBOR = .map([.utf8String("docType"): .utf8String(docType)])
        let taggedMso: CBOR = .tagged(.encodedCBORDataItem, .byteString(mso.encode()))
        let payload: CBOR = .byteString(taggedMso.encode())
        return .array([
            .byteString([]), // protected headers (opaque to the wallet)
            .map([:]), // unprotected headers
            payload,
            .byteString([UInt8](repeating: 0, count: 64)), // signature (opaque to the wallet)
        ])
    }

    func testParseStoredCredential_unwrapsDeviceResponseEnvelope() throws {
        let docType = "org.iso.18013.5.1.mDL"
        let namespace = "org.iso.18013.5.1"

        let issuerSigned: CBOR = .map([
            .utf8String("nameSpaces"): buildNameSpaces(namespace: namespace),
            .utf8String("issuerAuth"): buildIssuerAuth(docType: docType),
        ])
        let document: CBOR = .map([
            .utf8String("docType"): .utf8String(docType),
            .utf8String("issuerSigned"): issuerSigned,
        ])
        let envelope: CBOR = .map([
            .utf8String("documents"): .array([document]),
            .utf8String("status"): .unsignedInt(0),
        ])

        let parsed = try MdocCbor.parseStoredCredential(envelope.encode())

        XCTAssertEqual(docType, parsed.docType)
        XCTAssertEqual(1, parsed.issuerSigned.nameSpaces.count)
        let familyName = try XCTUnwrap(
            parsed.issuerSigned.nameSpaces[namespace]?.first { $0.item.elementIdentifier == "family_name" }
        )
        guard case .utf8String(let value) = familyName.item.elementValue else {
            return XCTFail("expected a utf8String elementValue")
        }
        XCTAssertEqual("Doe", value)
    }

    func testParseStoredCredential_acceptsBareIssuerSignedStructure_derivingDocTypeFromMso() throws {
        // No enclosing {documents: [...]} envelope - the exact shape
        // geneva2026.mdoc.online's OID4VCI credential response returns for
        // ANY docType it issues, not just mDL (docType is read from the MSO
        // dynamically, never hardcoded), confirmed via its conformance
        // report's "Send Credential Response" section.
        let docType = "eu.europa.ec.eudi.pid.1"
        let namespace = "eu.europa.ec.eudi.pid.1"

        let bareIssuerSigned: CBOR = .map([
            .utf8String("nameSpaces"): buildNameSpaces(namespace: namespace),
            .utf8String("issuerAuth"): buildIssuerAuth(docType: docType),
        ])

        let parsed = try MdocCbor.parseStoredCredential(bareIssuerSigned.encode())

        XCTAssertEqual(docType, parsed.docType)
        XCTAssertEqual(1, parsed.issuerSigned.nameSpaces.count)
        let givenName = try XCTUnwrap(
            parsed.issuerSigned.nameSpaces[namespace]?.first { $0.item.elementIdentifier == "given_name" }
        )
        guard case .utf8String(let value) = givenName.item.elementValue else {
            return XCTFail("expected a utf8String elementValue")
        }
        XCTAssertEqual("Jane", value)
    }

    func testParseStoredCredential_bareIssuerSigned_worksForAnyDocType() throws {
        // A second, different docType - proves docType extraction isn't
        // accidentally coupled to mDL specifically.
        let docType = "org.iso.23220.photoid.1"
        let namespace = "org.iso.23220.1"

        let bareIssuerSigned: CBOR = .map([
            .utf8String("nameSpaces"): buildNameSpaces(namespace: namespace),
            .utf8String("issuerAuth"): buildIssuerAuth(docType: docType),
        ])

        let parsed = try MdocCbor.parseStoredCredential(bareIssuerSigned.encode())

        XCTAssertEqual(docType, parsed.docType)
    }

    func testParseStoredCredential_throwsWhenNeitherShapeMatches() {
        let garbage: CBOR = .map([.utf8String("something_else"): .utf8String("value")])

        XCTAssertThrowsError(try MdocCbor.parseStoredCredential(garbage.encode()))
    }
}

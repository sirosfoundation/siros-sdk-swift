// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
@preconcurrency import SwiftCBOR

/// Minimal, holder-side ISO 18013-5 mdoc data model and CBOR parsing.
///
/// Mirrors the shapes in `sirosfoundation/vc`'s `pkg/mdoc` (DeviceResponseMdoc/
/// DocumentMdoc/IssuerSignedMdoc/IssuerSignedItem) closely enough to
/// interoperate, but scoped to only what a WALLET (holder) needs: parsing a
/// stored credential's envelope for claim display and selecting a subset of
/// disclosed elements for a presentation - not MSO digest verification,
/// DeviceRequest building, or any other verifier-side concern (those live in
/// the issuer/verifier).
///
/// Lives in `SirosCredentials` (not `SirosKeystore`) since both the credential
/// display pipeline (`CredentialUtils`, this module) and the presentation
/// builder (`MdocDeviceResponseBuilder`, `SirosKeystore`, which depends on
/// this module) need it.
///
/// Confirmed via `sirosfoundation/wallet-frontend#191`: a stored mdoc
/// credential's raw bytes are a full `DeviceResponseMdoc`-shaped envelope
/// (`{documents: [{docType, issuerSigned}], ...}`), not a bare IssuerSigned
/// blob - `MdocCbor.parseStoredCredential` unwraps this down to the first document.

public enum MdocError: Error, CustomStringConvertible {
    case malformed(String)

    public var description: String {
        switch self {
        case .malformed(let reason): return reason
        }
    }
}

/// A single decoded ISO 18013-5 data element (an unwrapped `IssuerSignedItem`).
public struct IssuerSignedItem: Sendable {
    public let digestId: UInt64
    public let random: [UInt8]
    public let elementIdentifier: String
    public let elementValue: CBOR

    public init(digestId: UInt64, random: [UInt8], elementIdentifier: String, elementValue: CBOR) {
        self.digestId = digestId
        self.random = random
        self.elementIdentifier = elementIdentifier
        self.elementValue = elementValue
    }
}

/// One namespace's disclosed items: each entry pairs the decoded
/// `IssuerSignedItem` (for filtering/reading) with the ORIGINAL tag-24-wrapped
/// `CBOR` bytes it came from. Selective disclosure must preserve these
/// original bytes verbatim for any item that's kept - the MSO's digests were
/// computed over the exact tagged CBOR encoding, so re-encoding from the
/// parsed model would invalidate them. Disclosure only ever *selects a
/// subset* of already-digested items; it never re-hashes.
public struct NamespaceItem: Sendable {
    public let item: IssuerSignedItem
    public let original: CBOR

    public init(item: IssuerSignedItem, original: CBOR) {
        self.item = item
        self.original = original
    }
}

/// The IssuerSigned portion of one mdoc document: namespace -> disclosed
/// items, plus the untouched `issuerAuth` (COSE_Sign1 over the MSO). The
/// wallet never parses or modifies `issuerAuth` - it's opaque, passed through
/// as-is in any built DeviceResponse.
public struct IssuerSignedMdoc: Sendable {
    public let nameSpaces: [String: [NamespaceItem]]
    public let issuerAuth: CBOR

    public init(nameSpaces: [String: [NamespaceItem]], issuerAuth: CBOR) {
        self.nameSpaces = nameSpaces
        self.issuerAuth = issuerAuth
    }
}

public struct DocumentMdoc: Sendable {
    public let docType: String
    public let issuerSigned: IssuerSignedMdoc

    public init(docType: String, issuerSigned: IssuerSignedMdoc) {
        self.docType = docType
        self.issuerSigned = issuerSigned
    }
}

public enum MdocCbor {

    /// Parse a stored mdoc credential's raw bytes (a full DeviceResponseMdoc
    /// envelope, per wallet-frontend#191) and return its first document.
    public static func parseStoredCredential(_ bytes: [UInt8]) throws -> DocumentMdoc {
        guard let root = try CBOR.decode(bytes) else {
            throw MdocError.malformed("mdoc credential envelope: empty CBOR")
        }
        guard case .array(let documents)? = root["documents"], let first = documents.first else {
            throw MdocError.malformed("mdoc credential envelope missing documents[]")
        }
        return try parseDocument(first)
    }

    private static func parseDocument(_ doc: CBOR) throws -> DocumentMdoc {
        guard case .utf8String(let docType)? = doc["docType"] else {
            throw MdocError.malformed("mdoc document missing docType")
        }
        guard let issuerSignedObj = doc["issuerSigned"] else {
            throw MdocError.malformed("mdoc document missing issuerSigned")
        }
        guard case .map(let nameSpacesMap)? = issuerSignedObj["nameSpaces"] else {
            throw MdocError.malformed("issuerSigned missing nameSpaces")
        }

        var nameSpaces: [String: [NamespaceItem]] = [:]
        for (key, value) in nameSpacesMap {
            guard case .utf8String(let ns) = key else { continue }
            guard case .array(let itemsArray) = value else { continue }
            var items: [NamespaceItem] = []
            for tagged in itemsArray {
                items.append(NamespaceItem(item: try parseIssuerSignedItem(tagged), original: tagged))
            }
            nameSpaces[ns] = items
        }

        guard let issuerAuth = issuerSignedObj["issuerAuth"] else {
            throw MdocError.malformed("issuerSigned missing issuerAuth")
        }
        return DocumentMdoc(docType: docType, issuerSigned: IssuerSignedMdoc(nameSpaces: nameSpaces, issuerAuth: issuerAuth))
    }

    /// Unwrap a tag-24 (encoded-CBOR-data-item) bstr and decode the IssuerSignedItem map inside it.
    private static func parseIssuerSignedItem(_ tagged: CBOR) throws -> IssuerSignedItem {
        let innerBytes: [UInt8]
        switch tagged {
        case .tagged(let tag, let content) where tag == .encodedCBORDataItem:
            guard case .byteString(let b) = content else {
                throw MdocError.malformed("tag-24 content is not a byte string")
            }
            innerBytes = b
        case .byteString(let b):
            // Tolerate an already-untagged byte string, in case an issuer omits the tag.
            innerBytes = b
        default:
            throw MdocError.malformed("unexpected IssuerSignedItem encoding")
        }

        guard let item = try CBOR.decode(innerBytes) else {
            throw MdocError.malformed("empty IssuerSignedItem")
        }
        guard case .unsignedInt(let digestId)? = item["digestID"] else {
            throw MdocError.malformed("IssuerSignedItem missing digestID")
        }
        guard case .byteString(let random)? = item["random"] else {
            throw MdocError.malformed("IssuerSignedItem missing random")
        }
        guard case .utf8String(let elementIdentifier)? = item["elementIdentifier"] else {
            throw MdocError.malformed("IssuerSignedItem missing elementIdentifier")
        }
        guard let elementValue = item["elementValue"] else {
            throw MdocError.malformed("IssuerSignedItem missing elementValue")
        }
        return IssuerSignedItem(digestId: digestId, random: random, elementIdentifier: elementIdentifier, elementValue: elementValue)
    }

    /// Re-encode a document (with possibly-filtered `nameSpaces`) back into
    /// the `{docType, issuerSigned: {nameSpaces, issuerAuth}}` shape used
    /// inside a DeviceResponse's `documents[]` array. Each kept namespace
    /// item is emitted using its ORIGINAL tag-24-wrapped bytes (never
    /// re-encoded from the parsed model) so MSO digests remain valid.
    public static func encodeDocument(_ doc: DocumentMdoc) -> CBOR {
        var nameSpacesMap: [CBOR: CBOR] = [:]
        for (ns, items) in doc.issuerSigned.nameSpaces {
            nameSpacesMap[.utf8String(ns)] = .array(items.map { $0.original })
        }
        let issuerSignedObj: CBOR = .map([
            .utf8String("nameSpaces"): .map(nameSpacesMap),
            .utf8String("issuerAuth"): doc.issuerSigned.issuerAuth,
        ])
        return .map([
            .utf8String("docType"): .utf8String(doc.docType),
            .utf8String("issuerSigned"): issuerSignedObj,
        ])
    }
}

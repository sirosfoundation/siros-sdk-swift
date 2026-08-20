// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
@preconcurrency import SwiftCBOR

/// Parses an ISO 18013-5 §8.3.2.1.2.1/§8.3.2.1.2.2 `DeviceRequest`, decrypted
/// from an incoming proximity `SessionEstablishment`/`SessionData` message
/// (see `ProximitySessionCrypto`, `ProximitySessionMessages`).
/// ```
/// DeviceRequest = { "version": tstr, "docRequests": [DocRequest] }
/// DocRequest = { "itemsRequest": ItemsRequestBytes, ? "readerAuth": ReaderAuth }
/// ItemsRequestBytes = #6.24(bstr .cbor ItemsRequest)
/// ItemsRequest = { "docType": tstr, "nameSpaces": { tstr => { tstr => bool } } }
/// ```
/// `readerAuth` (mdoc reader authentication, §9.1.4) is parsed here (the
/// bare COSE_Sign1 array - `ReaderAuth = COSE_Sign1`, confirmed untagged
/// from the base spec's own worked example's diagnostic notation) but not
/// verified in this class - see `MdocCose.verify1`/`MdocCose.extractX5Chain`
/// for the signature/x5chain half and RICAL trust evaluation (go-trust's
/// `mdocrical` registry, or a local fallback) for the trust-decision half,
/// both driven from the wallet layer that has the session transcript this
/// parser doesn't. Matches the Kotlin SDK's
/// `org.siros.sdk.keystore.mdoc.DeviceRequestParser`, which this is ported
/// from.
public enum DeviceRequestParser {

    /// One requested document: its type, and the namespace/element-identifier pairs asked for.
    public struct DocRequest: Sendable {
        public let docType: String
        /// Namespace -> requested element identifiers (the reader's
        /// per-element `IntentToRetain` bit is ignored - every listed
        /// identifier is being requested regardless of its value).
        public let requestedItems: [String: [String]]
        /// The reader's `readerAuth` COSE_Sign1 (bare 4-element array), if
        /// the reader sent one - nil for readers that don't participate in
        /// reader authentication (it's optional per §9.1.4).
        public let readerAuth: CBOR?
        /// The tag-24-wrapped `itemsRequest` CBOR, re-encoded from the
        /// parsed value (SwiftCBOR's decode discards the original byte
        /// offsets, so this is a re-encoding, not a verbatim byte slice -
        /// a real Copilot-review finding against this doc comment's
        /// earlier, overclaiming wording). Matches the original bytes
        /// whenever the reader used canonical CBOR encoding, which is the
        /// only case the real ISO 18013-5 Annex D.4.1.1 worked example (and
        /// every conformant encoder) exercises - needed to reconstruct
        /// `ReaderAuthenticationBytes` via `MdocCose.buildReaderAuthenticationBytes`.
        public let itemsRequestTaggedBytes: [UInt8]

        public init(
            docType: String,
            requestedItems: [String: [String]],
            readerAuth: CBOR? = nil,
            itemsRequestTaggedBytes: [UInt8] = []
        ) {
            self.docType = docType
            self.requestedItems = requestedItems
            self.readerAuth = readerAuth
            self.itemsRequestTaggedBytes = itemsRequestTaggedBytes
        }

        /// Flattened element identifiers across all namespaces - the shape
        /// `MdocDeviceResponseBuilder`'s `disclosedClaims` expects.
        public func disclosedClaims() -> [String] {
            requestedItems.values.flatMap { $0 }
        }
    }

    public static func parse(_ deviceRequestBytes: [UInt8]) throws -> [DocRequest] {
        guard let request = try CBOR.decode(deviceRequestBytes) else {
            throw KeystoreError.cryptoError("empty DeviceRequest")
        }
        guard case .array(let docRequestsArray)? = request["docRequests"] else {
            throw KeystoreError.invalidParameter("DeviceRequest missing docRequests")
        }

        return try docRequestsArray.map { docRequest in
            guard let itemsRequestTagged = docRequest["itemsRequest"] else {
                throw KeystoreError.invalidParameter("DocRequest missing itemsRequest")
            }
            guard case .tagged(let tag, let content) = itemsRequestTagged, tag == .encodedCBORDataItem,
                  case .byteString(let itemsRequestBytes) = content else {
                throw KeystoreError.invalidParameter("itemsRequest is not a tag-24-wrapped ItemsRequest")
            }
            guard let itemsRequest = try CBOR.decode(itemsRequestBytes) else {
                throw KeystoreError.cryptoError("empty ItemsRequest")
            }

            guard case .utf8String(let docType)? = itemsRequest["docType"] else {
                throw KeystoreError.invalidParameter("ItemsRequest missing docType")
            }
            guard case .map(let nameSpacesMap)? = itemsRequest["nameSpaces"] else {
                throw KeystoreError.invalidParameter("ItemsRequest missing nameSpaces")
            }

            var requestedItems: [String: [String]] = [:]
            for (nsKey, elementsObj) in nameSpacesMap {
                guard case .utf8String(let ns) = nsKey else { continue }
                guard case .map(let elementsMap) = elementsObj else { continue }
                let elementIds: [String] = elementsMap.keys.compactMap {
                    if case .utf8String(let s) = $0 { return s }
                    return nil
                }
                requestedItems[ns] = elementIds
            }

            // readerAuth = COSE_Sign1 (bare array, confirmed untagged from
            // ISO 18013-5:2021's own worked example's diagnostic notation) -
            // optional per §9.1.4, so a reader that doesn't participate in
            // reader authentication is not an error.
            let readerAuth = docRequest["readerAuth"]

            return DocRequest(
                docType: docType,
                requestedItems: requestedItems,
                readerAuth: readerAuth,
                itemsRequestTaggedBytes: itemsRequestTagged.encode()
            )
        }
    }
}

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
/// `readerAuth` (mdoc reader authentication, §9.1.4) is intentionally not
/// parsed or verified here - matching the Kotlin SDK's
/// `org.siros.sdk.keystore.mdoc.DeviceRequestParser`, which this is ported
/// from, deferred until after the Tier 0 BLE transport itself is validated.
public enum DeviceRequestParser {

    /// One requested document: its type, and the namespace/element-identifier pairs asked for.
    public struct DocRequest: Sendable {
        public let docType: String
        /// Namespace -> requested element identifiers (the reader's
        /// per-element `IntentToRetain` bit is ignored - every listed
        /// identifier is being requested regardless of its value).
        public let requestedItems: [String: [String]]

        public init(docType: String, requestedItems: [String: [String]]) {
            self.docType = docType
            self.requestedItems = requestedItems
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
            return DocRequest(docType: docType, requestedItems: requestedItems)
        }
    }
}

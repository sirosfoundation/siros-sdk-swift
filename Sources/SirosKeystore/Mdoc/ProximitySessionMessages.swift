// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
@preconcurrency import SwiftCBOR

/// ISO 18013-5 §12.2.4 `SessionEstablishment`/`SessionData` CBOR message
/// framing, carried over the BLE transport built in `BleMessageChunker`.
/// ```
/// SessionEstablishment = { "eReaderKey": EReaderKeyBytes, "data": bstr }
/// SessionData = { ? "data": bstr, ? "status": uint }
/// ```
///
/// Ported from `org.siros.sdk.keystore.mdoc.ProximitySessionMessages` (Kotlin).
public enum ProximitySessionMessages {

    /// A parsed `SessionEstablishment` message: the reader's ephemeral public
    /// key bytes plus the encrypted mdoc request.
    public struct SessionEstablishment: Sendable {
        public let eReaderKeyBytes: [UInt8]
        public let encryptedData: [UInt8]

        public init(eReaderKeyBytes: [UInt8], encryptedData: [UInt8]) {
            self.eReaderKeyBytes = eReaderKeyBytes
            self.encryptedData = encryptedData
        }
    }

    public static func parseSessionEstablishment(_ bytes: [UInt8]) throws -> SessionEstablishment {
        guard let map = try CBOR.decode(bytes) else {
            throw KeystoreError.cryptoError("empty SessionEstablishment")
        }
        guard let eReaderKey = map["eReaderKey"] else {
            throw KeystoreError.invalidParameter("SessionEstablishment missing eReaderKey")
        }
        guard case .byteString(let data)? = map["data"] else {
            throw KeystoreError.invalidParameter("SessionEstablishment missing data")
        }
        return SessionEstablishment(eReaderKeyBytes: eReaderKey.encode(), encryptedData: data)
    }

    /// Build a `SessionData` message carrying an encrypted mdoc response, optionally with a status code.
    public static func buildSessionData(encryptedData: [UInt8]?, status: Int? = nil) -> [UInt8] {
        var map: [CBOR: CBOR] = [:]
        if let encryptedData { map["data"] = .byteString(encryptedData) }
        if let status { map["status"] = .unsignedInt(UInt64(status)) }
        return CBOR.map(map).encode()
    }

    /// ISO 18013-5 Table 15 status codes.
    public enum StatusCode {
        public static let sessionEncryptionError = 10
        public static let cborDecodingError = 11
        public static let sessionTermination = 20
    }
}

/// ISO 18013-5 §11.1.3.4 BLE message chunking: splits an application message
/// into MTU-3-sized parts, each prefixed `0x01` (more coming) or `0x00`
/// (last part), and reassembles a sequence of received parts back into the
/// original message. Shared by both BLE roles (central client / peripheral
/// server) - the framing is identical regardless of which side is the GATT
/// client or server.
///
/// Ported from `org.siros.sdk.keystore.mdoc.BleMessageChunker` (Kotlin).
public enum BleMessageChunker {

    /// Split `message` into chunks whose TOTAL wire size (1-byte prefix +
    /// payload) never exceeds `maxChunkSize` - i.e. `maxChunkSize` is the
    /// already MTU-3-adjusted (and 512-byte-attribute-capped) limit on what
    /// can actually go out over the air in one write/notify, not a
    /// payload-only figure. Each payload slice is therefore at most
    /// `maxChunkSize - 1` bytes, reserving room for the prefix byte - an
    /// earlier version of this function (in the Kotlin SDK this was ported
    /// from) took `maxChunkSize` payload bytes and then added the prefix on
    /// top, silently producing chunks one byte OVER the caller's limit
    /// (caught via a real BLE notification rejection on Android: hitting the
    /// BLE Core Specification's hard 512-byte attribute-value cap once the
    /// negotiated MTU exceeded 515). Do not reintroduce that bug.
    public static func chunk(_ message: [UInt8], maxChunkSize: Int) -> [[UInt8]] {
        precondition(maxChunkSize > 1, "maxChunkSize must allow at least 1 payload byte alongside the prefix")
        let payloadSize = maxChunkSize - 1
        if message.isEmpty { return [[0x00]] }
        var chunks: [[UInt8]] = []
        var offset = 0
        while offset < message.count {
            let end = min(offset + payloadSize, message.count)
            let isLast = end == message.count
            let prefix: UInt8 = isLast ? 0x00 : 0x01
            chunks.append([prefix] + message[offset..<end])
            offset = end
        }
        return chunks
    }

    /// Accumulates incoming chunks and reports the reassembled message once
    /// the last (`0x00`-prefixed) chunk arrives.
    public final class Reassembler: @unchecked Sendable {
        private var buffer: [UInt8] = []

        public init() {}

        /// Feed one received chunk (including its prefix byte). Returns the
        /// complete message once the last part arrives, nil otherwise.
        public func feed(_ chunk: [UInt8]) -> [UInt8]? {
            precondition(!chunk.isEmpty, "chunk must include its continuation-byte prefix")
            let isLast = chunk[0] == 0x00
            buffer.append(contentsOf: chunk.dropFirst())
            guard isLast else { return nil }
            let result = buffer
            buffer = []
            return result
        }
    }
}

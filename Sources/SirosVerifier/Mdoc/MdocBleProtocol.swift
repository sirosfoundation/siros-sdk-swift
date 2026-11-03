// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
import Crypto
#endif

/// ISO/IEC 18013-5 BLE UUIDs and framing shared by the reader's GATT roles.
enum MdocBleProtocol {
    static let maximumMessageSize = 2 * 1024 * 1024
    static let defaultMtu = 23
    static let maximumAttributeSize = 512

    static let stateStart: UInt8 = 0x01
    static let stateEnd: UInt8 = 0x02

    // Table 5: mdoc service, when the holder is the GATT server.
    static let mdocStateUuid = UUID(uuidString: "00000001-A123-48CE-896B-4C76973373E6")!
    static let mdocClient2ServerUuid = UUID(uuidString: "00000002-A123-48CE-896B-4C76973373E6")!
    static let mdocServer2ClientUuid = UUID(uuidString: "00000003-A123-48CE-896B-4C76973373E6")!

    // Table 6: mdoc reader service, when the reader is the GATT server.
    static let readerStateUuid = UUID(uuidString: "00000005-A123-48CE-896B-4C76973373E6")!
    static let readerClient2ServerUuid = UUID(uuidString: "00000006-A123-48CE-896B-4C76973373E6")!
    static let readerServer2ClientUuid = UUID(uuidString: "00000007-A123-48CE-896B-4C76973373E6")!
    static let readerIdentUuid = UUID(uuidString: "00000008-A123-48CE-896B-4C76973373E6")!

    /// Convert an ATT MTU to a total chunk-size limit, including framing.
    static func maxChunkSize(negotiatedMtu: Int) -> Int {
        guard negotiatedMtu > defaultMtu else { return defaultMtu - 3 }
        return min(negotiatedMtu - 3, maximumAttributeSize)
    }

    /// CoreBluetooth reports the maximum attribute value directly (already
    /// MTU-3-adjusted), rather than exposing an MTU-negotiation callback.
    static func maxChunkSize(attributeValueLength: Int) -> Int {
        max(min(attributeValueLength, maximumAttributeSize), defaultMtu - 3)
    }

    /// Split a whole message without putting the continuation byte outside
    /// the ATT attribute-value limit. `maxChunkSize` includes that byte.
    static func chunk(_ message: [UInt8], maxChunkSize: Int) -> [[UInt8]] {
        precondition(maxChunkSize > 1, "maxChunkSize must include framing and at least one payload byte")
        if message.isEmpty { return [[0x00]] }
        var chunks: [[UInt8]] = []
        var offset = 0
        while offset < message.count {
            let end = min(offset + maxChunkSize - 1, message.count)
            chunks.append([end == message.count ? 0x00 : 0x01] + message[offset..<end])
            offset = end
        }
        return chunks
    }

    /// §11.1.3.1: HKDF-SHA256(exact EDeviceKeyBytes, no salt, BLEIdent, 16).
    /// RFC 5869 represents absent salt as HashLen zero bytes.
    static func computeIdent(eDeviceKeyBytes: [UInt8]) -> [UInt8] {
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: Data(eDeviceKeyBytes)),
            salt: Data(repeating: 0, count: 32),
            info: Data("BLEIdent".utf8),
            outputByteCount: 16
        )
        return key.withUnsafeBytes { Array($0) }
    }
}

/// Bounded reassembly of one incoming whole-message stream. A malformed or
/// oversized chunk discards partial input before surfacing an error.
final class MdocBleReassembler: @unchecked Sendable {
    private let maximumMessageSize: Int
    private var buffer: [UInt8] = []

    init(maximumMessageSize: Int = MdocBleProtocol.maximumMessageSize) {
        self.maximumMessageSize = maximumMessageSize
    }

    func feed(_ chunk: [UInt8]) throws -> [UInt8]? {
        guard let continuation = chunk.first else {
            buffer.removeAll(keepingCapacity: false)
            throw MdocBleTransportError.malformedMessage("BLE chunk has no continuation byte")
        }
        guard continuation == 0x00 || continuation == 0x01 else {
            buffer.removeAll(keepingCapacity: false)
            throw MdocBleTransportError.malformedMessage("BLE chunk continuation byte must be 0x00 or 0x01")
        }
        let payloadSize = chunk.count - 1
        guard payloadSize <= maximumMessageSize - buffer.count else {
            buffer.removeAll(keepingCapacity: false)
            throw MdocBleTransportError.messageTooLarge
        }
        buffer.append(contentsOf: chunk.dropFirst())
        guard continuation == 0x00 else { return nil }
        defer { buffer.removeAll(keepingCapacity: false) }
        return buffer
    }
}

enum MdocBleStateEvent: Sendable, Equatable {
    case start
    case end
}

enum MdocBleState {
    static func parse(_ value: [UInt8]) throws -> MdocBleStateEvent {
        guard value.count == 1 else {
            throw MdocBleTransportError.malformedMessage("BLE State value must contain exactly one byte")
        }
        switch value[0] {
        case MdocBleProtocol.stateStart:
            return .start
        case MdocBleProtocol.stateEnd:
            return .end
        default:
            throw MdocBleTransportError.malformedMessage("Unknown BLE State value \(value[0])")
        }
    }
}

enum MdocBleNotificationCharacteristic {
    case state
    case serverToClient
}

/// Pure GATT-client startup logic, independent of CoreBluetooth callbacks.
final class MdocBleClientHandshake: @unchecked Sendable {
    private let lock = NSLock()
    private var stateNotifications = false
    private var dataNotifications = false
    private var startWritten = false

    var ready: Bool {
        lock.lock()
        defer { lock.unlock() }
        return stateNotifications && dataNotifications && startWritten
    }

    func onNotifications(_ characteristic: MdocBleNotificationCharacteristic, enabled: Bool) {
        lock.lock()
        switch characteristic {
        case .state:
            stateNotifications = enabled
        case .serverToClient:
            dataNotifications = enabled
        }
        lock.unlock()
    }

    func onStateStartWritten() {
        lock.lock()
        startWritten = true
        lock.unlock()
    }
}

/// Pure GATT-server startup logic for Server2Client CCCD and STATE_START.
final class MdocBleServerHandshake: @unchecked Sendable {
    private let lock = NSLock()
    private var dataNotifications = false
    private var startReceived = false

    var ready: Bool {
        lock.lock()
        defer { lock.unlock() }
        return dataNotifications && startReceived
    }

    var started: Bool {
        lock.lock()
        defer { lock.unlock() }
        return startReceived
    }

    func onServer2ClientNotifications(enabled: Bool) {
        lock.lock()
        dataNotifications = enabled
        lock.unlock()
    }

    @discardableResult
    func onState(_ value: [UInt8]) throws -> MdocBleStateEvent {
        let event = try MdocBleState.parse(value)
        if event == .start {
            lock.lock()
            startReceived = true
            lock.unlock()
        }
        return event
    }
}

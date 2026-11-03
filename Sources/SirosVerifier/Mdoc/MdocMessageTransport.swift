// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// A connected ISO/IEC 18013-5 reader message transport.
///
/// Implementations own radio framing, chunking, reassembly, backpressure, and
/// timeouts. Values crossing this interface are complete CBOR
/// SessionEstablishment or SessionData messages, never BLE fragments. A
/// transport belongs to exactly one elected reader session.
public protocol MdocMessageTransport: AnyObject, Sendable {
    func send(message: [UInt8]) async throws
    func receive() async throws -> [UInt8]
    func close() async
}

/// A BLE discovery, connection, protocol, timeout, disconnect, or I/O failure.
public enum MdocBleTransportError: Error, Sendable, Equatable {
    case unsupportedPlatform
    case failed(String)
    case timeout(String)
    case disconnected(String)
    case malformedMessage(String)
    case messageTooLarge
    case incomingQueueOverflow
    case noReadyTransport(String)
    case closed
}

extension MdocBleTransportError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .unsupportedPlatform:
            return "CoreBluetooth mdoc BLE transports require iOS"
        case .failed(let detail):
            return detail
        case .timeout(let detail):
            return detail
        case .disconnected(let detail):
            return detail
        case .malformedMessage(let detail):
            return detail
        case .messageTooLarge:
            return "BLE message exceeds \(MdocBleProtocol.maximumMessageSize) bytes"
        case .incomingQueueOverflow:
            return "Incoming whole-message BLE queue is full"
        case .noReadyTransport(let detail):
            return "No offered BLE role became ready: \(detail)"
        case .closed:
            return "The BLE transport is closed"
        }
    }
}

extension MdocBleTransportError: LocalizedError {
    public var errorDescription: String? { description }
}

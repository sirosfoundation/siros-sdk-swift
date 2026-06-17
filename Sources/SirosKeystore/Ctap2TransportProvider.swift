// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Protocol for providing a CTAP2 transport channel to external authenticators.
///
/// Implementations bridge platform-specific BLE or NFC communication
/// to the WSCD's CTAP2 transport requirements. The wallet application
/// provides a concrete implementation that handles device discovery,
/// pairing, and CBOR message framing over the chosen transport.
///
/// Usage with WSCD:
/// ```swift
/// class BleTransport: Ctap2TransportProvider {
///     func send(command: Data) async throws -> Data {
///         // BLE GATT write/notify cycle
///     }
///     func isAvailable() async -> Bool {
///         return CBCentralManager.authorization == .allowedAlways
///     }
/// }
/// ```
public protocol Ctap2TransportProvider: AnyObject, Sendable {
    /// Send a CTAP2 command (CBOR-encoded) and return the response.
    ///
    /// The implementation handles framing (e.g. BLE fragmentation)
    /// and waits for the authenticator response.
    ///
    /// - Parameter command: CBOR-encoded CTAP2 command bytes.
    /// - Returns: CBOR-encoded CTAP2 response bytes.
    func send(command: Data) async throws -> Data

    /// Whether the transport is currently available and connected.
    func isAvailable() async -> Bool

    /// Attempt to discover and connect to an authenticator.
    ///
    /// For BLE: starts scanning for FIDO2 service UUID.
    /// For NFC: initiates tag polling session.
    func connect() async throws

    /// Disconnect from the current authenticator.
    func disconnect() async throws
}

/// Errors specific to CTAP2 transport operations.
public enum Ctap2TransportError: Error, Sendable {
    case notAvailable
    case connectionFailed(String)
    case timeout
    case deviceDisconnected
    case invalidResponse(String)
}

extension Ctap2TransportError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .notAvailable: return "CTAP2 transport not available"
        case .connectionFailed(let msg): return "Connection failed: \(msg)"
        case .timeout: return "CTAP2 transport timeout"
        case .deviceDisconnected: return "Authenticator disconnected"
        case .invalidResponse(let msg): return "Invalid CTAP2 response: \(msg)"
        }
    }
}

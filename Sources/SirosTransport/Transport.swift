// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Transport-independent interface for WMP communication.
/// Implementations handle framing and connection lifecycle for a specific
/// transport binding (WebSocket, HTTPS+SSE, in-process, etc.).
public protocol TransportProtocol: AnyObject, Sendable {
    /// Current connection state as an async stream.
    var stateStream: AsyncStream<TransportState> { get }

    /// Current connection state (snapshot).
    var currentState: TransportState { get }

    /// Connect to the remote endpoint.
    func connect() async throws

    /// Send a raw JSON-RPC message.
    func send(_ message: Data) async throws

    /// Incoming messages as an async stream.
    func incoming() -> AsyncStream<Data>

    /// Gracefully close the connection.
    func disconnect() async
}

/// Connection state for a transport.
public enum TransportState: String, Sendable {
    case disconnected
    case connecting
    case connected
    case reconnecting
    case failed
}

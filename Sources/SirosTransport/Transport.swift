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

    /// Connect to the remote endpoint. For the HTTP+SSE binding this opens the
    /// event stream ONLY once the session id is known (the engine's SSE route
    /// requires `?session_id=`): a `connect()` before `onSessionCreated` is a
    /// no-op there, deferring to it.
    func connect() async throws

    /// The session was created (or resumed): its id. The HTTP+SSE binding
    /// names its event stream with it (`?session_id=` - the engine routes the
    /// stream, its replay and its live events by that id); the WS and
    /// in-process bindings need nothing (their carrier is bound another way).
    func onSessionCreated(sessionId: String) async

    /// Force the carrier closed WITHOUT ending the session (#306): unlike
    /// ``disconnect()`` the incoming and state streams live on, so the
    /// reconnect that immediately follows finds them alive and re-opens the
    /// carrier. For the SSE binding this kills a reader the kernel still
    /// calls established (a half-open socket: no bytes flow, no error
    /// surfaces, the heartbeat clock has not tripped yet) — a request that
    /// timed out over such a stream gets its carrier torn down and rebuilt
    /// before its retry. The default no-op fits the bindings whose carrier
    /// cannot silently die (in-process, a WebSocket with its own liveness).
    func forceClose() async

    /// Send a raw JSON-RPC message.
    func send(_ message: Data) async throws

    /// Incoming messages as an async stream.
    func incoming() -> AsyncStream<Data>

    /// Gracefully close the connection.
    func disconnect() async
}

extension TransportProtocol {
    /// The default: bindings that do not name their stream (WS, in-process).
    public func onSessionCreated(sessionId: String) async {}

    /// The default: bindings whose carrier cannot silently die need no
    /// forced close.
    public func forceClose() async {}
}

/// Connection state for a transport.
public enum TransportState: String, Sendable {
    case disconnected
    case connecting
    case connected
    case reconnecting
    case failed
}

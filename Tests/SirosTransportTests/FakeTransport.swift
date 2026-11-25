// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
@testable import SirosTransport

/// In-memory transport for unit testing. Allows sending canned responses
/// and capturing outgoing messages.
final class FakeTransport: TransportProtocol, @unchecked Sendable {
    private var _currentState: TransportState = .disconnected
    var currentState: TransportState { _currentState }

    private let stateCont: AsyncStream<TransportState>.Continuation
    let stateStream: AsyncStream<TransportState>

    private let incomingCont: AsyncStream<Data>.Continuation
    private let _incoming: AsyncStream<Data>

    private let lock = NSLock()
    private var _sent: [Data] = []
    var sentMessages: [Data] {
        lock.lock()
        defer { lock.unlock() }
        return _sent
    }

    /// An ordered lifecycle log for the reconnect-ordering tests (#306):
    /// "connect", "disconnect", "forceClose", "send:<method>" — the order
    /// the transport's carrier was torn down and rebuilt.
    private let eventLock = NSLock()
    private var _events: [String] = []
    var events: [String] {
        eventLock.lock()
        defer { eventLock.unlock() }
        return _events
    }

    private func recordEvent(_ event: String) {
        eventLock.lock()
        _events.append(event)
        eventLock.unlock()
    }

    /// The JSON-RPC method of a raw message, for the event log.
    private func method(of message: Data) -> String? {
        let text = String(decoding: message, as: UTF8.self)
        guard let at = text.range(of: "\"method\":\"") else { return nil }
        let rest = text[at.upperBound...]
        guard let end = rest.firstIndex(of: "\"") else { return nil }
        return String(rest[..<end])
    }

    init() {
        var sc: AsyncStream<TransportState>.Continuation!
        self.stateStream = AsyncStream { sc = $0 }
        self.stateCont = sc

        var ic: AsyncStream<Data>.Continuation!
        self._incoming = AsyncStream { ic = $0 }
        self.incomingCont = ic
    }

    func connect() async throws {
        recordEvent("connect")
        _currentState = .connected
        stateCont.yield(.connected)
    }

    /// Sends of this JSON-RPC method throw (a failed POST on an otherwise healthy connection).
    var failingMethod: String? {
        get { lock.lock(); defer { lock.unlock() }; return _failingMethod }
        set { lock.lock(); _failingMethod = newValue; lock.unlock() }
    }
    private var _failingMethod: String?
    struct SendFailed: Error {}

    func send(_ message: Data) async throws {
        lock.lock()
        let failing = _failingMethod
        lock.unlock()
        if let failing, String(decoding: message, as: UTF8.self).contains("\"method\":\"\(failing)\"") { throw SendFailed() }
        lock.lock()
        _sent.append(message)
        lock.unlock()
        recordEvent("send:\(method(of: message) ?? "?")")
    }

    func incoming() -> AsyncStream<Data> {
        _incoming
    }

    func disconnect() async {
        recordEvent("disconnect")
        _currentState = .disconnected
        stateCont.yield(.disconnected)
    }

    /// #306: the forced close — the reader dies, the state shows FAILED, but
    /// the streams LIVE (a disconnect would end them): the resume that
    /// immediately follows re-opens them. The event is recorded BEFORE the
    /// failure yield, so an ordering test sees forceClose → connect.
    func forceClose() async {
        recordEvent("forceClose")
        _currentState = .failed
        stateCont.yield(.failed)
    }

    /// Simulate receiving a message from the server.
    func receiveFromServer(_ data: Data) {
        incomingCont.yield(data)
    }

    func simulateDisconnect() {
        _currentState = .disconnected
        stateCont.yield(.disconnected)
    }

    func simulateFailure() {
        _currentState = .failed
        stateCont.yield(.failed)
    }
}

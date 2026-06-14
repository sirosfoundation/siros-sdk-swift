// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// WMP WebSocket transport binding.
/// Connects to a WMP endpoint using the `wmp.v1` subprotocol.
public final class WmpWebSocketTransport: TransportProtocol, @unchecked Sendable {
    private let url: URL
    private let extraHeaders: [String: String]

    private let stateContinuation: AsyncStream<TransportState>.Continuation
    public let stateStream: AsyncStream<TransportState>
    private var _currentState: TransportState = .disconnected
    public var currentState: TransportState { _currentState }

    private let incomingContinuation: AsyncStream<Data>.Continuation
    private let _incoming: AsyncStream<Data>

    private var webSocketTask: URLSessionWebSocketTask?
    private let session: URLSession

    public init(url: URL, extraHeaders: [String: String] = [:]) {
        self.url = url
        self.extraHeaders = extraHeaders
        self.session = URLSession(configuration: .default)

        var stateCont: AsyncStream<TransportState>.Continuation!
        self.stateStream = AsyncStream { stateCont = $0 }
        self.stateContinuation = stateCont

        var incomingCont: AsyncStream<Data>.Continuation!
        self._incoming = AsyncStream { incomingCont = $0 }
        self.incomingContinuation = incomingCont
    }

    public func connect() async throws {
        guard _currentState != .connected else { return }
        setState(.connecting)

        var request = URLRequest(url: url)
        request.setValue("wmp.v1", forHTTPHeaderField: "Sec-WebSocket-Protocol")
        for (key, value) in extraHeaders {
            request.setValue(value, forHTTPHeaderField: key)
        }

        let task = session.webSocketTask(with: request)
        self.webSocketTask = task
        task.resume()

        setState(.connected)
        startReceiveLoop(task)
    }

    public func send(_ message: Data) async throws {
        guard let task = webSocketTask else {
            throw TransportError.notConnected
        }
        let text = String(data: message, encoding: .utf8) ?? ""
        try await task.send(.string(text))
    }

    public func incoming() -> AsyncStream<Data> {
        _incoming
    }

    public func disconnect() async {
        webSocketTask?.cancel(with: .normalClosure, reason: "client disconnect".data(using: .utf8))
        webSocketTask = nil
        setState(.disconnected)
    }

    private func startReceiveLoop(_ task: URLSessionWebSocketTask) {
        Task { [weak self] in
            while task.state == .running {
                do {
                    let message = try await task.receive()
                    switch message {
                    case .string(let text):
                        if let data = text.data(using: .utf8) {
                            self?.incomingContinuation.yield(data)
                        }
                    case .data(let data):
                        self?.incomingContinuation.yield(data)
                    @unknown default:
                        break
                    }
                } catch {
                    self?.setState(.failed)
                    return
                }
            }
        }
    }

    private func setState(_ state: TransportState) {
        _currentState = state
        stateContinuation.yield(state)
    }
}

/// Transport errors.
public enum TransportError: Error, Sendable {
    case notConnected
}

extension TransportError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .notConnected: return "Transport is not connected"
        }
    }
}

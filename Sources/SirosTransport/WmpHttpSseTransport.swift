// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// WMP HTTP+SSE transport binding.
///
/// Uses HTTP POST for sending messages and Server-Sent Events (SSE) for
/// receiving messages. This is useful for environments where WebSocket
/// connections are blocked by firewalls or corporate proxies.
///
/// - Note: Requires Apple platforms (URLSession async bytes API).
#if canImport(Darwin)
public final class WmpHttpSseTransport: TransportProtocol, @unchecked Sendable {
    private let sendUrl: URL
    private let sseUrl: URL
    private let urlSession: URLSession
    private let extraHeaders: [String: String]

    private var _state: TransportState = .disconnected
    public var currentState: TransportState { _state }
    private let stateCont: AsyncStream<TransportState>.Continuation
    public let stateStream: AsyncStream<TransportState>

    private let incomingCont: AsyncStream<Data>.Continuation
    private let _incoming: AsyncStream<Data>

    public init(
        sendUrl: URL,
        sseUrl: URL,
        session: URLSession = .shared,
        extraHeaders: [String: String] = [:]
    ) {
        self.sendUrl = sendUrl
        self.sseUrl = sseUrl
        self.urlSession = session
        self.extraHeaders = extraHeaders

        var sc: AsyncStream<TransportState>.Continuation!
        self.stateStream = AsyncStream { sc = $0 }
        self.stateCont = sc

        var ic: AsyncStream<Data>.Continuation!
        self._incoming = AsyncStream { ic = $0 }
        self.incomingCont = ic
    }

    public func connect() async throws {
        guard _state != .connected else { return }
        setState(.connecting)

        var request = URLRequest(url: sseUrl)
        request.setValue("text/event-stream", forHTTPHeaderField: "Accept")
        for (key, value) in extraHeaders {
            request.setValue(value, forHTTPHeaderField: key)
        }

        Task { [weak self] in
            guard let self else { return }
            do {
                let (bytes, response) = try await self.urlSession.bytes(for: request)
                guard let httpResponse = response as? HTTPURLResponse,
                      (200..<300).contains(httpResponse.statusCode) else {
                    self.setState(.failed)
                    return
                }
                self.setState(.connected)

                var currentData = ""
                for try await line in bytes.lines {
                    if line.isEmpty {
                        if !currentData.isEmpty, let data = currentData.data(using: .utf8) {
                            self.incomingCont.yield(data)
                        }
                        currentData = ""
                    } else if line.hasPrefix("data: ") {
                        let payload = String(line.dropFirst(6))
                        currentData = currentData.isEmpty ? payload : currentData + "\n" + payload
                    }
                }
                self.setState(.disconnected)
            } catch {
                if self._state != .disconnected {
                    self.setState(.failed)
                }
            }
        }
    }

    public func send(_ message: Data) async throws {
        var request = URLRequest(url: sendUrl)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        for (key, value) in extraHeaders {
            request.setValue(value, forHTTPHeaderField: key)
        }
        request.httpBody = message

        let (_, response) = try await urlSession.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse,
              (200..<300).contains(httpResponse.statusCode) else {
            let code = (response as? HTTPURLResponse)?.statusCode ?? 0
            throw TransportError.sendFailed("HTTP POST failed: \(code)")
        }
    }

    public func incoming() -> AsyncStream<Data> { _incoming }

    public func disconnect() async {
        setState(.disconnected)
        incomingCont.finish()
        stateCont.finish()
    }

    private func setState(_ state: TransportState) {
        _state = state
        stateCont.yield(state)
    }
}
#endif // canImport(Darwin)

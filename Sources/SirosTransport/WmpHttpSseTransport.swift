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
    private var sseTask: Task<Void, Never>?
    // The SSE event-id state outlives a single connection: a reconnect presents the last id seen
    // (`Last-Event-ID`) and an event whose id was already delivered is dropped, so a replayed
    // completion is never handed to the wallet twice.
    private var eventParser = SseEventParser()
    private var replayFilter = SseReplayFilter()

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
        if let lastEventId = eventParser.lastEventId {
            request.setValue(lastEventId, forHTTPHeaderField: "Last-Event-ID")
        }

        sseTask = Task { [weak self] in
            guard let self else { return }
            do {
                let (bytes, response) = try await self.urlSession.bytes(for: request)
                guard let httpResponse = response as? HTTPURLResponse,
                      (200..<300).contains(httpResponse.statusCode) else {
                    self.setState(.failed)
                    return
                }
                self.setState(.connected)

                // Split the bytes ourselves: `bytes.lines` omits the blank line that ends an event.
                // A new response never continues a block the previous one left unfinished.
                self.eventParser.beginResponse()
                var splitter = SseLineSplitter()
                for try await byte in bytes {
                    guard let line = splitter.feed(byte: byte),
                          let event = self.eventParser.feed(line: line),
                          self.replayFilter.admit(event),
                          let data = event.data.data(using: .utf8) else { continue }
                    self.incomingCont.yield(data)
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
        sseTask?.cancel()
        sseTask = nil
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

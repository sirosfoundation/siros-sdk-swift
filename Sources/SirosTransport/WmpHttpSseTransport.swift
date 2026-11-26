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
    /// Freshens the `Authorization` bearer per request: the binding is stateless - every POST is its own
    /// own request and the engine validates each one - so a token baked in at connect dies with its
    /// (~120 s) expiry. A nil return falls back to no Authorization header; extraHeaders' Authorization
    /// (if any) then applies.
    private let tokenProvider: (@Sendable () async -> String?)?

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
    // One reader at a time: two overlapping connects must not feed one parser from two tasks.
    private let readerGate = SseReaderGate()
    /// The stream's liveness clock (#306 — the Kotlin binding sets OkHttp's read
    /// timeout; URLSession has none, so the Swift twin watches the clock itself):
    /// every line received — heartbeat or data — notes the time, a periodic check
    /// (~30 s) trips when four heartbeats went missing (~60 s at the engine's
    /// ~15 s cadence) and the transport is marked FAILED — the session's
    /// reconnect replays from `Last-Event-ID`. Armed by each reader, stopped
    /// with it, so a dead reader's silence never fails a stopped transport.
    private let liveness = SseLivenessWatchdog()
    /// The session this stream belongs to, from `onSessionCreated`. The engine's SSE route REQUIRES
    /// `?session_id=` (it routes the replay and the live events by it), so the stream cannot open
    /// before the create answers - `connect()` defers to `onSessionCreated` until the id arrives.
    private var sseSessionId: String?

    public init(
        sendUrl: URL,
        sseUrl: URL,
        session: URLSession = .shared,
        extraHeaders: [String: String] = [:],
        tokenProvider: (@Sendable () async -> String?)? = nil
    ) {
        self.sendUrl = sendUrl
        self.sseUrl = sseUrl
        self.urlSession = session
        self.extraHeaders = extraHeaders
        self.tokenProvider = tokenProvider

        var sc: AsyncStream<TransportState>.Continuation!
        self.stateStream = AsyncStream { sc = $0 }
        self.stateCont = sc

        var ic: AsyncStream<Data>.Continuation!
        self._incoming = AsyncStream { ic = $0 }
        self.incomingCont = ic

        // The half-open socket's undertaker (#306): the kernel still calls
        // the connection established, but no line arrived for four missed
        // heartbeats — the reader is cancelled (its read would block
        // forever), the gate frees (the reconnect that follows installs a
        // fresh reader) and the FAILED state reaches the session's
        // collector, which runs the resume.
        liveness.onIdle = { [weak self] in
            guard let self else { return }
            self.readerGate.stop {
                self.sseTask?.cancel()
                self.sseTask = nil
                self.setState(.failed)
            }
        }
    }

    public func connect() async throws {
        // Pre-create there is no session to name: the engine's SSE route answers 400 without
        // `?session_id=`, and no session exists yet anyway. `onSessionCreated` opens the stream
        // once the create answered; a resume re-connects through here with the remembered id.
        guard let sessionId = sseSessionId else { return }
        // The request is built first; the reader is claimed and installed in ONE step under the gate lock, so a
        // concurrent `disconnect()` always finds the reader it has to cancel.

        var request = URLRequest(url: sseRequestUrl(sessionId))
        request.setValue("text/event-stream", forHTTPHeaderField: "Accept")
        for (key, value) in try await requestHeaders() {
            request.setValue(value, forHTTPHeaderField: key)
        }
        let baseRequest = request   // a `let` for the closure: not changed after this point
        let started = readerGate.start { generation in
            // The resume cursor is read under the gate lock, where readers update it, so it is the one the
            // previous reader left, not a value torn between two readers.
            var finalRequest = baseRequest
            if let lastEventId = eventParser.lastEventId {
                finalRequest.setValue(lastEventId, forHTTPHeaderField: "Last-Event-ID")
            }
            let sent = finalRequest
            setState(.connecting)
            sseTask = Task { [weak self] in
                guard let self else { return }
                await self.runReader(generation: generation, request: sent)
            }
        }
        _ = started   // false: a reader is already connecting or connected
    }

    private func runReader(generation: Int, request: URLRequest) async {
            // The liveness clock starts with the reader (#306): a connect that
            // never delivers a byte and a stream that goes silent are the same
            // death — the kernel still calls the connection established either
            // way. Every line received below keeps the clock fresh.
            liveness.arm()
            do {
                let (bytes, response) = try await self.urlSession.bytes(for: request)
                guard let httpResponse = response as? HTTPURLResponse,
                      (200..<300).contains(httpResponse.statusCode) else {
                    self.readerGate.finish(generation) {
                        self.liveness.stop()
                        self.setState(.failed)
                    }
                    return
                }
                // Checking that this reader is still current, publishing `.connected` and starting the response
                // are one step: a stop that lands before it leaves no `.connected` behind.
                // Split the bytes ourselves: `bytes.lines` omits the blank line that ends an event.
                // A new response never continues a block the previous one left unfinished.
                // The closure names its type: with two statements and no annotation the older toolchain CodeQL builds with cannot
                // infer `T` ("missing return in closure").
                let stillCurrent: Void? = self.readerGate.ifCurrent(generation) { () -> Void in
                    self.setState(.connected)
                    self.eventParser.beginResponse()
                }
                guard stillCurrent != nil else { return }
                var splitter = SseLineSplitter()
                for try await byte in bytes {
                    guard let line = splitter.feed(byte: byte) else { continue }
                    // The parser and filter are touched only while this reader is the current one, and the gate
                    // is held for that whole step: a replaced or stopped reader never mutates its successor's state.
                    let delivered: Data?? = self.readerGate.ifCurrent(generation) { () -> Data? in
                        // Heartbeat or data, a line is proof the stream is alive (#306).
                        self.liveness.noteActivity()
                        guard let event = self.eventParser.feed(line: line), self.replayFilter.admit(event) else { return Data?.none }
                        return event.data.data(using: .utf8)
                    }
                    guard let delivered else { break }          // stale: stop reading
                    if let data = delivered { self.incomingCont.yield(data) }
                }
                // Free the gate and publish the state as one step: a consumer that reconnects as soon as it sees
                // `.disconnected` finds the gate open, and a stale reader never overwrites its successor's state.
                self.readerGate.finish(generation) {
                    self.liveness.stop()
                    self.setState(.disconnected)
                }
            } catch {
                self.readerGate.finish(generation) {
                    self.liveness.stop()
                    if self._state != .disconnected { self.setState(.failed) }
                }
            }
    }

    /// The stream, opened with the session the wallet created: `?session_id=` names it (the engine
    /// routes the replay and the live events by it).
    public func onSessionCreated(sessionId: String) async {
        let previous = sseSessionId
        sseSessionId = sessionId
        switch previous {
        case nil:
            // The first create: open the stream on it.
            if _state != .connected { try? await connect() }
        case .some(let old) where old != sessionId:
            // A re-create minted a NEW session id (the re-scan path,
            // `WmpSession.recreate` — a second invitation consume on a live
            // peer): the old stream still names the RETIRED id, and the engine
            // routes every event by `?session_id=` — the new session's outbox
            // pushes never reach it (found live: a re-scan left the wallet
            // deaf to its group; heartbeats flowed, zero data). Stop the
            // retired reader and open on the fresh id, with fresh event state:
            // the engine's replay then re-delivers everything the new
            // session's mailbox holds from the top.
            readerGate.stop {
                sseTask?.cancel()
                sseTask = nil
                liveness.stop()
                setState(.disconnected)
            }
            eventParser = SseEventParser()
            replayFilter = SseReplayFilter()
            try? await connect()
        default:
            // The same id again: the stream stays as it is.
            if _state != .connected { try? await connect() }
        }
    }

    /// The SSE GET, named with the session id.
    private func sseRequestUrl(_ sessionId: String) -> URL {
        var components = URLComponents(url: sseUrl, resolvingAgainstBaseURL: false)!
        var items = components.queryItems ?? []
        items.append(URLQueryItem(name: "session_id", value: sessionId))
        components.queryItems = items
        return components.url ?? sseUrl
    }

    /// [extraHeaders], with the `Authorization` freshened from [tokenProvider] when it answers.
    private func requestHeaders() async throws -> [String: String] {
        var headers = extraHeaders
        if let token = await tokenProvider?() {
            headers["Authorization"] = "Bearer \(token)"
        }
        return headers
    }

    public func send(_ message: Data) async throws {
        var request = URLRequest(url: sendUrl)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        for (key, value) in try await requestHeaders() {
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
        // Invalidating the reader, cancelling ITS task and publishing the state are one step under the gate lock:
        // a `connect()` that follows cannot install a task this disconnect then cancels instead.
        readerGate.stop {
            sseTask?.cancel()
            sseTask = nil
            liveness.stop()
            setState(.disconnected)
        }
        incomingCont.finish()
        stateCont.finish()
    }

    /// #306: force the stream closed WITHOUT ending the session — the incoming
    /// and state streams live on (unlike ``disconnect()``, which finishes them
    /// for good), so the resume that immediately follows re-opens the reader
    /// over a fresh socket. This kills a reader the kernel still calls
    /// established: a `flow.start` POST that timed out usually died with its
    /// ANSWER — the POST channel is independent, the answer rides the event
    /// stream, and a stream nobody reads is a stream the answer never reaches.
    /// The FAILED state reaches the session's collector, which runs the resume.
    public func forceClose() async {
        readerGate.stop {
            sseTask?.cancel()
            sseTask = nil
            liveness.stop()
            setState(.failed)
        }
    }

    private func setState(_ state: TransportState) {
        _state = state
        stateCont.yield(state)
    }
}
#endif // canImport(Darwin)

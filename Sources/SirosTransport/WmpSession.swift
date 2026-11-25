// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// WMP session client managing a single session over a `TransportProtocol`.
///
/// Handles session lifecycle (create/resume/close), request-response correlation,
/// and automatic reconnection with session resumption.
public final class WmpSession: @unchecked Sendable {
    private let transport: any TransportProtocol
    internal let codec: WmpCodec
    private let config: WmpSessionConfig

    // Saved from create() so the fresh-create fallback after a resume
    // exhaustion replays the same auth, sender and capabilities.
    private var savedAuthToken: String?
    private var savedSender: String?
    private var savedCapabilities: [String: AnyCodable]?

    private var sessionId: String?
    private var resumptionToken: String?
    private var lastReceivedId: String?

    private var _state: WmpSessionState = .closed
    private let stateContinuation: AsyncStream<WmpSessionState>.Continuation
    public let stateStream: AsyncStream<WmpSessionState>

    public var currentState: WmpSessionState { _state }

    /// The current session's id, when one is live (issue #77: the join
    /// invitation's group name) — read-only, the Kotlin SDK's shape.
    public var currentSessionId: String? { sessionId }

    /// The latest resumption token (rotated on every resume), for persistence.
    public var currentResumptionToken: String? { resumptionToken }

    /// Called once when the session has ended for good: closed, or every reconnect attempt exhausted. NOT on a
    /// transient `.failed` (one failed resume that the retry loop goes on from). A hook rather than a state
    /// observer, so it never takes elements from `stateStream`, which a host may be reading.
    public var onTerminal: (@Sendable () -> Void)?
    private var terminalFired = false
    private let terminalLock = NSLock()

    /// Fires `onTerminal` once per session, whichever of a permanent disconnect or `close()` comes first; a new
    /// `create()` re-arms it.
    private func fireTerminalOnce() {
        terminalLock.lock()
        let first = !terminalFired
        terminalFired = true
        terminalLock.unlock()
        if first { onTerminal?() }
    }

    /// Called after a lost connection has been resumed.
    public var onResumed: (@Sendable () -> Void)?

    // Request-response correlation
    private nonisolated(unsafe) var pendingRequests: [String: CheckedContinuation<JsonRpcResponse, Error>] = [:]
    private let pendingLock = NSLock()

    // Notifications
    private let notificationContinuation: AsyncStream<JsonRpcRequest>.Continuation
    private let _notifications: AsyncStream<JsonRpcRequest>

    // Send serialization — actor ensures no concurrent sends without holding locks across await
    private let sendSerializer = SendSerializer()

    /// One recovery at a time, with waiting (#306): see ``handleDisconnect``.
    private let recoveryGate = RecoveryGate()

    /// Notifications from the server (flow.progress, flow.complete, etc.).
    public func notifications() -> AsyncStream<JsonRpcRequest> {
        _notifications
    }

    public init(
        transport: any TransportProtocol,
        codec: WmpCodec = WmpCodec(),
        config: WmpSessionConfig = WmpSessionConfig()
    ) {
        self.transport = transport
        self.codec = codec
        self.config = config

        var stateCont: AsyncStream<WmpSessionState>.Continuation!
        self.stateStream = AsyncStream { stateCont = $0 }
        self.stateContinuation = stateCont

        var notifCont: AsyncStream<JsonRpcRequest>.Continuation!
        self._notifications = AsyncStream { notifCont = $0 }
        self.notificationContinuation = notifCont
    }

    /// The engine's answers that mean the wallet's session is GONE
    /// server-side (wallet-core#48): `-31000` "Session not found" — the
    /// engine restarted or the store swept it — and `-31001` "Session
    /// expired" — the record is present but its TTL passed. Both are
    /// self-healable the same way: a transparent fresh `create` (the
    /// engine session is stateless from the wallet's perspective; the
    /// credentials live in the wallet's store, not the engine's).
    /// Matched on the message text because every error path embeds it.
    static func isSessionGone(_ message: String?) -> Bool {
        guard let message else { return false }
        return message.contains("Session not found") || message.contains("Session expired")
    }

    /// A fresh `create` replaying the saved auth, sender and capabilities —
    /// the self-heal after the engine answered session loss (#48). The same
    /// call the resume-exhaustion fallback makes; safe over a connected
    /// transport (`resume` re-`connect`s the same way).
    ///
    /// `invitationNonce` (issue #77): consume a scanned invitation's nonce
    /// with the fresh create — the join lands on the backend that minted it.
    func recreate(invitationNonce: String? = nil) async throws {
        guard let token = savedAuthToken else {
            throw WmpSessionError.noAuthTokenToRecreate
        }
        try await create(
            authToken: token,
            sender: savedSender,
            capabilitiesOffered: savedCapabilities,
            invitationNonce: invitationNonce
        )
    }

    /// Create a new WMP session with the given auth token.
    ///
    /// `invitationNonce` (issue #77): consume an invitation's single-use
    /// nonce with the create — the engine's session bootstrap validates it
    /// (expiry, signature — every failure `-31002`) and answers the session
    /// the invitation names. The join lands on the backend that MINTED the
    /// invite; `nil` creates a plain session.
    public func create(
        authToken: String,
        sender: String? = nil,
        capabilitiesOffered: [String: AnyCodable]? = nil,
        invitationNonce: String? = nil
    ) async throws {
        // Saved for the fresh-create fallback after a resume exhaustion
        // (see handleDisconnect): the same auth, sender and capabilities.
        // (The nonce is NOT saved: it is single-use, spent by THIS create.)
        savedAuthToken = authToken
        savedSender = sender
        savedCapabilities = capabilitiesOffered
        terminalLock.lock(); terminalFired = false; terminalLock.unlock()
        setState(.connecting)
        try await transport.connect()
        startMessageLoop()

        let params = try codec.encodeParams(
            SessionCreateParams(
                wmp: WmpMeta(sender: sender),
                capabilitiesOffered: capabilitiesOffered,
                ttl: config.sessionTtlSeconds,
                auth: SessionAuth(type: "bearer", token: authToken),
                invitationNonce: invitationNonce
            )
        )

        let response = try await sendRequest(method: "wmp.session.create", params: params)
        if let error = response.error {
            setState(.failed)
            throw WmpSessionError.sessionCreationFailed(error.message)
        }

        guard let result = response.result else {
            throw WmpSessionError.missingResult
        }

        // Parse the result to extract session info
        let resultData = try JSONEncoder().encode(result)
        let parsed = try JSONDecoder().decode(SessionCreateResult.self, from: resultData)

        sessionId = parsed.wmp.sessionId
        resumptionToken = parsed.resumptionToken

        // The HTTP+SSE binding names its event stream with the session id (the engine's SSE route
        // requires `?session_id=`): it opens HERE, after the create answered. The create's own
        // reply rode the POST's body. The WS and in-process bindings answer nothing (their carrier
        // is bound another way).
        if let sid = sessionId {
            await transport.onSessionCreated(sessionId: sid)
        }

        setState(.active)
    }

    /// Restore a previously persisted session and resume it (after an app
    /// restart): seeds the stored session id + token, then runs the normal resume flow.
    public func resumeWith(sessionId: String, resumptionToken: String) async throws {
        self.sessionId = sessionId
        self.resumptionToken = resumptionToken
        try await resume()
    }

    /// Resume an existing session after reconnection.
    public func resume() async throws {
        guard let sid = sessionId else { throw WmpSessionError.noSession }
        guard let token = resumptionToken else { throw WmpSessionError.noResumptionToken }

        setState(.resuming)
        try await transport.connect()
        startMessageLoop()

        let params = try codec.encodeParams(
            SessionResumeParams(
                wmp: WmpMeta(sessionId: sid),
                sessionId: sid,
                resumptionToken: token,
                lastReceivedId: lastReceivedId
            )
        )

        let response = try await sendRequest(method: "wmp.session.resume", params: params)
        if let error = response.error {
            setState(.failed)
            throw WmpSessionError.resumeFailed(error.message)
        }

        // The resumption token rotates on every resume. Persist this new one,
        // not the already-spent token that was presented above.
        if let result = response.result,
           let resultData = try? JSONEncoder().encode(result),
           let parsed = try? JSONDecoder().decode(SessionResumeResult.self, from: resultData),
           let rotatedToken = parsed.resumptionToken {
            resumptionToken = rotatedToken
        }
        // A fresh HTTP+SSE transport learns the restored session id here and
        // opens its event stream; an existing transport keeps its live stream.
        await transport.onSessionCreated(sessionId: sid)

        setState(.active)
        onResumed?()
    }

    /// Close the session gracefully.
    public func close(reason: String = "complete") async throws {
        guard let sid = sessionId else { return }

        let params = try codec.encodeParams(
            SessionCloseParams(
                wmp: WmpMeta(sessionId: sid),
                reason: reason
            )
        )

        // The local teardown does not depend on the peer hearing about it: a failed close notification (a failed POST on a
        // healthy stream, say) still disconnects, ends the session and fires the terminal hook, then reports the failure.
        var notificationError: Error?
        do { try await sendNotification(method: "wmp.session.close", params: params) } catch { notificationError = error }
        await transport.disconnect()
        setState(.closed)
        fireTerminalOnce()
        sessionId = nil
        resumptionToken = nil
        if let notificationError { throw notificationError }
    }

    /// Send a JSON-RPC request and wait for the correlated response.
    public func sendRequest(
        method: String,
        params: [String: AnyCodable]?,
        timeoutMs: Int = 0
    ) async throws -> JsonRpcResponse {
        let effectiveTimeout = timeoutMs > 0 ? timeoutMs : Int(config.requestTimeoutMs)
        let id = UUID().uuidString

        let message = try codec.encodeRequest(method: method, params: stampSessionId(params), id: id)

        return try await withCheckedThrowingContinuation { continuation in
            pendingLock.lock()
            pendingRequests[id] = continuation
            pendingLock.unlock()

            Task {
                do {
                    try await sendSerializer.send(message, via: transport)
                } catch {
                    pendingLock.lock()
                    let cont = pendingRequests.removeValue(forKey: id)
                    pendingLock.unlock()
                    cont?.resume(throwing: error)
                    return
                }

                // Timeout
                try? await Task.sleep(nanoseconds: UInt64(effectiveTimeout) * 1_000_000)
                pendingLock.lock()
                let cont = pendingRequests.removeValue(forKey: id)
                pendingLock.unlock()
                cont?.resume(throwing: WmpTimeoutError(method: method, timeoutMs: effectiveTimeout))
            }
        }
    }

    /// Send a JSON-RPC notification (no response expected).
    public func sendNotification(method: String, params: [String: AnyCodable]?) async throws {
        let message = try codec.encodeNotification(method: method, params: stampSessionId(params))
        try await sendSerializer.send(message, via: transport)
    }

    /// [params] with this session's id stamped into its `wmp.session_id`.
    ///
    /// The engine resolves EVERY request's session context from that member (the SSE
    /// stream aside, the HTTP+SSE binding is stateless - nothing else names the session a
    /// POST belongs to), and its capability gate fails closed without one: a flow start
    /// whose envelope carried no session id was answered "Capability not supported" (found
    /// driving the issuance against a live engine). Nil before the create answered
    /// ([sessionId] unset): the params ride as built. The resume/close envelopes already
    /// name the session; the stamp is idempotent over them.
    private func stampSessionId(_ params: [String: AnyCodable]?) -> [String: AnyCodable]? {
        guard let sid = sessionId, var params = params,
              case var .object_(wmp) = params["wmp"] ?? AnyCodable.object_([:]) else { return params }
        wmp["session_id"] = .string(sid)
        params["wmp"] = .object_(wmp)
        return params
    }

    /// Send a JSON-RPC response for an incoming request.
    public func sendResponse(id: String, result: AnyCodable?) async throws {
        let resultDict: [String: AnyCodable]?
        if case .object_(let dict) = result {
            resultDict = dict
        } else {
            resultDict = nil
        }
        let message = try codec.encodeResponse(id: id, result: resultDict)
        try await sendSerializer.send(message, via: transport)
    }

    /// Send a JSON-RPC error response for an incoming request.
    public func sendErrorResponse(id: String, code: Int, message: String) async throws {
        let msg = try codec.encodeErrorResponse(id: id, code: code, message: message)
        try await sendSerializer.send(msg, via: transport)
    }

    // MARK: - Private

    private func startMessageLoop() {
        // Collect incoming messages
        Task {
            for await data in transport.incoming() {
                do {
                    try handleIncoming(data)
                } catch {
                    // Log and continue
                }
            }
        }

        // Monitor transport state for disconnects
        Task {
            for await transportState in transport.stateStream {
                switch transportState {
                case .disconnected, .failed:
                    // #306: the failure is handled whatever the session state
                    // is. The old `.active`-only guard silently DROPPED a
                    // failure that landed while the session was resuming or
                    // connecting, and the session stranded: the transport was
                    // dead, the resume that would have healed it never ran,
                    // and every later flow.start orphaned — the engine's asks
                    // still went to a stream nobody read. handleDisconnect
                    // itself skips the terminal states and the recovery gate is
                    // single-flight, so a redundant call costs nothing; a
                    // dropped one strands the session (the resume path is
                    // idempotent — a repeated recovery only presents the
                    // current resumption token and rotates it again).
                    await handleDisconnect()
                default:
                    break
                }
            }
        }
    }

    private func handleIncoming(_ data: Data) throws {
        let message = try codec.decodeMessage(data)

        switch message {
        case .response(let response):
            if let id = response.id {
                pendingLock.lock()
                let continuation = pendingRequests.removeValue(forKey: id)
                pendingLock.unlock()
                continuation?.resume(returning: response)
            }
        case .notification(let notification):
            if let id = notification.id {
                lastReceivedId = id
            }
            notificationContinuation.yield(notification)
        case .request(let request):
            if let id = request.id {
                lastReceivedId = id
            }
            notificationContinuation.yield(request)
        }
    }

    /// #306: a request that timed out over a carrier that may be half-open —
    /// the kernel still calls the socket established but no byte flows, so the
    /// request's ANSWER died with the stream nobody read (the POST channel is
    /// independent; the answers ride the event stream). Force the carrier
    /// closed — the heartbeat clock has not tripped yet; this acts on demand,
    /// now — then run the reconnect path: the resume re-opens the stream from
    /// the `Last-Event-ID` cursor and rotates the resumption token, so the
    /// engine's asks reach the wallet again. The caller retries its request
    /// over the healed session once this returns.
    func recoverStalledTransport() async {
        await transport.forceClose()
        await handleDisconnect()
    }

    private func handleDisconnect() async {
        // A session already ended — closed by the host, or a recovery that
        // exhausted its attempts — has nothing left to recover: its pending
        // requests were already failed and its terminal hook fired. Checked
        // BEFORE the gate, so the transport-failure events that queue up
        // behind a finished recovery end here instead of in another loop.
        guard _state != .closed, _state != .failed else { return }

        // Single-flight with waiting (#306): the transport-state collector and
        // a caller's on-demand recovery share the resume loop. A caller that
        // arrives while one runs WAITS — the outcome it wants (the session
        // resumed) is being produced — and then returns without starting
        // another, so exactly one recovery runs however many failure events
        // landed, and the on-demand caller proceeds only once the session is
        // healed.
        await recoveryGate.runOnce { await self.performRecovery() }
    }

    private func performRecovery() async {
        // Without a resumption token there is nothing to retry: the loss is final, and ends the session the same way.
        let attempts = resumptionToken == nil ? 0 : config.maxReconnectAttempts
        if attempts > 0 { setState(.resuming) }

        var lastError: (any Error)?
        for attempt in 0..<attempts {
            let backoffMs = min(
                config.reconnectBaseMs * Int64(1 << (attempt + 1)),
                config.reconnectMaxMs
            )
            try? await Task.sleep(nanoseconds: UInt64(backoffMs) * 1_000_000)

            do {
                try await resume()
                return
            } catch {
                lastError = error
                // Try again
            }
        }

        // The resume exhausted. A "Session not found" means the session
        // expired or the server restarted - it is GONE, and trying to
        // resume again is trying to bring back the dead. The wallet's
        // engine session is stateless from its own perspective (the
        // credentials live in the wallet's store, not the engine's), so
        // a transparent fresh create is safe and the wallet never gets
        // stranded on a dead session. Found on-device against the GDC
        // released engine: the session's TTL lapsed while the wallet sat
        // in the background, the resume loop exhausted, and every later
        // QR scan's flow start landed on the dead session - the engine
        // answered "Capability not supported" (the capability gate fires
        // on an unresolvable session before the flow's own matching, so
        // every request failed identically regardless of which credential
        // it named). The Kotlin twin is the same fix
        // (siros-sdk-kotlin's `fix/wmp-session-recovery`).
        // A session-gone answer ("Session not found" for a swept/restarted
        // session, "Session expired" for a present record whose TTL passed —
        // #48: the wallet sat in the background past the engine's session
        // TTL). The original cut matched only "Session not found", so the
        // TTL-expiry answer fell through to FAILED here and every later
        // flow start surfaced its error - the recovery the #48 fix re-found
        // on-device (the Kotlin twin carries the same fix).
        if let message = (lastError as? WmpSessionError)?.errorDescription,
           Self.isSessionGone(message),
           let token = savedAuthToken {
            do {
                try await create(
                    authToken: token,
                    sender: savedSender,
                    capabilitiesOffered: savedCapabilities
                )
                return
            } catch {
                // Fall through to the failed state
            }
        }

        setState(.failed)
        fireTerminalOnce()
        // Cancel all pending requests
        pendingLock.lock()
        let pending = pendingRequests
        pendingRequests.removeAll()
        pendingLock.unlock()
        for (_, continuation) in pending {
            continuation.resume(throwing: WmpSessionError.connectionFailed)
        }
    }

    private func setState(_ state: WmpSessionState) {
        _state = state
        stateContinuation.yield(state)
    }
}

// MARK: - Supporting types

public enum WmpSessionState: String, Sendable {
    case closed
    case connecting
    case active
    case resuming
    case failed
}

public struct WmpSessionConfig: Sendable {
    /// The session create's requested TTL, seconds. **Nil (the default)
    /// omits the `ttl` member** so the engine's own default applies —
    /// an explicit value overrides it (the reference engine caps a named
    /// ttl at its max). The old 3600 default reaped live join sessions
    /// at one hour against engines defaulting to days (found live:
    /// golden-fox, 2026-11-25 — the join session died at its ttl while
    /// the inviter's carried 24h, and the group vanished on restart).
    /// A caller that wants a bounded session names one.
    public var sessionTtlSeconds: Int?
    public var requestTimeoutMs: Int64
    public var maxReconnectAttempts: Int
    public var reconnectBaseMs: Int64
    public var reconnectMaxMs: Int64

    public init(
        sessionTtlSeconds: Int? = nil,
        requestTimeoutMs: Int64 = 30_000,
        maxReconnectAttempts: Int = 10,
        reconnectBaseMs: Int64 = 1_000,
        reconnectMaxMs: Int64 = 30_000
    ) {
        self.sessionTtlSeconds = sessionTtlSeconds
        self.requestTimeoutMs = requestTimeoutMs
        self.maxReconnectAttempts = maxReconnectAttempts
        self.reconnectBaseMs = reconnectBaseMs
        self.reconnectMaxMs = reconnectMaxMs
    }
}

public enum WmpSessionError: Error, Sendable {
    case sessionCreationFailed(String)
    case resumeFailed(String)
    case flowFailed(String)
    /// A session recreation had no saved auth token to replay.
    case noAuthTokenToRecreate
    case missingResult
    case noSession
    case noResumptionToken
    case connectionFailed
}

extension WmpSessionError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .sessionCreationFailed(let msg): return "Session creation failed: \(msg)"
        case .resumeFailed(let msg): return "Session resume failed: \(msg)"
        case .flowFailed(let msg): return "Flow request failed: \(msg)"
        case .missingResult: return "Missing result in WMP response"
        case .noSession: return "No active WMP session"
        case .noResumptionToken: return "No resumption token available"
        case .connectionFailed: return "WMP connection failed"
        case .noAuthTokenToRecreate: return "No auth token saved to recreate the session with"
        }
    }
}

public struct WmpTimeoutError: Error, Sendable {
    public let method: String
    public let timeoutMs: Int
}

extension WmpTimeoutError: LocalizedError {
    public var errorDescription: String? {
        "Request '\(method)' timed out after \(timeoutMs)ms"
    }
}

/// Actor that serializes transport sends without holding locks across `await`.
private actor SendSerializer {
    func send(_ data: Data, via transport: any TransportProtocol) async throws {
        try await transport.send(data)
    }
}

/// One recovery at a time, with waiting (#306): the transport-state collector
/// and a caller's on-demand recovery (a timed-out request's
/// force-close-and-resume) share the resume loop. A caller that arrives while
/// one runs suspends until it finishes — the outcome it wants (the session
/// resumed) is being produced — and then returns without starting another.
private final class RecoveryGate: @unchecked Sendable {
    private let lock = NSLock()
    private var running = false
    private var waiters: [CheckedContinuation<Bool, Never>] = []

    /// Runs `body` unless one is already running: a concurrent caller
    /// suspends until THAT one finishes and then returns `false` (its outcome
    /// is the running recovery's). True when this caller ran `body` to
    /// completion. The lock lives in the sync helpers (`admit`/`release`):
    /// `NSLock` in an async context is a concurrency violation.
    @discardableResult
    func runOnce(_ body: @escaping @Sendable () async -> Void) async -> Bool {
        let runs: Bool = await withCheckedContinuation { cont in
            self.admit(cont)
        }
        guard runs else { return false }
        await body()
        for waiter in release() { waiter.resume(returning: false) }
        return true
    }

    /// Claims the gate for one caller, or parks the caller's continuation
    /// behind the running one. Under the lock, so two concurrent callers
    /// cannot both see `running == false`.
    private func admit(_ cont: CheckedContinuation<Bool, Never>) {
        lock.lock()
        if running {
            waiters.append(cont)
            lock.unlock()
        } else {
            running = true
            lock.unlock()
            cont.resume(returning: true)
        }
    }

    /// Frees the gate and hands the waiters their answer: they rode the
    /// finished recovery, they do not start another.
    private func release() -> [CheckedContinuation<Bool, Never>] {
        lock.lock()
        running = false
        let resumees = waiters
        waiters = []
        lock.unlock()
        return resumees
    }
}

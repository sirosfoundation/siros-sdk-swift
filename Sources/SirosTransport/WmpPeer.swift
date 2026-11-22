// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

#if canImport(os)
import os
#endif

/// WMP Peer — the central dispatch node for the Wallet Messaging Protocol.
///
/// Wraps a ``WmpSession`` and adds profile-based routing for flows, methods,
/// and resolve requests. Profiles are registered via ``use(_:)`` before connecting.
///
/// Usage:
/// ```swift
/// let peer = WmpPeer(session: session)
/// peer.use(OpenID4xProfile(config: config))
/// try await peer.connect(authToken: token)
///
/// for await event in peer.flowEvents() {
///     switch event {
///     case .progress(let flowId, let step, _): ...
///     case .complete(let flowId, _): ...
///     ...
///     }
/// }
/// ```
public final class WmpPeer: WmpPeerContext, @unchecked Sendable {
    private let session: WmpSession
    private let registry = WmpRegistry()
    public var codec: WmpCodec { session.codec }

    #if canImport(os)
    private let logger = Logger(subsystem: "org.siros.sdk", category: "WmpPeer")
    private func logWarning(_ msg: String) { logger.warning("\(msg)") }
    private func logError(_ msg: String) { logger.error("\(msg)") }
    #else
    private func logWarning(_ msg: String) { print("[WmpPeer WARNING] \(msg)") }
    private func logError(_ msg: String) { print("[WmpPeer ERROR] \(msg)") }
    #endif

    // Flow event stream
    private let eventContinuation: AsyncStream<FlowEvent>.Continuation
    private let _flowEvents: AsyncStream<FlowEvent>

    // Issue #77: every incoming `wmp.message.deliver` ping's params, live.
    // The MESSAGE BODY does not ride the ping — it lands in the recipient
    // session's mailbox (`wmp.message.poll` pulls it; SirosWallet's
    // `pollGroupMessages` does). Emitted from the dispatch loop (the single
    // consumer of the session's notification stream — a second consumer
    // there would steal pings).
    private let messageDeliverContinuation: AsyncStream<[String: AnyCodable]>.Continuation
    private let _messageDeliveries: AsyncStream<[String: AnyCodable]>

    // Flow type tracking
    private nonisolated(unsafe) var flowTypeMap: [String: String] = [:]
    private let flowTypeLock = NSLock()

    public init(session: WmpSession) {
        self.session = session

        var cont: AsyncStream<FlowEvent>.Continuation!
        self._flowEvents = AsyncStream { cont = $0 }
        self.eventContinuation = cont

        var deliverCont: AsyncStream<[String: AnyCodable]>.Continuation!
        self._messageDeliveries = AsyncStream { deliverCont = $0 }
        self.messageDeliverContinuation = deliverCont
    }

       /// Observable stream of flow lifecycle events dispatched by profiles.
    public func flowEvents() -> AsyncStream<FlowEvent> { _flowEvents }

    /// Issue #77: the live `wmp.message.deliver` pings — the raw params of
    /// every delivery notification (the poll pulls the bodies).
    public func messageDeliveries() -> AsyncStream<[String: AnyCodable]> { _messageDeliveries }

    /// Session state stream.
    public var stateStream: AsyncStream<WmpSessionState> { session.stateStream }

    /// The current session's id, when one is live (the join invitation's
    /// group name, issue #77) — the Kotlin SDK's `WmpPeer.currentSessionId`.
    public var currentSessionId: String? { session.currentSessionId }

    /// The current session state (a synchronous read beside the
    /// ``stateStream``) — the Kotlin SDK's `WmpPeer.state.value`.
    public var currentState: WmpSessionState { session.currentState }

    // MARK: - Profile Registration

    /// Register a ``WmpProfile``. The profile may also conform to
    /// ``WmpFlowHandler``, ``WmpMethodHandler``, or ``WmpResolveHandler``.
    ///
    /// Must be called before ``connect(authToken:sender:)``.
    public func use(_ profile: WmpProfile) {
        registry.register(profile)
        profile.initialize(ctx: self)
    }

    // MARK: - Lifecycle

    /// Connect and create a WMP session. Starts the dispatch loop.
    ///
    /// `capabilitiesOffered` is sent in `wmp.session.create`. Capabilities are
    /// negotiated per session, so changing what is offered means creating a
    /// new session.
    public func connect(
        authToken: String,
        sender: String? = nil,
        capabilitiesOffered: [String: AnyCodable]? = nil
    ) async throws {
        // Before `create`: it starts the disconnect monitor, so a loss right after it must find the hooks.
        installSessionHooks()
        try await session.create(authToken: authToken, sender: sender, capabilitiesOffered: capabilitiesOffered)
        startDispatch()
    }

    /// Connect consuming an invitation's single-use nonce (issue #77, the
    /// invite's OWN backend): the engine's session bootstrap validates the
    /// nonce (expiry, signature — every failure `-31002`) and answers the
    /// session the invitation names — the wallet lands IN the inviter's
    /// group. For a backend the wallet was never connected to: this FIRST
    /// create consumes the nonce (a plain ``connect(authToken:)`` would
    /// burn a nonce-less session first, and ``recreateSession(invitationNonce:)``
    /// a second one after).
    public func connectWithInvitation(
        authToken: String,
        invitationNonce: String,
        capabilitiesOffered: [String: AnyCodable]? = nil
    ) async throws {
        installSessionHooks()
        try await session.create(
            authToken: authToken,
            capabilitiesOffered: capabilitiesOffered,
            invitationNonce: invitationNonce
        )
        startDispatch()
    }

    /// Recreate the session (issue #77), optionally consuming an
    /// invitation's single-use nonce — the Kotlin SDK's
    /// `WmpPeer.recreateSession` bridge, same shape.
    public func recreateSession(invitationNonce: String? = nil) async throws {
        try await session.recreate(invitationNonce: invitationNonce)
    }

    /// Close the session and stop dispatching.
    public func close(reason: String = "complete") async throws {
        // Handlers still running for the orchestrator's child flows end with the session, and answer nothing.
        registry.shutdownProfiles()
        // The event stream ends whether or not the close notification got through: a consumer must not stay suspended on
        // a session that is closed.
        defer { eventContinuation.finish() }
        try await session.close(reason: reason)
    }

    // MARK: - PeerContext (outgoing)

    public func notify(method: String, params: [String: AnyCodable]?) async throws {
        try await session.sendNotification(method: method, params: params)
    }

    public func call(method: String, params: [String: AnyCodable]?) async throws -> JsonRpcResponse {
        try await session.sendRequest(method: method, params: params)
    }

    // MARK: - Flow Convenience Methods

    /// Start a flow via wmp.flow.start.
    ///
    /// The session-loss self-heal (wallet-core#48): a start that names a
    /// session the engine no longer honours - swept by a restart, or
    /// expired while the wallet sat in the background - answers
    /// "Session not found" / "Session expired" instead of running. The
    /// transport-disconnect recovery never fires when no disconnect was
    /// observed (the wallet foregrounded straight into a scan), so the
    /// refusal IS the first notice: a fresh session (the engine session
    /// is stateless from the wallet's side) and one retry; anything else
    /// re-throws.
    public func startFlow(flowType: String, flowId: String, params: AnyCodable? = nil) async throws -> FlowStartResult {
        do {
            return try await performStart(flowType: flowType, flowId: flowId, params: params)
        } catch {
            guard let message = (error as? WmpSessionError)?.errorDescription,
                  WmpSession.isSessionGone(message) else { throw error }
            try await session.recreate()
            return try await performStart(flowType: flowType, flowId: flowId, params: params)
        }
    }

    /// The flow start itself, without the session-loss recovery.
    private func performStart(flowType: String, flowId: String, params: AnyCodable?) async throws -> FlowStartResult {
        let reqParams = try codec.encodeParams(
            FlowStartParams(wmp: WmpMeta(), flowId: flowId, flowType: flowType, params: params)
        )
        let response = try await call(method: WmpMethods.flowStart, params: reqParams)
        if let error = response.error {
            throw WmpSessionError.flowFailed(error.message)
        }
        guard let result = response.result else {
            throw WmpSessionError.missingResult
        }
        let data = try JSONEncoder().encode(result)
        let parsed = try JSONDecoder().decode(FlowStartResult.self, from: data)
        trackFlowType(flowId: parsed.flowId, flowType: parsed.flowType)
        return parsed
    }

    /// Send a flow action via wmp.flow.action.
    public func sendFlowAction(flowId: String, action: String, params: AnyCodable? = nil) async throws -> FlowActionResult {
        let reqParams = try codec.encodeParams(
            FlowActionParams(wmp: WmpMeta(), flowId: flowId, action: action, params: params)
        )
        let response = try await call(method: WmpMethods.flowAction, params: reqParams)
        if let error = response.error {
            throw WmpSessionError.flowFailed(error.message)
        }
        guard let result = response.result else {
            throw WmpSessionError.missingResult
        }
        let data = try JSONEncoder().encode(result)
        return try JSONDecoder().decode(FlowActionResult.self, from: data)
    }

    /// Send a flow cancel notification.
    public func cancelFlow(flowId: String, reason: String? = nil) async throws {
        // A cancel made here stops this side's work for the flow at once and forgets the flow, without waiting
        // for the peer to echo it: only an INCOMING cancel used to reach the handler.
        if let handler = registry.flowHandler(for: lookupFlowType(flowId)) {
            await handler.handleCancel(params: FlowCancelParams(flowId: flowId, reason: reason))
        }
        removeFlowType(flowId: flowId)
        let params = try codec.encodeParams(
            FlowCancelParams(wmp: WmpMeta(), flowId: flowId, reason: reason)
        )
        try await notify(method: WmpMethods.flowCancel, params: params)
    }

    /// Cancels `flowId` from a synchronous caller: this side's work for it (the flow's child flows included) stops
    /// BEFORE this returns, so nothing it was doing can answer or recreate state afterwards; the cancel
    /// notification goes out on a task. Application callbacks are not run (they could land after a replacement
    /// flow has begun).
    public func cancelFlowNow(flowId: String, reason: String? = nil) {
        registry.cancelLocally(flowId: flowId)
        removeFlowType(flowId: flowId)
        Task { [self] in
            guard let params = try? codec.encodeParams(FlowCancelParams(wmp: WmpMeta(), flowId: flowId, reason: reason)) else { return }
            try? await notify(method: WmpMethods.flowCancel, params: params)
        }
    }

    /// Cancels every flow this peer is running for the wallet (its parent flows; their sign/match children stop with
    /// them), from a synchronous caller: see ``cancelFlowNow(flowId:reason:)``.
    public func cancelAllFlowsNow(reason: String? = nil) {
        flowTypeLock.lock()
        let parents = flowTypeMap.filter { $0.value != WmpSubFlowTypes.sign && $0.value != WmpSubFlowTypes.match }.keys
        flowTypeLock.unlock()
        for flowId in parents { cancelFlowNow(flowId: flowId, reason: reason) }
    }

    // MARK: - Dispatch Loop

    /// Stops the profiles' in-flight work (child flows running application handlers) and keeps them from
    /// starting more. For session teardown by a caller that cannot wait for `close()`.
    public func shutdownProfiles() {
        registry.shutdownProfiles()
    }

    private func installSessionHooks() {
        // A session that ends for good (reconnects exhausted, or closed) ends the handlers running for it, whether
        // or not anyone calls `close()`. A hook, not a reader of `stateStream`: that stream belongs to the host.
        session.onTerminal = { [weak self] in self?.registry.shutdownProfiles() }
        session.onResumed = { [weak self] in self?.registry.resumeProfiles() }
    }

    private func startDispatch() {
        Task { [weak self] in
            guard let self else { return }
            for await msg in self.session.notifications() {
                do {
                    try await self.dispatch(msg)
                } catch {
                    self.logError("WmpPeer dispatch error for \(msg.method): \(error)")
                }
            }
        }
    }

    private func dispatch(_ msg: JsonRpcRequest) async throws {
        let paramsWrapped: AnyCodable? = msg.params.map { .object_($0) }

        switch msg.method {
        case WmpMethods.messageDeliver:
            // Issue #77: the mailbox ping — the body rides the recipient's
            // mailbox (the poll pulls it). No flow state, no handler: the raw
            // params reach the message surface.
            if let params = msg.params {
                messageDeliverContinuation.yield(params)
            }
        case WmpMethods.flowProgress:   try await dispatchFlowProgress(paramsWrapped)
        case WmpMethods.flowComplete:   try await dispatchFlowComplete(paramsWrapped)
        case WmpMethods.flowError:      try await dispatchFlowError(paramsWrapped)
        case WmpMethods.flowStart:      try await dispatchFlowStart(paramsWrapped, requestId: msg.id)
        case WmpMethods.flowAction:     try await dispatchFlowAction(paramsWrapped, requestId: msg.id)
        case WmpMethods.flowCancel:     try await dispatchFlowCancel(paramsWrapped)
        case WmpMethods.resolve:        try await dispatchResolve(paramsWrapped)
        default:
            if let handler = registry.methodHandler(for: msg.method) {
                let result = try await handler.handleMethod(method: msg.method, params: paramsWrapped)
                if let id = msg.id {
                    try await session.sendResponse(id: id, result: result)
                }
            } else {
                if let id = msg.id {
                    try await session.sendErrorResponse(id: id, code: WmpErrorCodes.methodNotFound, message: "Method not found: \(msg.method)")
                }
                logWarning("Unhandled WMP method: \(msg.method)")
            }
        }
    }

    private func dispatchFlowProgress(_ paramsWrapped: AnyCodable?) async throws {
        let p: FlowProgressParams = try decode(paramsWrapped)
        if let handler = registry.flowHandler(for: lookupFlowType(p.flowId)) {
            await handler.handleProgress(params: p)
        }
        eventContinuation.yield(.progress(flowId: p.flowId, step: p.step, payload: p.payload))
    }

    private func dispatchFlowComplete(_ paramsWrapped: AnyCodable?) async throws {
        let p: FlowCompleteParams = try decode(paramsWrapped)
        if let handler = registry.flowHandler(for: lookupFlowType(p.flowId)) {
            await handler.handleComplete(params: p)
        }
        removeFlowType(flowId: p.flowId)
        eventContinuation.yield(.complete(flowId: p.flowId, result: p.result))
    }

    private func dispatchFlowError(_ paramsWrapped: AnyCodable?) async throws {
        let p: FlowErrorParams = try decode(paramsWrapped)
        if let handler = registry.flowHandler(for: lookupFlowType(p.flowId)) {
            await handler.handleError(params: p)
        }
        removeFlowType(flowId: p.flowId)
        eventContinuation.yield(.error(flowId: p.flowId, code: p.code, message: p.message))
    }

    private func dispatchFlowStart(_ paramsWrapped: AnyCodable?, requestId: String? = nil) async throws {
        let p: FlowStartParams = try decode(paramsWrapped)
        if let handler = registry.flowHandler(for: p.flowType) {
            trackFlowType(flowId: p.flowId, flowType: p.flowType)
            let result = try await handler.startFlow(params: p)
            if let id = requestId {
                let resultParams = try codec.encodeParams(result)
                try await session.sendResponse(id: id, result: .object_(resultParams))
            }
        }
        eventContinuation.yield(.started(flowId: p.flowId, flowType: p.flowType, params: p.params))
    }

    private func dispatchFlowAction(_ paramsWrapped: AnyCodable?, requestId: String? = nil) async throws {
        let p: FlowActionParams = try decode(paramsWrapped)
        if let handler = registry.flowHandler(for: lookupFlowType(p.flowId)) {
            let result = try await handler.handleAction(params: p)
            if let id = requestId {
                let resultParams = try codec.encodeParams(result)
                try await session.sendResponse(id: id, result: .object_(resultParams))
            }
        }
        eventContinuation.yield(.action(flowId: p.flowId, action: p.action, params: p.params))
    }

    private func dispatchFlowCancel(_ paramsWrapped: AnyCodable?) async throws {
        let p: FlowCancelParams = try decode(paramsWrapped)
        if let handler = registry.flowHandler(for: lookupFlowType(p.flowId)) {
            await handler.handleCancel(params: p)
        }
        removeFlowType(flowId: p.flowId)
        eventContinuation.yield(.cancelled(flowId: p.flowId, reason: p.reason))
    }

    private func dispatchResolve(_ paramsWrapped: AnyCodable?) async throws {
        let p: ResolveParams = try decode(paramsWrapped)
        if let handler = registry.resolveHandler(for: p.type) {
            _ = try await handler.handleResolve(params: p)
        } else {
            logWarning("No resolve handler for type: \(p.type)")
        }
    }

    private func decode<T: Decodable>(_ params: AnyCodable?) throws -> T {
        guard let params else {
            throw WmpSessionError.missingResult
        }
        let data = try JSONEncoder().encode(params)
        return try JSONDecoder().decode(T.self, from: data)
    }

    // MARK: - Flow Type Tracking

    private func trackFlowType(flowId: String, flowType: String) {
        flowTypeLock.lock()
        flowTypeMap[flowId] = flowType
        flowTypeLock.unlock()
    }

    private func lookupFlowType(_ flowId: String) -> String {
        flowTypeLock.lock()
        defer { flowTypeLock.unlock() }
        return flowTypeMap[flowId] ?? "unknown"
    }

    public func releaseFlow(flowId: String) {
        removeFlowType(flowId: flowId)
    }

    private func removeFlowType(flowId: String) {
        flowTypeLock.lock()
        flowTypeMap.removeValue(forKey: flowId)
        flowTypeLock.unlock()
    }
}

/// Flow lifecycle events emitted by ``WmpPeer/flowEvents()``.
public enum FlowEvent: Sendable {
    case started(flowId: String, flowType: String, params: AnyCodable?)
    case progress(flowId: String, step: String, payload: AnyCodable?)
    case action(flowId: String, action: String, params: AnyCodable?)
    case complete(flowId: String, result: AnyCodable?)
    case error(flowId: String, code: String?, message: String?)
    case cancelled(flowId: String, reason: String?)
}

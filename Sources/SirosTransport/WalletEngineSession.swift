// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// WebSocket session client for the wallet backend engine protocol.
///
/// Implements the wallet backend's custom type-based WebSocket protocol
/// (handshake → flow_start → sign_request/match_request → flow_complete).
///
/// Connection sequence:
/// 1. Open WebSocket to `/api/v2/wallet?tenant_id=<tenantId>`
/// 2. Send `{"type":"handshake","app_token":"<jwt>"}`
/// 3. Receive `{"type":"handshake_complete","session_id":"...","capabilities":[...]}`
/// 4. Exchange flow messages until disconnect
public final class WalletEngineSession: @unchecked Sendable {
    public enum State: String, Sendable {
        case disconnected, connecting, connected, reconnecting, failed
    }

    private let baseUrl: String
    private let tenantId: String
    private let session: URLSession

    private let encoder = JSONEncoder()
    private let decoder: JSONDecoder = {
        let d = JSONDecoder()
        return d
    }()

    private var _state: State = .disconnected
    private let stateContinuation: AsyncStream<State>.Continuation
    public let stateStream: AsyncStream<State>
    public var currentState: State { _state }

    private var webSocketTask: URLSessionWebSocketTask?
    private var sessionId: String?
    private var lastAppToken: String?
    private var reconnectAttempts = 0
    private let maxReconnectAttempts = 5
    private let baseReconnectDelayMs: UInt64 = 1000

    // Typed message channels
    private let messagesContinuation: AsyncStream<EngineMessage>.Continuation
    private let _messages: AsyncStream<EngineMessage>

    private let flowProgressContinuation: AsyncStream<FlowProgressMessage>.Continuation
    private let _flowProgress: AsyncStream<FlowProgressMessage>

    private let flowCompleteContinuation: AsyncStream<FlowCompleteMessage>.Continuation
    private let _flowComplete: AsyncStream<FlowCompleteMessage>

    private let flowErrorContinuation: AsyncStream<FlowErrorMessage>.Continuation
    private let _flowErrors: AsyncStream<FlowErrorMessage>

    private let signRequestContinuation: AsyncStream<SignRequestMessage>.Continuation
    private let _signRequests: AsyncStream<SignRequestMessage>

    private let matchRequestContinuation: AsyncStream<MatchRequestMessage>.Continuation
    private let _matchRequests: AsyncStream<MatchRequestMessage>

    private let pushContinuation: AsyncStream<PushMessage>.Continuation
    private let _pushMessages: AsyncStream<PushMessage>

    public init(
        baseUrl: String,
        tenantId: String = "default",
        session: URLSession = .shared
    ) {
        self.baseUrl = baseUrl
        self.tenantId = tenantId
        self.session = session

        var stateCont: AsyncStream<State>.Continuation!
        self.stateStream = AsyncStream { stateCont = $0 }
        self.stateContinuation = stateCont

        var msgCont: AsyncStream<EngineMessage>.Continuation!
        self._messages = AsyncStream { msgCont = $0 }
        self.messagesContinuation = msgCont

        var fpCont: AsyncStream<FlowProgressMessage>.Continuation!
        self._flowProgress = AsyncStream { fpCont = $0 }
        self.flowProgressContinuation = fpCont

        var fcCont: AsyncStream<FlowCompleteMessage>.Continuation!
        self._flowComplete = AsyncStream { fcCont = $0 }
        self.flowCompleteContinuation = fcCont

        var feCont: AsyncStream<FlowErrorMessage>.Continuation!
        self._flowErrors = AsyncStream { feCont = $0 }
        self.flowErrorContinuation = feCont

        var srCont: AsyncStream<SignRequestMessage>.Continuation!
        self._signRequests = AsyncStream { srCont = $0 }
        self.signRequestContinuation = srCont

        var mrCont: AsyncStream<MatchRequestMessage>.Continuation!
        self._matchRequests = AsyncStream { mrCont = $0 }
        self.matchRequestContinuation = mrCont

        var pCont: AsyncStream<PushMessage>.Continuation!
        self._pushMessages = AsyncStream { pCont = $0 }
        self.pushContinuation = pCont
    }

    /// All incoming messages as raw `EngineMessage`.
    public func messages() -> AsyncStream<EngineMessage> { _messages }

    /// Server flow progress updates.
    public func flowProgress() -> AsyncStream<FlowProgressMessage> { _flowProgress }

    /// Server flow completion events.
    public func flowComplete() -> AsyncStream<FlowCompleteMessage> { _flowComplete }

    /// Server flow error events.
    public func flowErrors() -> AsyncStream<FlowErrorMessage> { _flowErrors }

    /// Server signing requests.
    public func signRequests() -> AsyncStream<SignRequestMessage> { _signRequests }

    /// Server credential matching requests.
    public func matchRequests() -> AsyncStream<MatchRequestMessage> { _matchRequests }

    /// Server push notifications.
    public func pushMessages() -> AsyncStream<PushMessage> { _pushMessages }

    /// Connect to the engine WebSocket and perform the handshake.
    public func connect(appToken: String) {
        guard _state != .connected else { return }
        setState(.connecting)
        lastAppToken = appToken
        reconnectAttempts = 0
        doConnect(appToken: appToken)
    }

    private func doConnect(appToken: String) {
        let wsUrl = baseUrl
            .replacingOccurrences(of: "https://", with: "wss://")
            .replacingOccurrences(of: "http://", with: "ws://")
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            + "/api/v2/wallet?tenant_id=\(tenantId)"

        guard let url = URL(string: wsUrl) else {
            setState(.failed)
            return
        }

        var request = URLRequest(url: url)
        request.setValue("wmp.v1", forHTTPHeaderField: "Sec-WebSocket-Protocol")

        let task = session.webSocketTask(with: request)
        self.webSocketTask = task
        task.resume()

        // Send handshake
        let handshake = HandshakeMessage(appToken: appToken)
        if let data = try? encoder.encode(handshake),
           let text = String(data: data, encoding: .utf8) {
            task.send(.string(text)) { [weak self] error in
                if error != nil {
                    self?.scheduleReconnect()
                }
            }
        }

        startReceiveLoop(task)
    }

    private func startReceiveLoop(_ task: URLSessionWebSocketTask) {
        Task { [weak self] in
            while task.state == .running {
                do {
                    let message = try await task.receive()
                    switch message {
                    case .string(let text):
                        await self?.handleMessage(text)
                    case .data(let data):
                        if let text = String(data: data, encoding: .utf8) {
                            await self?.handleMessage(text)
                        }
                    @unknown default:
                        break
                    }
                } catch {
                    self?.scheduleReconnect()
                    return
                }
            }
        }
    }

    private func scheduleReconnect() {
        guard let token = lastAppToken, reconnectAttempts < maxReconnectAttempts else {
            setState(.failed)
            return
        }
        setState(.reconnecting)
        reconnectAttempts += 1
        let attempt = reconnectAttempts
        let delayMs = baseReconnectDelayMs * UInt64(1 << min(attempt - 1, 4))

        Task {
            try? await Task.sleep(nanoseconds: delayMs * 1_000_000)
            if self._state == .reconnecting {
                self.doConnect(appToken: token)
            }
        }
    }

    private func handleMessage(_ text: String) async {
        guard let data = text.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let type = json["type"] as? String else {
            return
        }

        switch type {
        case MessageTypes.handshakeComplete:
            if let msg = try? decoder.decode(HandshakeCompleteMessage.self, from: data) {
                sessionId = msg.sessionId
                setState(.connected)
            }
        case MessageTypes.flowProgress:
            if let msg = try? decoder.decode(FlowProgressMessage.self, from: data) {
                flowProgressContinuation.yield(msg)
            }
        case MessageTypes.flowComplete:
            if let msg = try? decoder.decode(FlowCompleteMessage.self, from: data) {
                flowCompleteContinuation.yield(msg)
            }
        case MessageTypes.flowError:
            if let msg = try? decoder.decode(FlowErrorMessage.self, from: data) {
                flowErrorContinuation.yield(msg)
            }
        case MessageTypes.signRequest:
            if let msg = try? decoder.decode(SignRequestMessage.self, from: data) {
                signRequestContinuation.yield(msg)
            }
        case MessageTypes.matchRequest:
            if let msg = try? decoder.decode(MatchRequestMessage.self, from: data) {
                matchRequestContinuation.yield(msg)
            }
        case MessageTypes.push:
            if let msg = try? decoder.decode(PushMessage.self, from: data) {
                pushContinuation.yield(msg)
            }
        case MessageTypes.error:
            let _ = try? decoder.decode(ErrorMessage.self, from: data)
            setState(.failed)
        default:
            break
        }

        // Also send to raw messages channel
        if let envelope = try? decoder.decode(EngineMessage.self, from: data) {
            messagesContinuation.yield(envelope)
        }
    }

    // MARK: - Client → Server messages

    /// Start an OID4VCI credential issuance flow.
    public func startIssuance(
        offer: String? = nil,
        credentialOfferUri: String? = nil,
        redirectUri: String? = nil
    ) {
        send(FlowStartMessage(
            protocol: "oid4vci",
            offer: offer,
            credentialOfferUri: credentialOfferUri,
            redirectUri: redirectUri
        ))
    }

    /// Start an OID4VP credential presentation flow.
    public func startPresentation(
        requestUri: String? = nil,
        requestUriRef: String? = nil
    ) {
        send(FlowStartMessage(
            protocol: "oid4vp",
            requestUri: requestUri,
            requestUriRef: requestUriRef
        ))
    }

    /// Cancel an in-progress flow.
    public func cancelFlow(flowId: String) {
        sendFlowAction(flowId: flowId, action: "decline", payload: ["reason": "user_cancelled"])
    }

    /// Send a flow action (consent, select_credential, etc.).
    public func sendFlowAction(flowId: String, action: String, payload: [String: AnyCodable]? = nil) {
        send(FlowActionMessage(
            flowId: flowId,
            action: action,
            payload: payload,
            timestamp: ISO8601DateFormatter().string(from: Date())
        ))
    }

    /// Send a signing response back to the server.
    public func sendSignResponse(
        flowId: String,
        proofJwt: String? = nil,
        vpToken: String? = nil,
        proofs: [ProofObject]? = nil,
        messageId: String? = nil
    ) {
        send(SignResponseMessage(
            flowId: flowId,
            messageId: messageId,
            proofJwt: proofJwt,
            vpToken: vpToken,
            proofs: proofs
        ))
    }

    /// Send a credential matching response back to the server.
    public func sendMatchResponse(flowId: String, matches: [CredentialMatch]) {
        send(MatchResponseMessage(
            flowId: flowId,
            matches: matches
        ))
    }

    /// Send a trust evaluation result back to the server.
    public func sendTrustResult(flowId: String, trusted: Bool, reason: String? = nil) {
        var payload: [String: AnyCodable] = ["trusted": .bool(trusted)]
        if let reason { payload["reason"] = .string(reason) }
        sendFlowAction(flowId: flowId, action: "trust_result", payload: payload)
    }

    /// Send an OID4VCI §10 credential lifecycle notification for forwarding to
    /// the issuer. The backend authenticates the notification using the
    /// ephemeral issuance token it captured at flow completion.
    public func sendCredentialNotification(
        flowId: String,
        notificationId: String,
        event: String,
        eventDescription: String? = nil
    ) {
        send(CredentialNotificationMessage(
            flowId: flowId,
            notificationId: notificationId,
            event: event,
            eventDescription: eventDescription,
            timestamp: ISO8601DateFormatter().string(from: Date())
        ))
    }

    /// Suspend until the engine WebSocket handshake completes or fails.
    public func awaitConnected(timeoutMs: UInt64 = 10_000) async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                for await state in self.stateStream {
                    if state == .connected || state == .failed {
                        return
                    }
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: timeoutMs * 1_000_000)
                throw EngineSessionError.connectionTimeout
            }
            try await group.next()
            group.cancelAll()
        }
        if _state == .failed {
            throw EngineSessionError.connectionFailed
        }
    }

    /// Disconnect the WebSocket session.
    public func disconnect() {
        lastAppToken = nil
        webSocketTask?.cancel(with: .normalClosure, reason: "client disconnect".data(using: .utf8))
        webSocketTask = nil
        sessionId = nil
        setState(.disconnected)
        messagesContinuation.finish()
        flowProgressContinuation.finish()
        flowCompleteContinuation.finish()
        flowErrorContinuation.finish()
        signRequestContinuation.finish()
        matchRequestContinuation.finish()
        pushContinuation.finish()
    }

    private func send<T: Encodable>(_ message: T) {
        guard let ws = webSocketTask else {
            preconditionFailure("Not connected")
        }
        guard let data = try? encoder.encode(message),
              let text = String(data: data, encoding: .utf8) else {
            return
        }
        ws.send(.string(text)) { _ in }
    }

    private func setState(_ state: State) {
        _state = state
        stateContinuation.yield(state)
    }
}

public enum EngineSessionError: Error, Sendable {
    case connectionTimeout
    case connectionFailed
}

extension EngineSessionError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .connectionTimeout: return "Engine session connection timed out"
        case .connectionFailed: return "Engine session connection failed"
        }
    }
}

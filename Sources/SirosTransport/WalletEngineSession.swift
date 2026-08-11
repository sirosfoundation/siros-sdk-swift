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
public final class WalletEngineSession: CredentialNotifier, @unchecked Sendable {
    public enum State: String, Sendable {
        case disconnected, connecting, connected, reconnecting
        /// Distinct from `.failed`: a reconnect attempt's `tokenProvider` call
        /// itself failed (the access-token/session refresh mechanism was
        /// rejected), not merely that the socket couldn't connect - see
        /// `scheduleReconnect`. `.failed` is reserved for exhausting reconnect
        /// attempts on a transient network-level failure.
        case reauthRequired
        case failed
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
    /// Mints a fresh handshake token on demand - called before every
    /// automatic reconnect attempt instead of replaying `lastAppToken`, which
    /// is otherwise never updated after the initial `connect` and goes stale
    /// within minutes (the AS's default access-token TTL is 2 minutes) since
    /// this path had no refresh logic at all. Typically wraps
    /// `AuthTokens.ensureAnonymousToken()`, which already handles
    /// expiry-aware caching - this class only needs to call it, not
    /// duplicate that logic. Nil preserves the old (non-refreshing) behavior
    /// for callers that haven't opted in.
    private var tokenProvider: (() async throws -> String)?
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

    private let notificationAckContinuation: AsyncStream<NotificationAckMessage>.Continuation
    private let _notificationAcks: AsyncStream<NotificationAckMessage>

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

        // Unlike flowProgress/flowComplete/flowErrors/signRequests/
        // matchRequests (all drained internally by SirosWallet's own `for
        // await` loops), pushMessages/notificationAcks are host-app-facing,
        // opt-in APIs - nothing in this SDK consumes them itself. A host app
        // that never calls pushMessages()/notificationAcks() would otherwise
        // grow these streams' default `.unbounded` buffer for the entire
        // connection lifetime. Bounding to the most recent 64 caps that
        // growth without affecting a host app that drains them promptly.
        var pCont: AsyncStream<PushMessage>.Continuation!
        self._pushMessages = AsyncStream(bufferingPolicy: .bufferingNewest(64)) { pCont = $0 }
        self.pushContinuation = pCont

        var naCont: AsyncStream<NotificationAckMessage>.Continuation!
        self._notificationAcks = AsyncStream(bufferingPolicy: .bufferingNewest(64)) { naCont = $0 }
        self.notificationAckContinuation = naCont
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

    /// Acknowledgements for OID4VCI §10 credential notifications sent via
    /// `sendCredentialNotification`. Each value reports whether the backend
    /// forwarded the notification to the issuer (`status == "forwarded"`) or
    /// rejected it, including any `error` detail.
    public func notificationAcks() -> AsyncStream<NotificationAckMessage> { _notificationAcks }

    /// Whether the underlying WebSocket is currently connected.
    public var isConnected: Bool { webSocketTask != nil }

    /// Connect to the engine WebSocket and perform the handshake.
    /// - Parameters:
    ///   - appToken: JWT used for this initial handshake (avoids an extra
    ///     round trip re-minting a token we were just handed).
    ///   - tokenProvider: mints a fresh token before each subsequent
    ///     automatic reconnect attempt - see `tokenProvider`'s doc comment.
    ///     Omit only if the caller genuinely has no refresh mechanism to
    ///     offer; every real `SirosWallet` call site should pass one.
    public func connect(appToken: String, tokenProvider: (() async throws -> String)? = nil) {
        guard _state != .connected else { return }
        setState(.connecting)
        lastAppToken = appToken
        self.tokenProvider = tokenProvider
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
        guard lastAppToken != nil, reconnectAttempts < maxReconnectAttempts else {
            setState(.failed)
            return
        }
        setState(.reconnecting)
        reconnectAttempts += 1
        let attempt = reconnectAttempts
        let delayMs = baseReconnectDelayMs * UInt64(1 << min(attempt - 1, 4))

        Task {
            try? await Task.sleep(nanoseconds: delayMs * 1_000_000)
            guard self._state == .reconnecting else { return }
            guard let token = await self.refreshTokenOrSignalReauth() else { return }
            if self._state == .reconnecting {
                self.doConnect(appToken: token)
            }
        }
    }

    /// Mints a fresh token via `tokenProvider` (falling back to
    /// `lastAppToken` if no provider was supplied) for a reconnect attempt.
    /// A provider failure means the refresh mechanism itself was rejected -
    /// not a transient network blip like a socket-connect failure - so this
    /// short-circuits straight to `.reauthRequired` rather than consuming
    /// the remaining backoff budget on a broken session.
    /// - Returns: the token to reconnect with, or nil if reconnecting should
    ///   stop (state has already been updated to reflect why).
    private func refreshTokenOrSignalReauth() async -> String? {
        guard let provider = tokenProvider else { return lastAppToken }
        do {
            let fresh = try await provider()
            lastAppToken = fresh
            return fresh
        } catch {
            setState(.reauthRequired)
            return nil
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
        case MessageTypes.notificationAck:
            if let msg = try? decoder.decode(NotificationAckMessage.self, from: data) {
                notificationAckContinuation.yield(msg)
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
    ///
    /// - Parameters:
    ///   - clientAttestation: optional Wallet Instance Attestation JWT (OAuth
    ///     Client Attestation, draft-ietf-oauth-attestation-based-client-auth-04
    ///     §3.1) - see `FlowStartMessage.clientAttestation`.
    ///   - clientAttestationPoP: the matching per-flow PoP JWT, required
    ///     whenever `clientAttestation` is set.
    public func startIssuance(
        offer: String? = nil,
        credentialOfferUri: String? = nil,
        redirectUri: String? = nil,
        clientAttestation: String? = nil,
        clientAttestationPoP: String? = nil
    ) {
        send(FlowStartMessage(
            protocol: "oid4vci",
            offer: offer,
            credentialOfferUri: credentialOfferUri,
            redirectUri: redirectUri,
            clientAttestation: clientAttestation,
            clientAttestationPoP: clientAttestationPoP
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
    ///
    /// This is a no-op when the session is not connected: the notification is
    /// triggered automatically after a credential is stored, which may race with
    /// a concurrent disconnect (e.g. logout). Dropping it in that case is safe
    /// because §10 notifications are optional and best-effort.
    public func sendCredentialNotification(
        flowId: String,
        notificationId: String,
        event: String,
        eventDescription: String? = nil
    ) {
        guard isConnected else { return }
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
                    if state == .connected || state == .failed || state == .reauthRequired {
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
        switch _state {
        case .reauthRequired:
            throw EngineSessionError.reauthenticationRequired
        case .failed:
            throw EngineSessionError.connectionFailed
        default:
            break
        }
    }

    /// Force-cancel the current WebSocket - even if it still looks "connected"
    /// (`isConnected`/`currentState` don't detect a "zombie" socket that has
    /// silently stopped delivering messages) - and reconnect.
    ///
    /// Unlike `disconnect()`, this does NOT call `.finish()` on any of the
    /// flow/message `AsyncStream` continuations, so existing `for await`
    /// collectors set up before the reconnect keep working afterward. Callers
    /// resuming a flow after an OAuth redirect should call this (then
    /// `awaitConnected()`) before sending a fresh `flow_start`, since the
    /// original socket may have gone stale during the browser round-trip.
    public func forceReconnect(appToken: String) {
        webSocketTask?.cancel(with: .goingAway, reason: nil)
        webSocketTask = nil
        sessionId = nil
        lastAppToken = appToken
        reconnectAttempts = 0
        setState(.connecting)
        doConnect(appToken: appToken)
    }

    /// Resume an OID4VCI credential issuance flow after an OAuth authorization
    /// redirect, via a brand-new `flow_start` message - NOT a `flow_action` on
    /// the original flow_id, which is not guaranteed to still be alive after
    /// the redirect round-trip. Mirrors the wallet-backend's
    /// `resumeWithAuthCode` contract already used by the web client.
    /// - Parameters:
    ///   - clientAttestation/clientAttestationPoP: OAuth Client Attestation
    ///     for the resumed flow - go-wallet-backend's `Execute()` sets up its
    ///     attestation provider identically regardless of whether this is a
    ///     fresh flow or a resume (the setup runs before branching on
    ///     `msg.AuthCode`), so this is just as meaningful here as on the
    ///     original `startIssuance` call - see `FlowStartMessage.clientAttestation`.
    public func resumeIssuance(
        offer: String? = nil,
        credentialOfferUri: String? = nil,
        redirectUri: String? = nil,
        authCode: String,
        codeVerifier: String? = nil,
        clientAttestation: String? = nil,
        clientAttestationPoP: String? = nil
    ) {
        send(FlowStartMessage(
            protocol: "oid4vci",
            offer: offer,
            credentialOfferUri: credentialOfferUri,
            redirectUri: redirectUri,
            authCode: authCode,
            codeVerifier: codeVerifier,
            clientAttestation: clientAttestation,
            clientAttestationPoP: clientAttestationPoP
        ))
    }

    /// Disconnect the WebSocket session.
    public func disconnect() {
        lastAppToken = nil
        tokenProvider = nil
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
        notificationAckContinuation.finish()
    }

    private func send<T: Encodable>(_ message: T) {
        // Crashing the whole process here (the original `preconditionFailure`)
        // meant any caller racing a concurrent `disconnect()` - or invoked
        // just after a dropped connection the receive loop hasn't yet
        // reacted to - brought down the entire app rather than just failing
        // this one send. `send` is called from many public, non-throwing
        // methods (sendTrustResult, sendMatchResponse, sendSignResponse,
        // etc.), so log-and-return matches the encode-failure branch just
        // below rather than crashing.
        guard let ws = webSocketTask else {
            print("[WalletEngineSession] ⚠️ send: not connected, dropping message")
            return
        }
        guard let data = try? encoder.encode(message),
              let text = String(data: data, encoding: .utf8) else {
            return
        }
        // Mirrors the handshake send's own completion handler (above): a
        // send failure here means the same dead socket the receive loop
        // would otherwise independently notice and reconnect from - discarding
        // the error silently (the previous `{ _ in }`) just delayed detection
        // until the next inbound frame timed out instead of reacting to it
        // immediately.
        ws.send(.string(text)) { [weak self] error in
            if error != nil {
                self?.scheduleReconnect()
            }
        }
    }

    private func setState(_ state: State) {
        _state = state
        stateContinuation.yield(state)
    }
}

public enum EngineSessionError: Error, Sendable {
    case connectionTimeout
    case connectionFailed
    /// The token-refresh mechanism itself was rejected before a reconnect -
    /// the session is invalid, not just the socket. Distinct from
    /// `.connectionFailed` (transient network failure) - callers should
    /// route the user to the login screen rather than retrying.
    case reauthenticationRequired
}

extension EngineSessionError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .connectionTimeout: return "Engine session connection timed out"
        case .connectionFailed: return "Engine session connection failed"
        case .reauthenticationRequired: return "Session expired and could not be refreshed - user must log in again"
        }
    }
}

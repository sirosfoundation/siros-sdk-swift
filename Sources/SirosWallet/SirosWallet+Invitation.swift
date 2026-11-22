// Copyright 2026 SIROS Foundation. BSD-2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosCredentials
import SirosTransport

/// Issue #77 — the wallet-to-wallet invitation, the join side.
///
/// `consumeInvitation(uri:)` joins the backend the INVITE names (the
/// invitation's `provider`, the `relay` URL's own base its fallback) — NOT
/// the wallet's configured engine. The nonce exists only on the backend
/// that minted it, so a join anywhere else refuses `-31002` no matter how
/// fresh the login (found live from an Android device: a wallet configured
/// for GDC scanning a wmp-mcp invite refused every scan until the join
/// moved to the invite's backend).
///
/// `connectedWmpEndpoints()` is the endpoint surface: the wallet speaks WMP
/// to potentially several backends at once (its configured engine plus one
/// per joined invite backend), and the sample apps render the list — the
/// SDK owns the tracking. Kotlin parity: `SirosWallet.consumeInvitation` /
/// `SirosWallet.connectedWmpEndpoints` / `WmpEndpointInfo`.
extension SirosWallet {

    // MARK: - The invitation consume (the join)

    /// Consume a scanned invitation URI (issue #77): parse the base64url
    /// `data` payload, then join the backend the invitation names — one
    /// cached join peer per backend, its endpoints from that backend's own
    /// well-known. A still-closed peer connects consuming the nonce
    /// (``WmpPeer.connectWithInvitation(authToken:invitationNonce:capabilitiesOffered:)``);
    /// a connected one recreates the session with it.
    ///
    /// An invitation naming no backend (`provider`/`relay` both absent — the
    /// legacy shape) falls back to the wallet's configured engine, the
    /// Kotlin SDK's identical fallback.
    public func consumeInvitation(uri: String) async throws {
        guard let payload = invitationPayload(uri) else {
            throw SirosError.wallet(message: "The invitation URI carries no data")
        }
        guard let invitation = try? JSONSerialization.jsonObject(with: payload) as? [String: Any],
              let nonce = invitation["nonce"] as? String else {
            throw SirosError.wallet(message: "The invitation carries no nonce")
        }

        let provider = ((invitation["provider"] as? String) ?? (invitation["relay"] as? String))?
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard let provider, !provider.isEmpty else {
            // The legacy shape: no backend named — the configured engine.
            lock.lock()
            let peer = wmpPeer
            lock.unlock()
            guard let peer else {
                throw SirosError.wallet(message: "The wallet is not connected to an engine")
            }
            try await peer.recreateSession(invitationNonce: nonce)
            return
        }

        let peer = try await joinPeerFor(provider: provider, invitation: invitation)
        // The cold join: discovery + token mint CONCURRENT (one chain's
        // latency, not two serialized — the Kotlin parity), and
        // CANCELLATION-SAFE: a cancel mid-join (any navigation away) must
        // not leave a poisoned cache — the nonce is single-use, spent by the
        // create; a cached half-joined peer would make the NEXT scan consume
        // the spent nonce and refuse. Close and drop it; the next scan
        // rebuilds (the cache write happens only on a completed join).
        #if canImport(Darwin)
        if peer.currentState == .closed {
            do {
                let token = try await freshBackendToken()
                try await peer.connectWithInvitation(
                    authToken: token,
                    invitationNonce: nonce,
                )
            } catch is CancellationError {
                lock.lock()
                wmpJoinPeers[provider] = nil
                lock.unlock()
                _ = try? await peer.close()
                throw CancellationError()
            }
        } else {
            try await peer.recreateSession(invitationNonce: nonce)
        }
        #else
        // Non-Apple: the transport boundary (URLSession async bytes) —
        // the same clear refusal makeWmpProviderTransport carries.
        throw SirosError.wallet(
            message: "joining an invited backend requires Apple platforms (WmpHttpSseTransport is URLSession-async-bytes based)"
        )
        #endif
    }

    /// The join peer for an invitation's OWN backend (issue #77): one cached
    /// peer per provider URL — the endpoints from the backend's own
    /// well-known (path-preserving), the token fresh per request from the
    /// wallet's own AS. The HTTP+SSE transport is Apple-only (URLSession
    /// async bytes): Linux fails closed with a clear error, the same
    /// boundary `makeWmpProviderTransport` carries for `remoteHttpSse`.
    private func joinPeerFor(provider: String, invitation: [String: Any]) async throws -> WmpPeer {
        lock.lock()
        let cached = wmpJoinPeers[provider]
        lock.unlock()
        if let cached { return cached }

        // The cold path: the discovery and the token mint run CONCURRENTLY
        // (independent chains — one chain's latency, not two serialized
        // TLS round trips; the Kotlin parity).
        #if canImport(Darwin)
        async let endpointsTask = discoverWmpEndpoints(provider)
        async let tokenTask = freshBackendToken()
        guard let endpoints = await endpointsTask else {
            throw SirosError.wallet(
                message: "The invitation's backend does not answer discovery " +
                    "(\(provider)/.well-known/wmp-configuration) — cannot join its group"
            )
        }
        let _ = try? await tokenTask // warmed; the transport mints its own fresh per request
        let transport = WmpHttpSseTransport(
            sendUrl: endpoints.send,
            sseUrl: endpoints.sse,
            tokenProvider: { [weak self] in
                // Rung 3 (the strict flip): a token from the INVITED backend's
                // OWN AS — discovered (RFC 8414), a client dynamically
                // registered there (RFC 7591), minted per request. NOT the
                // wallet's own AS token: a strict engine pins `iss` and
                // refuses a foreign issuer. A backend without an AS falls
                // back to the wallet's own token (the subject is advisory
                // in the no-AS mode).
                guard let self else { return nil }
                return try? await self.joinBearerFor(provider: provider)
            }
        )
        let peer = WmpPeer(session: WmpSession(transport: transport))
        lock.lock()
        wmpJoinPeers[provider] = peer
        wmpJoinPeerUrls[provider] = endpoints
        // The GROUP the invitation names (the reply path's `to`): captured
        // here — `replyToGroup(backend:text:)` routes by it.
        if let group = invitation["session_id"] as? String, !group.isEmpty {
            wmpJoinGroups[provider] = group
        }
        lock.unlock()
        return peer
        #else
        throw SirosError.wallet(
            message: "joining an invited backend requires Apple platforms (WmpHttpSseTransport is URLSession-async-bytes based)"
        )
        #endif
    }

    /// A backend token for the join (the wallet's own AS — fresh per call:
    /// the binding is stateless and the AS's tokens live minutes).
    private func freshBackendToken() async throws -> String {
        lock.lock()
        let tokens = authTokens
        lock.unlock()
        guard let tokens else {
            throw SirosError.wallet(message: "No authorization tokens to join an invited backend with")
        }
        return try await tokens.ensureBackendToken().raw
    }

    /// The WMP endpoints a backend's well-known names
    /// (`/.well-known/wmp-configuration`, path-preserving: a reverse-proxied
    /// deployment serves it under its own path). `nil` when the backend
    /// does not answer or carries no `endpoints.wmp`/`endpoints.events`.
    private func discoverWmpEndpoints(_ backendBase: String) async -> (send: String, sse: String)? {
        let url = backendBase.trimmingCharacters(in: CharacterSet(charactersIn: "/")) +
            "/.well-known/wmp-configuration"
        guard let base = Foundation.URL(string: url) else { return nil }
        do {
            let (data, response) = try await URLSession.shared.data(from: base)
            guard (response as? HTTPURLResponse)?.statusCode == 200,
                  let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let endpoints = parsed["endpoints"] as? [String: Any],
                  let send = endpoints["wmp"] as? String,
                  let events = endpoints["events"] as? String,
                  !send.isEmpty, !events.isEmpty else { return nil }
            return (send, events)
        } catch {
            return nil
        }
    }

    // MARK: - Rung 3: the invited backend's OWN AS (discover → DCR → mint)

    /// The AS metadata a backend publishes (RFC 8414): the token + the
    /// registration endpoints. `nil` when the backend runs without an AS.
    private struct AsMetadata {
        let tokenEndpoint: Foundation.URL
        let registrationEndpoint: Foundation.URL?
    }

    /// Read the backend's RFC 8414 metadata (`/.well-known/oauth-authorization-server`).
    private func discoverAsMetadata(_ backendBase: String) async -> AsMetadata? {
        let url = backendBase.trimmingCharacters(in: CharacterSet(charactersIn: "/")) +
            "/.well-known/oauth-authorization-server"
        guard let base = Foundation.URL(string: url) else { return nil }
        do {
            let (data, response) = try await URLSession.shared.data(from: base)
            guard (response as? HTTPURLResponse)?.statusCode == 200,
                  let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let token = parsed["token_endpoint"] as? String,
                  !token.isEmpty,
                  let tokenUrl = Foundation.URL(string: token) else { return nil }
            let registration = (parsed["registration_endpoint"] as? String)
            let registrationUrl = registration.flatMap { $0.isEmpty ? nil : Foundation.URL(string: $0) }
            return AsMetadata(
                tokenEndpoint: tokenUrl,
                registrationEndpoint: registrationUrl
            )
        } catch {
            return nil
        }
    }

    /// Dynamically register a client at the backend's AS (RFC 7591, open
    /// registration): the arbitrary-invite constraint — a wallet from
    /// another deployment has no client there until it registers one.
    /// `nil` when the AS has no registration endpoint.
    private func dcrRegister(registrationEndpoint: Foundation.URL, clientName: String) async -> (id: String, secret: String)? {
        let body: [String: Any] = [
            "client_name": clientName,
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "client_secret_basic",
        ]
        do {
            let data = try JSONSerialization.data(withJSONObject: body)
            var request = URLRequest(url: registrationEndpoint)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = data
            let (respData, response) = try await URLSession.shared.data(for: request)
            guard (response as? HTTPURLResponse)?.statusCode == 201,
                  let parsed = try? JSONSerialization.jsonObject(with: respData) as? [String: Any],
                  let id = parsed["client_id"] as? String,
                  let secret = parsed["client_secret"] as? String,
                  !id.isEmpty, !secret.isEmpty else { return nil }
            return (id, secret)
        } catch {
            return nil
        }
    }

    /// Mint a token at the backend's own AS (client_credentials, HTTP Basic).
    private func tokenViaClientCredentials(
        tokenEndpoint: Foundation.URL,
        client: (id: String, secret: String)
    ) async -> (token: String, expAtMs: Double)? {
        let basic = Data("\(client.id):\(client.secret)".utf8).base64EncodedString()
        var request = URLRequest(url: tokenEndpoint)
        request.httpMethod = "POST"
        request.setValue("Basic \(basic)", forHTTPHeaderField: "Authorization")
        request.httpBody = Data("grant_type=client_credentials".utf8)
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard (response as? HTTPURLResponse)?.statusCode == 200,
                  let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let token = parsed["access_token"] as? String,
                  !token.isEmpty else { return nil }
            let expiresIn = (parsed["expires_in"] as? NSNumber)?.doubleValue ?? 3600
            return (token, Date().addingTimeInterval(expiresIn - 60).timeIntervalSince1970 * 1000)
        } catch {
            return nil
        }
    }

    /// A bearer for the invited backend (rung 3): a token from THAT backend's
    /// own AS — discovered (RFC 8414), a client registered (RFC 7591), minted
    /// and cached until near expiry. Falls back to the wallet's own AS token
    /// when the backend publishes no AS (the no-AS mode: any bearer rides,
    /// the subject is advisory) or the DCR/mint path fails.
    private func joinBearerFor(provider: String) async throws -> String {
        lock.lock()
        let cachedToken = wmpJoinAsTokens[provider]
        lock.unlock()
        if let cachedToken, cachedToken.expAtMs > Date().timeIntervalSince1970 * 1000 {
            return cachedToken.token
        }
        guard let meta = await discoverAsMetadata(provider) else {
            return try await freshBackendToken()
        }
        lock.lock()
        let cachedClient = wmpJoinAsClients[provider]
        lock.unlock()
        let client: (id: String, secret: String)
        if let cachedClient {
            client = cachedClient
        } else {
            guard let registration = meta.registrationEndpoint,
                  let registered = await dcrRegister(registrationEndpoint: registration, clientName: "siros-wallet-ios") else {
                return try await freshBackendToken()
            }
            lock.lock()
            wmpJoinAsClients[provider] = registered
            lock.unlock()
            client = registered
        }
        guard let minted = await tokenViaClientCredentials(tokenEndpoint: meta.tokenEndpoint, client: client) else {
            return try await freshBackendToken()
        }
        lock.lock()
        wmpJoinAsTokens[provider] = minted
        lock.unlock()
        return minted.token
    }

    /// The base64url `data` payload a `wmp://invite?data=…` (or the
    /// `https://…/wmp/invite#…` fallback) URI carries. Kotlin parity:
    /// `parseInvitationData`.
    private func invitationPayload(_ uri: String) -> Data? {
        // The same two forms the Kotlin classifier recognizes: the
        // `?data=`/`&data=` query param, else the `#fragment` fallback.
        guard let range = uri.range(of: "[?&]data=([^&#]+)", options: .regularExpression)
            ?? uri.range(of: "#([^#]+)$", options: .regularExpression) else {
            return nil
        }
        let captured = uri[range]
        let encoded: Substring
        if captured.hasPrefix("#") {
            encoded = captured.dropFirst()
        } else if let eq = captured.firstIndex(of: "=") {
            encoded = captured[captured.index(after: eq)...]
        } else {
            return nil
        }
        return base64urlDecode(String(encoded))
    }

    /// Close and forget every join peer (the logout/destroy/relogin path):
    /// their tokens are the wallet's, minted against a session that ends.
    func teardownWmpInvitationPeers() {
        lock.lock()
        let peers = Array(wmpJoinPeers.values)
        wmpJoinPeers.removeAll()
        wmpJoinPeerUrls.removeAll()
        wmpJoinGroups.removeAll()
        wmpJoinAsClients.removeAll()
        wmpJoinAsTokens.removeAll()
        wmpMainUrls = nil
        lock.unlock()
        // Issue #77: the store dies with the session (the logout/relogin
        // path) — the cursors too, so the next login re-reads from the top.
        // The config-supplied store clears with it (an app that wants to
        // KEEP history across logins supplies a store whose clear() is its
        // own business — the protocol is the seam).
        let store = config.wmpMessageStore ?? InMemoryWmpMessageStore.sharedDefault
        store.clear()
        for peer in peers {
            Task { try? await peer.close() }
        }
    }

    // MARK: - The send + the reply (issue #77's message passing)

    /// Send one message to a peer session — the `wmp.message.deliver`
    /// notification. `nil` (or the engine's origin) routes via the main
    /// engine; an invited backend's provider URL routes via ITS join peer.
    ///
    /// Kotlin parity: `SirosWallet.sendMessage(backend:to:text:)`.
    public func sendMessage(backend: String? = nil, to: String, text: String) async throws {
        let peer: WmpPeer
        switch backend {
        case nil, "", WmpEndpointInfo.Origin.engine.rawValue:
            lock.lock()
            defer { lock.unlock() }
            guard let main = wmpPeer else {
                throw SirosError.wallet(message: "The wallet is not connected to an engine")
            }
            peer = main
        default:
            lock.lock()
            let joined = wmpJoinPeers[backend!]
            lock.unlock()
            guard let joined else {
                throw SirosError.wallet(message: "The wallet is not connected to the invited backend \(backend!)")
            }
            peer = joined
        }
        try await peer.notify(
            method: WmpMethods.messageDeliver,
            params: [
                "wmp": .object_([
                    "version": .string("0.1"),
                    "session_id": .string(peer.currentSessionId ?? ""),
                ]),
                "to": .array([.string(to)]),
                "content_type": .string("text/plain"),
                "body": .object_([
                    "text": .string(text),
                ]),
            ]
        )
    }

    /// Reply to the GROUP an invited backend's invitation named (issue #77):
    /// the message rides that backend's join peer, `to` the inviter's
    /// session. Kotlin parity: `SirosWallet.replyToGroup`.
    public func replyToGroup(backend: String, text: String) async throws {
        lock.lock()
        let group = wmpJoinGroups[backend]
        lock.unlock()
        guard let group else {
            throw SirosError.wallet(message: "No joined group on the invited backend \(backend) to reply to")
        }
        try await sendMessage(backend: backend, to: group, text: text)
    }

    /// The group ids this wallet joined on invited backends (issue #77): the
    /// provider URL → the inviter's session id. The apps' reply UIs read it.
    /// Kotlin parity: `SirosWallet.joinedGroups`.
    public func joinedGroups() -> [String: String] {
        lock.lock()
        defer { lock.unlock() }
        return wmpJoinGroups
    }

    // MARK: - The message read surface (the group inbox)

    /// Every WMP peer this wallet holds right now: the main engine plus
    /// every invited backend's join peer, paired with its report name
    /// (`WmpEndpointInfo.Origin.engine.rawValue` or the provider URL).
    private func allWmpPeers() -> [(backend: String, peer: WmpPeer)] {
        lock.lock()
        defer { lock.unlock() }
        var out: [(String, WmpPeer)] = []
        if let peer = wmpPeer {
            out.append((WmpEndpointInfo.Origin.engine.rawValue, peer))
        }
        for (provider, peer) in wmpJoinPeers {
            out.append((provider, peer))
        }
        return out
    }

    /// Pull the recent group messages (issue #77): one `wmp.message.poll`
    /// per connected session — the engine's mailbox fan-out (`to` naming a
    /// group expands to every member's box) lands them there; the poll is
    /// the read. Each backend poll is independent (one refusing does not
    /// fail the rest).
    ///
    /// The store (the app-supplied ``WmpMessageStore``): every answered
    /// message APPENDS to it (the persistent inbox, the cursors riding
    /// along) and the poll answers the store's tail — a persistent store
    /// means a restart resumes where the last poll left off, not from the
    /// top (the replay).
    ///
    /// Kotlin parity: `SirosWallet.pollGroupMessages`.
    public func pollGroupMessages(limit: Int = 50) async -> [WmpGroupMessage] {
        var out: [WmpGroupMessage] = []
        let store = wmpMessageStore
        for (backend, peer) in allWmpPeers() {
            guard let sessionId = peer.currentSessionId else { continue }
            guard peer.currentState == .active else { continue }
            // The cursor rides the STORE (a persistent store keeps the
            // read's place across restarts).
            let cursor = store.cursor(backend: backend, sessionId: sessionId) ?? ""
            let params: [String: AnyCodable] = [
                "wmp": .object_([
                    "version": .string("0.1"),
                    "session_id": .string(sessionId),
                ]),
                "since": .string(cursor),
                "limit": .int(limit),
            ]
            guard let response = try? await peer.call(method: WmpMethods.messagePoll, params: params),
                  response.error == nil,
                  let result = response.result else { continue }
            // The envelope the members receive carry the SENDER's params
            // (the `to` the sender named — the group — never the engine's
            // expansion): `from` is the sender's `wmp.session_id`, the text
            // `body.text`. (JsonRpcResponse.result is the params dictionary
            // itself — the envelope entries are the AnyCodable values.)
            guard case .array(let messages)? = result["messages"] else { continue }
            var last: String?
            for message in messages {
                guard case .object_(let envelope) = message,
                      case .object_(let inner)? = envelope["params"] else { continue }
                var from: String?
                if case .object_(let wmp)? = inner["wmp"],
                   case .string(let sender)? = wmp["session_id"] {
                    from = sender
                }
                guard case .object_(let body)? = inner["body"],
                      case .string(let text)? = body["text"] else { continue }
                var messageId: String?
                if case .string(let id)? = envelope["wmp_message_id"] {
                    messageId = id
                }
                let parsed = WmpGroupMessage(
                    backend: backend,
                    sessionId: sessionId,
                    from: from,
                    text: text,
                    messageId: messageId
                )
                // Every answered message appends (idempotent by the id when
                // present) — the store IS the inbox.
                store.append(parsed)
                out.append(parsed)
                if let messageId { last = messageId }
            }
            if let last {
                store.setCursor(backend: backend, sessionId: sessionId, since: last)
            }
        }
        store.prune(keep: 50)
        return out
    }

    /// The wallet's group inbox (issue #77): the messages every session
    /// holds, from the STORE (the app-supplied ``WmpMessageStore`` — its
    /// persistence, its retention). The apps render this snapshot;
    /// ``pollGroupMessages`` keeps it fresh.
    ///
    /// Kotlin parity: `SirosWallet.wmpGroupInbox`.
    public func wmpGroupInbox(limit: Int = 50) -> [WmpGroupMessage] {
        let store = wmpMessageStore
        return allWmpPeers().flatMap { (backend, peer) -> [WmpGroupMessage] in
            guard let sessionId = peer.currentSessionId else { return [] }
            return store.load(backend: backend, sessionId: sessionId, limit: limit)
        }
    }

    /// The live group messages (issue #77): every connected session's
    /// `wmp.message.deliver` ping → its mailbox poll → the typed messages.
    /// The SSE ping carries no body — the poll (`pollGroupMessages`'s
    /// cursor path) is the read. The peers are snapshotted when the stream
    /// is consumed — a backend joined after does not stream in
    /// (re-consume to pick it up; `pollGroupMessages` always sees every
    /// current peer).
    ///
    /// Kotlin parity: `SirosWallet.groupMessageEvents`.
    public func groupMessageEvents() -> AsyncStream<WmpGroupMessage> {
        AsyncStream { continuation in
            let task = Task { [weak self] in
                guard let self else { return }
                let peers = self.allWmpPeers()
                await withTaskGroup(of: Void.self) { group in
                    for (_, peer) in peers {
                        group.addTask {
                            for await _ in peer.messageDeliveries() {
                                // The ping fired: pull whatever landed since
                                // the last poll (every session — the cheap
                                // read; the pings are untargeted).
                                let messages = await self.pollGroupMessages()
                                for message in messages {
                                    continuation.yield(message)
                                }
                            }
                        }
                    }
                    await group.waitForAll()
                }
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }
}

/// Issue #77: one group message — a `wmp.message.deliver` the wallet's
/// session received (pulled from its backend's mailbox, or arrived live
/// via the ping → poll). Kotlin parity:
/// `org.siros.sdk.wallet.WmpGroupMessage`.
public struct WmpGroupMessage: Sendable, Equatable {
    /// `WmpEndpointInfo.Origin.engine.rawValue` or the invited backend's
    /// provider URL.
    public let backend: String
    /// The wallet's session on that backend (the box the message landed in).
    public let sessionId: String
    /// The sender's session id, when the envelope carries one.
    public let from: String?
    /// The message text (`params.body.text`).
    public let text: String
    /// The engine's message id (`wmp_message_id`), when carried.
    public let messageId: String?

    public init(
        backend: String,
        sessionId: String,
        from: String?,
        text: String,
        messageId: String?
    ) {
        self.backend = backend
        self.sessionId = sessionId
        self.from = from
        self.text = text
        self.messageId = messageId
    }

    public static func == (lhs: WmpGroupMessage, rhs: WmpGroupMessage) -> Bool {
        lhs.backend == rhs.backend && lhs.sessionId == rhs.sessionId &&
            lhs.messageId == rhs.messageId && lhs.text == rhs.text
    }
}

extension SirosWallet {
    // MARK: - The endpoint surface

    /// The connected WMP backends (issue #77's endpoint surface): the
    /// wallet's configured engine plus every backend a scanned invitation
    /// named — the sample apps render the list, the SDK owns the tracking.
    /// A join backend whose connect is still running reports
    /// `state = "connecting"`. Kotlin parity: `SirosWallet.connectedWmpEndpoints`.
    public func connectedWmpEndpoints() -> [WmpEndpointInfo] {
        lock.lock()
        defer { lock.unlock() }
        var out: [WmpEndpointInfo] = []
        if let peer = wmpPeer {
            out.append(
                WmpEndpointInfo(
                    origin: WmpEndpointInfo.Origin.engine,
                    providerUrl: nil,
                    sendUrl: wmpMainUrls?.send ?? "unknown",
                    sseUrl: wmpMainUrls?.sse,
                    state: peer.currentState.rawValue.lowercased(),
                    sessionId: peer.currentSessionId,
                )
            )
        }
        for (provider, peer) in wmpJoinPeers {
            let urls = wmpJoinPeerUrls[provider]
            out.append(
                WmpEndpointInfo(
                    origin: WmpEndpointInfo.Origin.invitation,
                    providerUrl: provider,
                    sendUrl: urls?.send ?? "unknown",
                    sseUrl: urls?.sse,
                    state: peer.currentState.rawValue.lowercased(),
                    sessionId: peer.currentSessionId,
                )
            )
        }
        return out
    }
}

/// Issue #77's endpoint surface, one connected WMP backend. Kotlin parity:
/// `org.siros.sdk.wallet.WmpEndpointInfo`.
public struct WmpEndpointInfo: Sendable, Equatable {
    /// The `Origin` discriminators: the configured engine, or an invited backend.
    public enum Origin: String, Sendable {
        /// The wallet's own configured engine.
        case engine
        /// A backend a scanned invitation named (the join landed there).
        case invitation
    }

    /// [Origin.engine] (the configured engine) or [Origin.invitation].
    public let origin: Origin
    /// The invitation's provider URL (the join's target); `nil` for the engine.
    public let providerUrl: String?
    /// The backend's POST /wmp URL ("local" for the in-process engine).
    public let sendUrl: String
    /// The backend's GET /wmp/events URL; `nil` for the WS transports.
    public let sseUrl: String?
    /// The `WmpSessionState` raw value, lower-cased ("active", "connecting", …).
    public let state: String
    /// The live session's id on this backend, when one exists.
    public let sessionId: String?

    public init(
        origin: WmpEndpointInfo.Origin,
        providerUrl: String?,
        sendUrl: String,
        sseUrl: String?,
        state: String,
        sessionId: String?
    ) {
        self.origin = origin
        self.providerUrl = providerUrl
        self.sendUrl = sendUrl
        self.sseUrl = sseUrl
        self.state = state
        self.sessionId = sessionId
    }

    public static func == (lhs: WmpEndpointInfo, rhs: WmpEndpointInfo) -> Bool {
        lhs.origin == rhs.origin && lhs.providerUrl == rhs.providerUrl
    }
}

/// base64url (RFC 4648 §5, unpadded) decode — the invitation payload's form.
private func base64urlDecode(_ encoded: String) -> Data? {
    var s = encoded.replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    while s.count % 4 != 0 { s += "=" }
    return Data(base64Encoded: s)
}
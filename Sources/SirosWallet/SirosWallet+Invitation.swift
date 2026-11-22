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

        let peer = try await joinPeerFor(provider: provider)
        if peer.currentState == .closed {
            let token = try await freshBackendToken()
            try await peer.connectWithInvitation(
                authToken: token,
                invitationNonce: nonce,
            )
        } else {
            try await peer.recreateSession(invitationNonce: nonce)
        }
    }

    /// The join peer for an invitation's OWN backend (issue #77): one cached
    /// peer per provider URL — the endpoints from the backend's own
    /// well-known (path-preserving), the token fresh per request from the
    /// wallet's own AS. The HTTP+SSE transport is Apple-only (URLSession
    /// async bytes): Linux fails closed with a clear error, the same
    /// boundary `makeWmpProviderTransport` carries for `remoteHttpSse`.
    private func joinPeerFor(provider: String) async throws -> WmpPeer {
        lock.lock()
        let cached = wmpJoinPeers[provider]
        lock.unlock()
        if let cached { return cached }

        guard let endpoints = await discoverWmpEndpoints(provider) else {
            throw SirosError.wallet(
                message: "The invitation's backend does not answer discovery " +
                    "(\(provider)/.well-known/wmp-configuration) — cannot join its group"
            )
        }
        #if canImport(Darwin)
        let transport = WmpHttpSseTransport(
            sendUrl: endpoints.send,
            sseUrl: endpoints.sse,
            tokenProvider: { [weak self] in
                try? await self?.freshBackendToken()
            }
        )
        let peer = WmpPeer(session: WmpSession(transport: transport))
        lock.lock()
        wmpJoinPeers[provider] = peer
        wmpJoinPeerUrls[provider] = endpoints
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
        wmpMainUrls = nil
        lock.unlock()
        for peer in peers {
            Task { try? await peer.close() }
        }
    }

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
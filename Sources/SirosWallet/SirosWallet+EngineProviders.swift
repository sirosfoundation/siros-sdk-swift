// Copyright 2026 SIROS Foundation. BSD 2-Clause License.
//
// The prioritized engine providers: the connect-time failover machinery
// (SirosWallet's WMP path) - each provider in priority order, retries
// before failing over, the connected session pinned to its provider. A
// separate file from SirosWallet+Engine.swift's single-mode transport
// builders: the provider list is the configuration shape, the builders
// are the wires it selects among.

import Foundation
import SirosCredentials
import SirosTransport
#if canImport(os)
import os
#endif

extension SirosWallet {

    // MARK: - WMP Protocol Path

    func connectViaWmp(appToken: String) async throws {
        markSessionEnded(false)
        lock.lock(); wmpAskGeneration &+= 1; lock.unlock()
        lock.lock(); let peerEpoch = wmpAskGeneration; lock.unlock()

        // The prioritized engine providers (config.engineProviders), or the
        // legacy single-mode mapping when none are configured. Each provider
        // is connected in order (engineConnectRetries attempts each) until
        // one answers; a connected session is then PINNED to that provider
        // - failover never happens mid-flow.
        let providers: [WmpEngineProvider] = if !config.engineProviders.isEmpty {
            config.engineProviders
        } else {
            switch config.wmpEngineMode {
            case .legacyWS: []
            case .httpSSE:
                [WmpEngineProvider.remoteHttpSse(
                    sendUrl: config.wmpSendUrl,
                    sseUrl: config.wmpSseUrl,
                    tenantTokens: config.wmpTenantTokens,
                )]
            case .local:
                [WmpEngineProvider.local { [weak self] ctx in
                    guard let self, let factory = self.config.wmpTransport else {
                        throw SirosError.wallet(message: "WmpEngineMode.local needs wmpTransport (the app's WmpUniFFITransport factory - the XCFramework's engine core)")
                    }
                    // The asks of the in-process engine ride the Host port (the UniFFI
                    // callbacks), not the wire: the factory gets the WALLET's own
                    // ask handler, so the same handlers answer the local engine as
                    // answer the remote one's child flows.
                    return try factory(ctx.asks)
                }]
            }
        }

        // The legacy Go engine's WebSocket - the historic path, unchanged,
        // and never part of the provider list (it is not a siros-wallet-core
        // engine; engineUrl > discovery > backendUrl).
        if providers.isEmpty {
            let engineBase = await resolveWmpEngineBase()
            let transport = try makeWmpTransport(engineBase: engineBase, freshToken: freshBearerProvider())
            try await connectWmpPeer(
                transport: transport,
                appToken: appToken,
                legacy: true
            )
            #if canImport(os)
            logger.info("Connected via WMP protocol (legacy Go engine)")
            #endif
            return
        }

        // The provider loop: each provider in priority order, each attempt
        // building a fresh transport (the local factory may carry
        // per-attempt state; the remote one is stateless anyway).
        var lastError: (any Error)?
        for provider in providers {
            let attempts = max(1, config.engineConnectRetries)
            for attempt in 1...attempts {
                do {
                    let transport = try makeWmpProviderTransport(provider, peerEpoch: peerEpoch)
                    try await connectWmpPeer(
                        transport: transport,
                        appToken: appToken,
                        legacy: false
                    )
                    #if canImport(os)
                    logger.info("Connected via WMP protocol (engine provider \(provider.label), attempt \(attempt))")
                    #endif
                    return
                } catch is CancellationError {
                    throw CancellationError()
                } catch {
                    lastError = error
                    #if canImport(os)
                    logger.warning("Engine provider \(provider.label) connect attempt \(attempt)/\(attempts) failed: \(error)")
                    #endif
                    if attempt < attempts {
                        try? await Task.sleep(nanoseconds: 250_000_000 * UInt64(attempt))
                    }
                }
            }
            #if canImport(os)
            logger.warning("Engine provider \(provider.label) failed all \(attempts) attempts - failing over")
            #endif
        }
        let failure = lastError.map { String(describing: $0) } ?? "unknown"
        throw SirosError.wallet(
            message: "No engine provider connected (tried \(providers.map(\.label).joined(separator: ", "))): \(failure)"
        )
    }

    /// The freshened bearer source (same as the legacy engine session's
    /// reconnect mint): the HTTP+SSE binding is stateless - every POST is
    /// its own request, the engine validates each one, and the AS's tokens
    /// live ~2 minutes - so the transport re-mints per request rather than
    /// baking the connect-time token in (found driving an issuance ~40 min
    /// after login: the start reached the engine with a long-expired
    /// token). No authTokens (an anonymous/fixed-token deployment) answers
    /// nil: the transport then sends no Authorization header.
    ///
    /// The kind follows the DEPLOYMENT's engine (engine-parity.md §8): a
    /// tenant-mode engine (config.wmpTenantTokens) takes the AS's
    /// pseudonymous kind - the wallet's traffic attributes to the tenant,
    /// never to a person; the default keeps the backend token (the user's
    /// own subject), matching a user-mode engine.
    private func freshBearerProvider() -> @Sendable () async -> String? {
        { [weak self] in
            guard let tokens = self?.authTokens, let config = self?.config else { return nil }
            return try? await (config.wmpTenantTokens ? tokens.ensureTenantToken() : tokens.ensureBackendToken()).raw
        }
    }

    /// One provider's transport, per connect attempt.
    private func makeWmpProviderTransport(
        _ provider: WmpEngineProvider,
        peerEpoch: Int
    ) throws -> any TransportProtocol {
        switch provider {
        case .remoteHttpSse(let sendUrl, let sseUrl, let tenantTokens):
            // WmpHttpSseTransport is Apple-only (URLSession async bytes) -
            // the transport's own platform restriction, carried by the
            // provider: Linux fails closed with a clear error rather than
            // a missing symbol.
            #if canImport(Darwin)
            guard let send = URL(string: sendUrl), !sendUrl.isEmpty else {
                throw SirosError.wallet(message: "remoteHttpSse needs sendUrl (the engine's POST /wmp endpoint)")
            }
            guard let sse = URL(string: sseUrl), !sseUrl.isEmpty else {
                throw SirosError.wallet(message: "remoteHttpSse needs sseUrl (the engine's GET /wmp/events endpoint)")
            }
            // The kind follows the provider (the deployment's engine): the
            // same freshBearerProvider shape with the provider's tenant flag.
            let token: @Sendable () async -> String? = { [weak self] in
                guard let tokens = self?.authTokens else { return nil }
                return try? await (tenantTokens ? tokens.ensureTenantToken() : tokens.ensureBackendToken()).raw
            }
            return WmpHttpSseTransport(sendUrl: send, sseUrl: sse, tokenProvider: token)
            #else
            throw SirosError.wallet(message: "remoteHttpSse requires Apple platforms (WmpHttpSseTransport is URLSession-async-bytes based)")
            #endif
        case .local(let factory):
            let askHandler = WalletEngineAskHandler(wallet: self, lifetime: peerEpoch)
            let context = WmpEngineAskContext(
                asks: askHandler,
                // A fresh wallet-backend bearer for the app's trust stack
                // (the backend proxy's TAC-gated /v1/evaluate accepts
                // exactly this).
                bearerProvider: { [weak self] in
                    guard let tokens = self?.authTokens else { return nil }
                    return try? await tokens.ensureBackendToken().raw
                }
            )
            return try factory(context)
        }
    }

    /// The common connect tail for one built transport: the profile, the
    /// capability negotiation, the connect, and the session bookkeeping.
    /// `legacy` selects the Go engine's capability shape (go-wmp knows no
    /// `flows`/`credential_notification`); the Rust engine's transports
    /// (remote and local) always offer both.
    private func connectWmpPeer(
        transport: any TransportProtocol,
        appToken: String,
        legacy: Bool
    ) async throws {
        let session = WmpSession(transport: transport)
        let peer = WmpPeer(session: session)
        peer.use(makeWmpProfile())
        // Offered per session: a flag flip applies from the next session.
        try await peer.connect(
            authToken: appToken,
            capabilitiesOffered: makeWmpCapabilitiesOffered(legacy: legacy)
        )
        lock.lock(); wmpPeer = peer; credentialNotifier = WmpCredentialNotifier(peer: peer); lock.unlock()
    }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosTransport

/// One engine the wallet can run its WMP flows on - a member of the
/// user-configured prioritized list (``WalletConfig/engineProviders``).
///
/// The wallet connects the FIRST provider that answers a connect: each in
/// priority order, each retried (``WalletConfig/engineConnectRetries``)
/// before failing over to the next. Failover is a CONNECT-time behavior
/// only - a connected session is pinned to its provider for its life
/// (the mode-switching invariant: never mid-flow).
public enum WmpEngineProvider: Sendable {
    /// A remote engine over the WMP HTTP+SSE binding (siros-wallet-core
    /// engine-server - POST /wmp, the reply riding GET /wmp/events).
    ///
    /// - Parameters:
    ///   - sendUrl: the engine's POST /wmp endpoint.
    ///   - sseUrl: the engine's GET /wmp/events endpoint.
    ///   - tenantTokens: whether the deployment's engine runs tenant-bound
    ///     (`ENGINE_PRINCIPAL_MODE=tenant`, engine-parity.md §8): the bearer
    ///     this provider mints is then the AS's pseudonymous engine kind.
    ///     Must match the deployment - see
    ///     ``WalletConfig/wmpTenantTokens``'s doc comment.
    case remoteHttpSse(
        sendUrl: String,
        sseUrl: String,
        tenantTokens: Bool = false
    )

    /// The LOCAL engine: siros-wallet-core's engine core in-process (the
    /// XCFramework's `WmpUniFFITransport` over the UniFFI ports), the app's
    /// own transport constructed per connect from
    /// ``WmpEngineAskContext``.
    ///
    /// The factory receives a fresh context per connect attempt (the
    /// per-attempt state rule: the wallet builds a fresh transport per
    /// attempt, so a factory that captured earlier state cannot leak it
    /// forward).
    case local(@Sendable (WmpEngineAskContext) throws -> any TransportProtocol)

    /// The user-facing name of the provider (logs, failover errors).
    public var label: String {
        switch self {
        case .remoteHttpSse(let sendUrl, _, _):
            return "remote (\(sendUrl))"
        case .local:
            return "local (in-process)"
        }
    }
}

/// What the wallet hands a ``WmpEngineProvider/local`` factory per connect
/// attempt - the pieces the in-process engine needs that are the wallet's
/// to provide.
public struct WmpEngineAskContext: Sendable {
    /// The wallet's ask handler - the same handlers answer the local
    /// engine's Host-port asks as answer the remote engine's child flows.
    public let asks: WmpEngineAskHandler

    /// A FRESH wallet-backend bearer (cached until expired by the wallet's
    /// own token manager) - for the app's trust stack: a local
    /// ``WmpEngineProvider/local`` engine evaluates issuer trust through
    /// the app-supplied `Pdp`, and the backend proxy's `/v1/evaluate` route
    /// is TAC-gated (a `wallet-backend`-audience token with `tac` covering
    /// `r` passes - exactly this bearer).
    public let bearerProvider: @Sendable () async throws -> String?

    /// - Parameters:
    ///   - asks: the wallet's ask handler.
    ///   - bearerProvider: a fresh wallet-backend bearer for the app's
    ///     trust stack (null: no bearer - the PDP routes will refuse,
    ///     fail-closed).
    public init(
        asks: WmpEngineAskHandler,
        bearerProvider: @Sendable @escaping () async throws -> String?
    ) {
        self.asks = asks
        self.bearerProvider = bearerProvider
    }
}
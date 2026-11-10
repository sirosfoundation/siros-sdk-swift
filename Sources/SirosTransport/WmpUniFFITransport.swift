// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

#if canImport(EngineAdapterSdk)
import EngineAdapterSdk
#endif

/// The in-process WMP engine as a `TransportProtocol` — the local mode of
/// the engine switch (siros-wallet-core's `docs/engine-switching.md`
/// deployment table): the WMP engine core runs in the wallet's own
/// process, linked from the `engine_adapter_sdkFFI` XCFramework (built by
/// siros-wallet-core's release workflow), and this class is the transport
/// the existing `WmpPeer`/`WmpProfile` stack plugs into in place of
/// `WmpWebSocketTransport`.
///
/// Everything downstream works unchanged — the profile dispatch, the flow
/// events, the flow client. The engine's outgoing fetches go through
/// `http` (URLSession — native TLS, system roots, VPNs), the wallet's own
/// asks (the sub-flows: signing, consent, key custody) through `host`, and
/// the trust evaluation through `pdp` — `nil` fails closed at the trust
/// step, exactly as the remote engine does unconfigured; the local mode is
/// not a permissive mode.
///
/// The UniFFI Swift bindings are vendored source
/// (`Generated/EngineAdapterSdk.swift`, regenerated per engine release
/// from siros-wallet-core's `make bindings`), gated on the same
/// `canImport(EngineAdapterSdk)` as this file: the package builds
/// everywhere without the XCFramework, and the local mode activates
/// where it links.
#if canImport(EngineAdapterSdk)
public final class WmpUniFFITransport: TransportProtocol, @unchecked Sendable {
    private let http: HttpClient
    private let host: Host
    private let pdp: Pdp?
    private let engine: WmpEngine

    private let stateContinuation: AsyncStream<TransportState>.Continuation
    public let stateStream: AsyncStream<TransportState>
    private var _currentState: TransportState = .disconnected
    public var currentState: TransportState { _currentState }

    private let incomingContinuation: AsyncStream<Data>.Continuation
    private let _incoming: AsyncStream<Data>

    /// Creates the transport over the in-process engine, constructed with
    /// the app's ports.
    ///
    /// - Parameters:
    ///   - http: The engine's HTTP port — every fetch the engine makes
    ///     (URLSession or the app's stack).
    ///   - host: The wallet host — the engine's sub-flow asks.
    ///   - pdp: The trust port (the app's trust stack), or `nil` to fail
    ///     closed at the trust step.
    ///   - config: The engine's construction configuration; the defaults
    ///     fit a wallet (1 MiB messages, a 3600 s session TTL, 16
    ///     concurrent flows, the consent check in warn mode).
    public init(
        http: HttpClient,
        host: Host,
        pdp: Pdp? = nil,
        config: EngineConfig = EngineConfig(
            maxMessageSize: 1048576,
            defaultSessionTtlSecs: 3600,
            maxConcurrentFlows: 16,
            consentCheck: "warn"
        )
    ) {
        self.http = http
        self.host = host
        self.pdp = pdp
        self.engine = createEngine(config: config, http: http, host: host, pdp: pdp)

        var stateCont: AsyncStream<TransportState>.Continuation!
        self.stateStream = AsyncStream { stateCont = $0 }
        self.stateContinuation = stateCont

        var incomingCont: AsyncStream<Data>.Continuation!
        self._incoming = AsyncStream { incomingCont = $0 }
        self.incomingContinuation = incomingCont
    }

    public func connect() async throws {
        guard _currentState != .connected else { return }
        setState(.connecting)
        // The in-process engine is always "connected" — no socket to open.
        setState(.connected)
    }

    public func send(_ message: Data) async throws {
        // One WMP message in, the reply out; a notification answers nil.
        // The call blocks until the engine answers: call it from a task
        // the engine's sub-flow asks (`host`) are free to run on.
        if let response = try engine.send(message: message) {
            incomingContinuation.yield(response)
        }
        // Deliver any queued notifications (flow progress, sub-flow
        // starts, completions) that arrived while the request was in
        // flight — the transport's polling counterpart of the SSE stream
        // the remote mode reads.
        for notification in engine.takeNotifications() {
            incomingContinuation.yield(notification)
        }
    }

    public func incoming() -> AsyncStream<Data> {
        _incoming
    }

    public func disconnect() async {
        incomingContinuation.finish()
        setState(.disconnected)
    }

    private func setState(_ state: TransportState) {
        _currentState = state
        stateContinuation.yield(state)
    }
}
#endif
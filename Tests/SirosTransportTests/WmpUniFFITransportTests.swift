// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import XCTest

@testable import SirosTransport

#if canImport(EngineAdapterSdk)
import EngineAdapterSdk
/// The in-process transport's tests. The engine's XCFramework rides
/// Package.swift's `engine_adapter_sdkFFI` binaryTarget (which lands with
/// the first siros-wallet-core release tag), so these run where the
/// framework links; the whole file is compiled out elsewhere — the same
/// gate as the transport and the vendored bindings.
final class WmpUniFFITransportTests: XCTestCase {

    // The scripted ports: these tests make no fetch and ask for nothing.
    private final class RefusingHttp: HttpClient {
        func send(request: HttpRequest) async throws -> HttpResponse {
            throw SdkError.NetworkRefused()
        }
    }

    private final class RefusingHost: Host {
        func requestSign(params: SignParams) async throws -> SignResult {
            throw SdkError.Declined()
        }

        func requestMatch(params: MatchParams) async throws -> MatchResult {
            throw SdkError.Declined()
        }

        func requestVp(params: VpParams) async throws -> VpResult {
            throw SdkError.Declined()
        }

        func requestDpopProof(params: DpopProofParams) async throws -> DpopProofResult {
            throw SdkError.Declined()
        }

        func requestConsent(params: ConsentParams) async throws -> ConsentResult {
            throw SdkError.Declined()
        }

        func requestTxCode(flowId: String) async throws -> String {
            throw SdkError.Declined()
        }

        func openAuthorization(flowId: String, url: String) async throws {}

        func requestSigningKey(params: SigningKeyParams) async throws -> SigningKeyResult {
            throw SdkError.Cannot(reason: "no key")
        }

        func requestAttestation(params: AttestationParams) async throws -> AttestationResult {
            throw SdkError.Cannot(reason: "no attestation")
        }

        func requestCredentialSelection(
            params: CredentialSelectionParams
        ) async throws -> CredentialSelectionResult {
            throw SdkError.Cannot(reason: "no selection")
        }

        func progress(flowId: String, step: String, detail: String?) {}
    }

    /// Whether the engine's native library loads in this process.
    private func engineLoadable() -> Bool {
        let engine = createEngine(
            config: EngineConfig(
                maxMessageSize: 1048576,
                defaultSessionTtlSecs: 3600,
                maxConcurrentFlows: 16,
                consentCheck: "warn"
            ),
            http: RefusingHttp(),
            host: RefusingHost(),
            pdp: nil
        )
        return engine.isReady()
    }

    func testConnectTransitionsToConnected() async throws {
        try XCTSkipUnless(engineLoadable(), "the engine's native library is not linked here")
        let transport = WmpUniFFITransport(http: RefusingHttp(), host: RefusingHost())

        XCTAssertEqual(transport.currentState, .disconnected)
        try await transport.connect()
        XCTAssertEqual(transport.currentState, .connected)
    }

    func testSendDeliversTheReplyThroughIncoming() async throws {
        try XCTSkipUnless(engineLoadable(), "the engine's native library is not linked here")
        let transport = WmpUniFFITransport(http: RefusingHttp(), host: RefusingHost())
        try await transport.connect()

        // One WMP request: the session create. The reply comes back
        // through incoming(), as the peer delivers it.
        let create = """
        {"jsonrpc":"2.0","id":"uniffi-1","method":"wmp.session.create",\
        "params":{"wmp":{"version":"0.1"},"security":{"mode":"tls"}}}
        """
        try await transport.send(Data(create.utf8))

        let reply = try await withTimeout(seconds: 10) {
            try await transport.incoming().first(where: { _ in true })
        }
        let text = String(data: reply, encoding: .utf8) ?? ""
        XCTAssertTrue(text.contains("\"id\":\"uniffi-1\""), "the reply carries the id: \(text)")
        XCTAssertTrue(text.contains("ses-"), "the session was assigned: \(text)")
        XCTAssertTrue(text.contains("\"capabilities\""), "the capabilities are present: \(text)")
    }

    func testDisconnectTransitionsBack() async throws {
        try XCTSkipUnless(engineLoadable(), "the engine's native library is not linked here")
        let transport = WmpUniFFITransport(http: RefusingHttp(), host: RefusingHost())
        try await transport.connect()

        await transport.disconnect()

        XCTAssertEqual(transport.currentState, .disconnected)
    }

    /// Waits for the first value of a stream, throwing on the bound.
    private func withTimeout<T: Sendable>(
        seconds: TimeInterval,
        _ body: @escaping @Sendable () async throws -> T?
    ) async throws -> T {
        let result = try await withThrowingTaskGroup(of: T?.self) { group in
            group.addTask { try await body() }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                return nil
            }
            defer { group.cancelAll() }
            return try await group.next() ?? nil
        }
        guard let value = result else {
            throw NSError(
                domain: "WmpUniFFITransportTests", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "timed out waiting for the stream"]
            )
        }
        return value
    }
}
#endif
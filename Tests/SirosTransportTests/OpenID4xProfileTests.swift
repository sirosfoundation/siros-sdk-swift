// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosTransport

// MARK: - Mock peer context

private final class MockPeerContext: WmpPeerContext, @unchecked Sendable {
    let codec = WmpCodec()

    private let lock = NSLock()
    private var _notifications: [(method: String, params: [String: AnyCodable]?)] = []

    var notifications: [(method: String, params: [String: AnyCodable]?)] {
        lock.lock()
        defer { lock.unlock() }
        return _notifications
    }

    func notify(method: String, params: [String: AnyCodable]?) async throws {
        lock.lock()
        _notifications.append((method, params))
        lock.unlock()
    }

    func call(method: String, params: [String: AnyCodable]?) async throws -> JsonRpcResponse {
        return JsonRpcResponse(id: "mock", result: [:])
    }
}

// MARK: - Tests

final class OpenID4xProfileTests: XCTestCase {

    // MARK: - handleProgress routing

    func testHandleProgressSignRequestCallsOnSignRequest() async throws {
        let ctx = MockPeerContext()
        var receivedFlowId: String?
        var receivedParams: SignSubFlowParams?

        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onSignRequest: { flowId, params in
                receivedFlowId = flowId
                receivedParams = params
                return SignSubFlowResult(proofs: [ProofObject(proofType: "jwt", jwt: "header.payload.sig")])
            }
        ))
        profile.initialize(ctx: ctx)

        let payload = try buildSignPayload()
        let progressParams = FlowProgressParams(
            flowId: "flow-1",
            step: "sign_request",
            payload: payload
        )
        await profile.handleProgress(params: progressParams)

        XCTAssertEqual(receivedFlowId, "flow-1")
        XCTAssertEqual(receivedParams?.action, "sign")
        XCTAssertEqual(receivedParams?.nonce, "nonce-abc")
        XCTAssertEqual(receivedParams?.audience, "https://issuer.example")

        // Verify sign_response notification sent on wmp.flow.action
        XCTAssertEqual(ctx.notifications.count, 1)
        let notification = ctx.notifications[0]
        XCTAssertEqual(notification.method, WmpMethods.flowAction)
        if case .string(let action) = notification.params?["action"] {
            XCTAssertEqual(action, "sign_response")
        } else {
            XCTFail("Expected action = sign_response in notification params")
        }
    }

    func testHandleProgressMatchRequestCallsOnMatchRequest() async throws {
        let ctx = MockPeerContext()
        var receivedFlowId: String?

        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onMatchRequest: { flowId, _ in
                receivedFlowId = flowId
                return MatchResult(matches: [
                    CredentialMatch(credentialId: "cred-1", format: "vc+sd-jwt"),
                ])
            }
        ))
        profile.initialize(ctx: ctx)

        let progressParams = FlowProgressParams(
            flowId: "flow-2",
            step: "match_request",
            payload: nil
        )
        await profile.handleProgress(params: progressParams)

        XCTAssertEqual(receivedFlowId, "flow-2")
        XCTAssertEqual(ctx.notifications.count, 1)
        let notification = ctx.notifications[0]
        XCTAssertEqual(notification.method, WmpMethods.flowAction)
        if case .string(let action) = notification.params?["action"] {
            XCTAssertEqual(action, "match_response")
        } else {
            XCTFail("Expected action = match_response in notification params")
        }
    }

    func testHandleProgressTrustEvaluationCallsOnTrustEvaluation() async throws {
        let ctx = MockPeerContext()
        var receivedFlowId: String?

        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onTrustEvaluation: { flowId, _ in
                receivedFlowId = flowId
                return TrustResult(trusted: true, framework: "eidas", reason: nil)
            }
        ))
        profile.initialize(ctx: ctx)

        let progressParams = FlowProgressParams(
            flowId: "flow-3",
            step: "trust_evaluation_required",
            payload: nil
        )
        await profile.handleProgress(params: progressParams)

        XCTAssertEqual(receivedFlowId, "flow-3")
        XCTAssertEqual(ctx.notifications.count, 1)
        let notification = ctx.notifications[0]
        XCTAssertEqual(notification.method, WmpMethods.flowAction)
        if case .string(let action) = notification.params?["action"] {
            XCTAssertEqual(action, "trust_result")
        } else {
            XCTFail("Expected action = trust_result in notification params")
        }
        if case .bool(let trusted) = notification.params?["trusted"] {
            XCTAssertTrue(trusted)
        } else {
            XCTFail("Expected trusted = true in notification params")
        }
    }

    func testHandleProgressUnknownStepCallsOnProgress() async throws {
        let ctx = MockPeerContext()
        var receivedStep: String?

        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onProgress: { _, step, _ in
                receivedStep = step
            }
        ))
        profile.initialize(ctx: ctx)

        let progressParams = FlowProgressParams(
            flowId: "flow-4",
            step: VCIStep.parsingOffer,
            payload: nil
        )
        await profile.handleProgress(params: progressParams)

        XCTAssertEqual(receivedStep, VCIStep.parsingOffer)
        XCTAssertEqual(ctx.notifications.count, 0, "No outgoing notification expected for passthrough progress")
    }

    // MARK: - handleComplete / handleError / handleCancel

    func testHandleCompleteCallsOnComplete() async throws {
        let ctx = MockPeerContext()
        var completedFlowId: String?

        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onComplete: { flowId, _ in completedFlowId = flowId }
        ))
        profile.initialize(ctx: ctx)

        await profile.handleComplete(params: FlowCompleteParams(flowId: "flow-5"))
        XCTAssertEqual(completedFlowId, "flow-5")
    }

    func testHandleErrorCallsOnError() async throws {
        let ctx = MockPeerContext()
        var errorFlowId: String?
        var errorCode: String?

        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onError: { flowId, code, _ in
                errorFlowId = flowId
                errorCode = code
            }
        ))
        profile.initialize(ctx: ctx)

        await profile.handleError(params: FlowErrorParams(flowId: "flow-6", code: "E_ISSUER", message: "issuer error"))
        XCTAssertEqual(errorFlowId, "flow-6")
        XCTAssertEqual(errorCode, "E_ISSUER")
    }

    // MARK: - Error propagation

    func testHandleProgressSignRequestHandlerErrorSendsFlowError() async throws {
        let ctx = MockPeerContext()

        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onSignRequest: { _, _ in
                struct SignError: Error, LocalizedError {
                    var errorDescription: String? { "key not found" }
                }
                throw SignError()
            }
        ))
        profile.initialize(ctx: ctx)

        let payload = try buildSignPayload()
        let progressParams = FlowProgressParams(
            flowId: "flow-7",
            step: "sign_request",
            payload: payload
        )
        await profile.handleProgress(params: progressParams)

        // Should send wmp.flow.error
        XCTAssertEqual(ctx.notifications.count, 1)
        XCTAssertEqual(ctx.notifications[0].method, WmpMethods.flowError)
        if case .string(let code) = ctx.notifications[0].params?["code"] {
            XCTAssertEqual(code, "SIGN_ERROR")
        } else {
            XCTFail("Expected code = SIGN_ERROR in flow error notification")
        }
    }

    func testHandleProgressTrustEvaluationHandlerErrorSendsUntrustedResult() async throws {
        let ctx = MockPeerContext()

        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onTrustEvaluation: { _, _ in
                struct TrustError: Error {}
                throw TrustError()
            }
        ))
        profile.initialize(ctx: ctx)

        await profile.handleProgress(params: FlowProgressParams(
            flowId: "flow-8",
            step: "trust_evaluation_required",
            payload: nil
        ))

        XCTAssertEqual(ctx.notifications.count, 1)
        XCTAssertEqual(ctx.notifications[0].method, WmpMethods.flowAction)
        if case .bool(let trusted) = ctx.notifications[0].params?["trusted"] {
            XCTAssertFalse(trusted, "Trust evaluation error should result in trusted=false")
        } else {
            XCTFail("Expected trusted field in trust_result notification")
        }
    }

    // MARK: - startFlow / initialize

    func testStartFlowReturnsMatchingResult() async throws {
        let ctx = MockPeerContext()
        let profile = OpenID4xProfile()
        profile.initialize(ctx: ctx)

        let params = FlowStartParams(
            wmp: WmpMeta(),
            flowId: "flow-9",
            flowType: OID4FlowTypes.oid4vci
        )
        let result = try await profile.startFlow(params: params)
        XCTAssertEqual(result.flowId, "flow-9")
        XCTAssertEqual(result.flowType, OID4FlowTypes.oid4vci)
    }

    func testProfileHasExpectedFlowTypes() {
        let profile = OpenID4xProfile()
        XCTAssertTrue(profile.flowTypes.contains(OID4FlowTypes.oid4vci))
        XCTAssertTrue(profile.flowTypes.contains(OID4FlowTypes.oid4vp))
    }
}

// MARK: - Helpers

private func buildSignPayload() throws -> AnyCodable {
    let signParams = SignSubFlowParams(
        action: "sign",
        nonce: "nonce-abc",
        audience: "https://issuer.example",
        proofType: "jwt"
    )
    let data = try JSONEncoder().encode(signParams)
    return try JSONDecoder().decode(AnyCodable.self, from: data)
}

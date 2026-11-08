// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosTransport

// MARK: - Mock peer context (the file's own pattern)

private final class AskPeerContext: WmpPeerContext, @unchecked Sendable {
    let codec = WmpCodec()

    private let lock = NSLock()
    private var _notifications: [(method: String, params: [String: AnyCodable]?)] = []

    var notifications: [(method: String, params: [String: AnyCodable]?)] {
        lock.lock(); defer { lock.unlock() }
        return _notifications
    }

    private var _released: [String] = []
    var released: [String] { lock.lock(); defer { lock.unlock() }; return _released }
    func releaseFlow(flowId: String) { lock.lock(); _released.append(flowId); lock.unlock() }

    func notify(method: String, params: [String: AnyCodable]?) async throws {
        lock.lock()
        _notifications.append((method, params))
        lock.unlock()
    }

    func call(method: String, params: [String: AnyCodable]?) async throws -> JsonRpcResponse {
        JsonRpcResponse(id: "mock", result: [:])
    }
}

/// siros-wallet-core's typed asks (engine-ports' `Host` vocabulary): each arrives as a
/// `wmp.flow.start` child and is answered with `wmp.flow.complete` carrying the ask's own
/// result struct on the child's id — or the structured NEGATIVE the engine relays correctly
/// (a consent decline, a named sign-stage refusal), never a bare flow error.
///
/// The dialect forks are exercised too: `sign` without an `action` member routes to the bare
/// handler; `match` without `parent_flow_id` answers `selections` (the wallet's own
/// credential ids) instead of go-wmp's query-id-only `matches`.
final class OpenID4xTypedAskTests: XCTestCase {

    private func childStart(
        flowType: String,
        childId: String,
        payload: [String: AnyCodable]?
    ) -> FlowStartParams {
        FlowStartParams(
            wmp: WmpMeta(),
            flowId: childId,
            flowType: flowType,
            params: payload.map { AnyCodable.object_($0) }
        )
    }

    private func answerResult(_ ctx: AskPeerContext, index: Int) -> [String: AnyCodable] {
        let answer = ctx.notifications[index]
        XCTAssertEqual(WmpMethods.flowComplete, answer.method)
        return answer.params?["result"]?.objectValue ?? [:]
    }

    // ── sign: the dialect fork ────────────────────────────────────────────────

    /// The bare `sign` ask (no `action` member) is answered with the signature byte array
    /// (`Vec<u8>` on the wire, not base64).
    func testBareSignAskAnswersTheSignatureByteArray() async throws {
        let ctx = AskPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onProofSign: { parentId, params in
                XCTAssertEqual("parent-1", parentId)
                XCTAssertEqual([104, 101, 108, 108, 111], params.toSign)
                XCTAssertEqual("kid-9", params.keyId)
                XCTAssertEqual("ES256", params.algorithm)
                return Data([4, 3, 2, 1])
            }
        ))
        profile.initialize(ctx: ctx)
        // Driven through runChildFlow directly (the peer's startFlow
        // acknowledgement is its own concern; the existing profile tests
        // drive the same way).
        await profile.runChildFlow(params: childStart(
            flowType: WmpSubFlowTypes.sign,
            childId: "parent-1::sign::1",
            payload: [
                "flow_id": .string("parent-1"),
                "to_sign": .array([104, 101, 108, 108, 111].map { AnyCodable.int($0) }),
                "key_id": .string("kid-9"),
                "algorithm": .string("ES256"),
            ]
        ))
        let result = answerResult(ctx, index: 0)
        XCTAssertEqual([4, 3, 2, 1], (result["signature"]?.arrayValue ?? []).compactMap { $0.intValue })
    }

    /// A `sign` ask still carrying an `action` member routes to the go-wmp handler —
    /// the bare handler must not see it.
    func testSignAskWithAnActionMemberRoutesToTheGoWmpHandler() async throws {
        let ctx = AskPeerContext()
        var bareSawIt = false
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onSignRequest: { parentId, params in
                XCTAssertEqual("parent-1", parentId)
                XCTAssertEqual("generate_proof", params.action)
                return SignSubFlowResult(proofs: [ProofObject(proofType: "jwt", jwt: "p")])
            },
            onProofSign: { _, _ in
                bareSawIt = true
                return Data([1])
            }
        ))
        profile.initialize(ctx: ctx)
        await profile.runChildFlow(params: childStart(
            flowType: WmpSubFlowTypes.sign,
            childId: "child-1",
            payload: [
                "action": .string("generate_proof"),
                "nonce": .string("n"), "audience": .string("a"),
                "parent_flow_id": .string("parent-1"),
            ]
        ))
        let result = answerResult(ctx, index: 0)
        XCTAssertEqual("p", result["proofs"]?.arrayValue?.first?.objectValue?["jwt"]?.stringValue)
        XCTAssertFalse(bareSawIt)
    }

    // ── signing_key ───────────────────────────────────────────────────────────

    /// The `signing_key` ask answers the JWK; "no such key" is the empty object (the
    /// engine reads it as a bare proof header).
    func testSigningKeyAskAnswersJwkAndNoKeyAsEmptyObject() async throws {
        let ctx = AskPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onSigningKey: { parentId, keyId in
                if keyId == "kid-9" {
                    XCTAssertEqual("p-1", parentId)
                    return EngineSigningKeyResult(jwk: ["kid": .string("kid-9"), "kty": .string("EC")])
                }
                return EngineSigningKeyResult(jwk: nil)
            }
        ))
        profile.initialize(ctx: ctx)
        await profile.runChildFlow(params: childStart(
            flowType: WmpSubFlowTypes.signingKey, childId: "p-1::signing_key::1",
            payload: ["flow_id": .string("p-1"), "key_id": .string("kid-9")]
        ))
        XCTAssertEqual("kid-9", answerResult(ctx, index: 0)["jwk"]?.objectValue?["kid"]?.stringValue)

        await profile.runChildFlow(params: childStart(
            flowType: WmpSubFlowTypes.signingKey, childId: "p-1::signing_key::2",
            payload: ["flow_id": .string("p-1"), "key_id": .string("missing")]
        ))
        let noKey = answerResult(ctx, index: 1)
        XCTAssertTrue(noKey.isEmpty, "the no-key answer is the empty object")
    }

    // ── consent ───────────────────────────────────────────────────────────────

    /// A consent decline rides the result (`consented: false`), never a flow error —
    /// the decline is the verifier-facing `access_denied`.
    func testConsentDeclineIsTheResultFalseNeverAFlowError() async throws {
        let ctx = AskPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onConsent: { parentId, params in
                XCTAssertEqual("p-2", parentId)
                XCTAssertEqual("scope-x", params.purpose)
                XCTAssertEqual(["given_name"], params.requestedClaims)
                return false
            }
        ))
        profile.initialize(ctx: ctx)
        await profile.runChildFlow(params: childStart(
            flowType: WmpSubFlowTypes.consent, childId: "p-2::consent::1",
            payload: [
                "flow_id": .string("p-2"), "purpose": .string("scope-x"),
                "requested_claims": .array([.string("given_name")]),
                "transaction_data": .array([]),
            ]
        ))
        XCTAssertEqual(false, answerResult(ctx, index: 0)["consented"]?.boolValue)
        XCTAssertTrue(ctx.notifications.allSatisfy { $0.method != WmpMethods.flowError },
                      "a decline is never a generic flow error")
    }

    /// A consent ask with no consent UI behind the wallet declines (the listener's
    /// fail-closed default).
    func testConsentAskWithNoConsentUiDeclines() async throws {
        let ctx = AskPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig())
        profile.initialize(ctx: ctx)
        await profile.runChildFlow(params: childStart(
            flowType: WmpSubFlowTypes.consent, childId: "p::consent::1",
            payload: ["flow_id": .string("p"), "requested_claims": .array([]), "transaction_data": .array([])]
        ))
        XCTAssertEqual(false, answerResult(ctx, index: 0)["consented"]?.boolValue)
    }

    // ── tx_code ────────────────────────────────────────────────────────────────

    func testTxCodeAskAnswersTheObjectForm() async throws {
        let ctx = AskPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onTxCode: { parentId in
                XCTAssertEqual("p-3", parentId)
                return "1234"
            }
        ))
        profile.initialize(ctx: ctx)
        await profile.runChildFlow(params: childStart(
            flowType: WmpSubFlowTypes.txCode, childId: "p-3::tx_code::1",
            payload: ["flow_id": .string("p-3")]
        ))
        XCTAssertEqual("1234", answerResult(ctx, index: 0)["tx_code"]?.stringValue)
    }

    // ── authorization ──────────────────────────────────────────────────────────

    /// The ask hands the URL over; the result is the empty object (the engine ignores it —
    /// the answer arrives later as an `authorize` action on the parent flow).
    func testAuthorizationAskHandsTheUrlOver() async throws {
        let ctx = AskPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onAuthorization: { parentId, url in
                XCTAssertEqual("p-4", parentId)
                XCTAssertEqual("https://as.example/authorize?state=s", url)
            }
        ))
        profile.initialize(ctx: ctx)
        await profile.runChildFlow(params: childStart(
            flowType: WmpSubFlowTypes.authorization, childId: "p-4::authorization::1",
            payload: ["flow_id": .string("p-4"), "url": .string("https://as.example/authorize?state=s")]
        ))
        XCTAssertTrue(answerResult(ctx, index: 0).isEmpty)
    }

    // ── presentation ──────────────────────────────────────────────────────────

    private func vpPayload() -> [String: AnyCodable] {
        [
            "flow_id": .string("p-5"), "audience": .string("verifier"), "nonce": .string("n1"),
            "selections": .array([.object_([
                "credential_query_id": .string("q1"), "credential_id": .string("7"),
                "disclosed_claims": .array([.string("given_name")]),
            ])]),
            "response_uri": .string("https://v/r"),
            "verifier_jwk_thumbprint": .string(""), "verifier_session_id": .string(""),
            "transaction_data": .array([]), "selection_handle": .null_,
        ]
    }

    func testPresentationAskAnswersTheVpToken() async throws {
        let ctx = AskPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onVpRequest: { parentId, params in
                XCTAssertEqual("p-5", parentId)
                XCTAssertEqual("verifier", params.audience)
                XCTAssertEqual("n1", params.nonce)
                XCTAssertEqual("7", params.selections.first?.credentialId)
                return EngineVpResult(vpToken: "tok.a~b")
            }
        ))
        profile.initialize(ctx: ctx)
        await profile.runChildFlow(params: childStart(
            flowType: WmpSubFlowTypes.presentation, childId: "p-5::presentation::1", payload: vpPayload()
        ))
        XCTAssertEqual("tok.a~b", answerResult(ctx, index: 0)["vp_token"]?.stringValue)
    }

    /// A user decline at the sign stage is the structured `SIGN_REFUSED`, never a flow
    /// error (the verifier must learn it was `access_denied`).
    func testUserDeclineIsTheStructuredSignRefused() async throws {
        let ctx = AskPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onVpRequest: { _, _ in
                EngineVpResult(refusalCode: EngineVpResult.signRefused)
            }
        ))
        profile.initialize(ctx: ctx)
        await profile.runChildFlow(params: childStart(
            flowType: WmpSubFlowTypes.presentation, childId: "p-5::presentation::1", payload: vpPayload()
        ))
        let result = answerResult(ctx, index: 0)
        XCTAssertEqual(EngineVpResult.signRefused, result["refusal"]?.objectValue?["code"]?.stringValue)
        XCTAssertTrue(ctx.notifications.allSatisfy { $0.method != WmpMethods.flowError })
    }

    /// A thrown error is the generic flow error on the child (the engine reads it as a
    /// refusal); the structured refusal is the result, never this.
    func testAThrowingVpHandlerReachesTheEngineAsAFlowError() async throws {
        let ctx = AskPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onVpRequest: { _, _ in
                throw NSError(domain: "test", code: 1)
            }
        ))
        profile.initialize(ctx: ctx)
        await profile.runChildFlow(params: childStart(
            flowType: WmpSubFlowTypes.presentation, childId: "p-5::presentation::1", payload: vpPayload()
        ))
        XCTAssertTrue(ctx.notifications.contains { $0.method == WmpMethods.flowError },
                      "a failed handler is the flow error; the DECLINE is the structured result")
    }

    // ── dpop_proof ────────────────────────────────────────────────────────────

    /// The proof answers; "unavailable" is the empty string (the engine falls back to
    /// its own key).
    func testDpopProofAskAnswersProofAndUnavailableAsEmpty() async throws {
        let ctx = AskPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onDpopProof: { parentId, params in
                XCTAssertEqual("p-6", parentId)
                XCTAssertEqual("POST", params.htm)
                XCTAssertEqual("https://as.example/token", params.htu)
                return params.keyId == "dpop-1" ? EngineDpopProofResult(proof: "proof.jwt") : EngineDpopProofResult(proof: nil)
            }
        ))
        profile.initialize(ctx: ctx)
        await profile.runChildFlow(params: childStart(
            flowType: WmpSubFlowTypes.dpopProof, childId: "p-6::dpop_proof::1",
            payload: [
                "flow_id": .string("p-6"), "key_id": .string("dpop-1"),
                "htm": .string("POST"), "htu": .string("https://as.example/token"),
                "access_token": .string(""), "nonce": .string(""),
            ]
        ))
        XCTAssertEqual("proof.jwt", answerResult(ctx, index: 0)["proof"]?.stringValue)

        await profile.runChildFlow(params: childStart(
            flowType: WmpSubFlowTypes.dpopProof, childId: "p-6::dpop_proof::2",
            payload: [
                "flow_id": .string("p-6"), "key_id": .null_,
                "htm": .string("POST"), "htu": .string("https://as.example/token"),
                "access_token": .string(""), "nonce": .string(""),
            ]
        ))
        XCTAssertEqual("", answerResult(ctx, index: 1)["proof"]?.stringValue)
    }

    // ── attestation ───────────────────────────────────────────────────────────

    func testAttestationAskAnswersWiaAndPop() async throws {
        let ctx = AskPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onAttestation: { parentId, params in
                XCTAssertEqual("p-7", parentId)
                XCTAssertEqual("https://as.example/token", params.audience)
                XCTAssertEqual("client-1", params.clientId)
                return EngineAttestationResult(wia: "wia.jwt", pop: "pop.jwt")
            }
        ))
        profile.initialize(ctx: ctx)
        await profile.runChildFlow(params: childStart(
            flowType: WmpSubFlowTypes.attestation, childId: "p-7::attestation::1",
            payload: [
                "flow_id": .string("p-7"), "audience": .string("https://as.example/token"),
                "client_id": .string("client-1"), "challenge": .string(""),
            ]
        ))
        let result = answerResult(ctx, index: 0)
        XCTAssertEqual("wia.jwt", result["wia"]?.stringValue)
        XCTAssertEqual("pop.jwt", result["pop"]?.stringValue)
    }

    // ── match: the dialect fork ───────────────────────────────────────────────

    /// A `match` ask without `parent_flow_id` answers `selections` (the wallet's own
    /// credential ids) — the Rust engine's dialect — and no `credentials_matched`
    /// action exists in it.
    func testMatchAskWithoutParentFlowIdAnswersFullSelections() async throws {
        let ctx = AskPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onMatchRequest: { parentId, _ in
                XCTAssertEqual("p-8", parentId)
                return MatchResult(matches: [
                    CredentialMatch(credentialQueryId: "q1", credentialId: "7", format: "vc+sd-jwt", vct: nil, availableClaims: ["given_name"]),
                ])
            }
        ))
        profile.initialize(ctx: ctx)
        await profile.runChildFlow(params: childStart(
            flowType: WmpSubFlowTypes.match, childId: "p-8::match::1",
            payload: [
                "flow_id": .string("p-8"),
                "dcql_query": .object_([:]),
                "verifier": .object_(["name": .string("V"), "client_id": .string("v")]),
                "transaction_data": .array([]),
            ]
        ))
        let selection = answerResult(ctx, index: 0)["selections"]?.arrayValue?.first?.objectValue
        XCTAssertEqual("q1", selection?["credential_query_id"]?.stringValue)
        XCTAssertEqual("7", selection?["credential_id"]?.stringValue)
        XCTAssertEqual("given_name", selection?["disclosed_claims"]?.arrayValue?.first?.stringValue)
        XCTAssertTrue(ctx.notifications.allSatisfy { $0.method != WmpMethods.flowAction },
                      "the Rust engine ends the flow itself on empty selections")
    }

    // ── the child-id parent fallback ──────────────────────────────────────────

    /// A `tx_code` ask whose params lost their `flow_id` still finds its parent in the
    /// child id's own `<parent>::<type>::<seq>` shape.
    func testParentComesFromTheChildIdPrefixWhenParamsCarryNoFlowId() async throws {
        let ctx = AskPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onTxCode: { parentId in
                XCTAssertEqual("flow-abc", parentId)
                return "9999"
            }
        ))
        profile.initialize(ctx: ctx)
        // No params at all: the child id alone names the parent.
        await profile.runChildFlow(params: childStart(
            flowType: WmpSubFlowTypes.txCode, childId: "flow-abc::tx_code::1", payload: nil
        ))
        XCTAssertEqual("9999", answerResult(ctx, index: 0)["tx_code"]?.stringValue)
    }
}
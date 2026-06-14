// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosTransport
import SirosKeystore

/// Manages OID4VCI and OID4VP flows over a WMP session.
///
/// Translates WMP flow notifications into `FlowEvent`s for the SDK consumer.
/// When `autoSign` is enabled, automatically handles sign_request events
/// using the provided `KeystoreManager`. When disabled, the consumer must
/// call `respondToSignRequest` manually.
public final class FlowClient: @unchecked Sendable {

    private let session: WmpSession
    private let keystore: KeystoreManager
    private let autoSign: Bool
    private let lock = NSLock()
    private var continuations: [String: AsyncStream<FlowEvent>.Continuation] = [:]

    public init(session: WmpSession, keystore: KeystoreManager, autoSign: Bool = true) {
        self.session = session
        self.keystore = keystore
        self.autoSign = autoSign
    }

    /// Flow events stream.
    public func events() -> AsyncStream<FlowEvent> {
        let id = UUID().uuidString
        return AsyncStream<FlowEvent> { continuation in
            lock.lock()
            continuations[id] = continuation
            lock.unlock()
            continuation.onTermination = { [weak self] _ in
                self?.lock.lock()
                self?.continuations.removeValue(forKey: id)
                self?.lock.unlock()
            }
        }
    }

    /// Start listening for flow notifications from the WMP session.
    public func start() {
        Task { [weak self] in
            guard let self else { return }
            for await notification in self.session.notifications() {
                await self.handleNotification(notification)
            }
        }
    }

    /// Start an OID4VCI credential issuance flow.
    public func startIssuance(params: OID4VCIFlowParams) async throws -> String {
        let flowId = UUID().uuidString.lowercased()
        var flowParams: [String: AnyCodable] = [
            "flow_type": "issuance",
            "flow_id": .string(flowId),
        ]
        if let uri = params.credentialOfferUri {
            flowParams["credential_offer_uri"] = .string(uri)
        }
        if let url = params.issuerUrl {
            flowParams["issuer_url"] = .string(url)
        }
        _ = try await session.sendRequest(method: "wmp.flow.start", params: flowParams)
        return flowId
    }

    /// Start an OID4VP verifiable presentation flow.
    public func startPresentation(params: OID4VPFlowParams) async throws -> String {
        let flowId = UUID().uuidString.lowercased()
        var flowParams: [String: AnyCodable] = [
            "flow_type": "presentation",
            "flow_id": .string(flowId),
        ]
        if let uri = params.requestUri {
            flowParams["request_uri"] = .string(uri)
        }
        _ = try await session.sendRequest(method: "wmp.flow.start", params: flowParams)
        return flowId
    }

    /// Send a flow action (e.g., user consent, credential selection).
    public func sendAction(flowId: String, action: String, payload: [String: AnyCodable]? = nil) async throws {
        var params: [String: AnyCodable] = [
            "flow_id": .string(flowId),
            "action": .string(action),
        ]
        if let payload { params["params"] = .object_(payload) }
        _ = try await session.sendRequest(method: "wmp.flow.action", params: params)
    }

    /// Respond to a sign request (when autoSign is disabled).
    public func respondToSignRequest(flowId: String, messageId: String, response: SignResponse) async throws {
        var params: [String: AnyCodable] = [
            "flow_id": .string(flowId),
            "message_id": .string(messageId),
        ]
        if let jwt = response.proofJwt { params["proof_jwt"] = .string(jwt) }
        if let vp = response.vpToken { params["vp_token"] = .string(vp) }
        try await session.sendNotification(method: "wmp.flow.action", params: params)
    }

    /// Respond to a match request.
    public func respondToMatchRequest(flowId: String, messageId: String, response: MatchResponse) async throws {
        let params: [String: AnyCodable] = [
            "flow_id": .string(flowId),
            "message_id": .string(messageId),
            "credential_ids": .array(response.credentialIds.map { .string($0) }),
        ]
        try await session.sendNotification(method: "wmp.flow.action", params: params)
    }

    // MARK: - Private

    private func emit(_ event: FlowEvent) {
        lock.lock()
        let conts = Array(continuations.values)
        lock.unlock()
        for c in conts { c.yield(event) }
    }

    private func handleNotification(_ notification: JsonRpcRequest) async {
        guard let params = notification.params,
              let flowId = params["flow_id"]?.stringValue else { return }

        switch notification.method {
        case "wmp.flow.progress":
            let step = params["step"]?.stringValue ?? ""
            let payload = params["payload"]?.objectValue
            emit(.progress(flowId: flowId, step: step, payload: anyCodableDictToAny(payload)))

            if step == "sign_request" {
                await handleSignRequest(flowId: flowId, params: params)
            }
            if step == "match_request" {
                await handleMatchRequest(flowId: flowId, params: params)
            }

        case "wmp.flow.complete":
            let result = params["result"]?.objectValue
            emit(.complete(flowId: flowId, result: anyCodableDictToAny(result)))

        case "wmp.flow.error":
            let code = params["code"]?.stringValue
            let message = params["message"]?.stringValue
            emit(.error(flowId: flowId, code: code, message: message))

        default:
            break
        }
    }

    private func handleSignRequest(flowId: String, params: [String: AnyCodable]) async {
        guard let messageId = params["message_id"]?.stringValue,
              let payload = params["payload"]?.objectValue,
              let actionStr = payload["action"]?.stringValue,
              let action = SignAction(rawValue: actionStr) else { return }

        let signParams = SignParams(
            audience: payload["audience"]?.stringValue,
            nonce: payload["nonce"]?.stringValue,
            issuer: payload["issuer"]?.stringValue,
            responseUri: payload["response_uri"]?.stringValue,
            credentialsToInclude: payload["credentials_to_include"]?.arrayValue?.compactMap {
                anyCodableDictToAny($0.objectValue) as? [String: Any]
            }
        )

        if autoSign {
            do {
                let response: SignResponse
                switch action {
                case .generateProof:
                    let proof = try await keystore.generateProof(
                        audience: signParams.audience ?? "",
                        nonce: signParams.nonce ?? ""
                    )
                    response = SignResponse(proofJwt: proof)

                case .signPresentation:
                    let credIds = signParams.credentialsToInclude?.compactMap {
                        $0["credential_id"] as? String
                    } ?? []
                    let vp = try await keystore.signPresentation(
                        nonce: signParams.nonce ?? "",
                        audience: signParams.audience ?? "",
                        credentialIds: credIds
                    )
                    response = SignResponse(vpToken: vp)
                }
                try await respondToSignRequest(flowId: flowId, messageId: messageId, response: response)
            } catch {
                emit(.signRequest(flowId: flowId, messageId: messageId, action: action, params: signParams))
            }
        } else {
            emit(.signRequest(flowId: flowId, messageId: messageId, action: action, params: signParams))
        }
    }

    private func handleMatchRequest(flowId: String, params: [String: AnyCodable]) async {
        guard let messageId = params["message_id"]?.stringValue,
              let payload = params["payload"]?.objectValue,
              let dcqlQuery = payload["dcql_query"]?.objectValue else { return }
        emit(.matchRequest(flowId: flowId, messageId: messageId, dcqlQuery: anyCodableDictToAny(dcqlQuery) as? [String: Any] ?? [:]))
    }

    /// Convert an AnyCodable dictionary to [String: Any] for the public API.
    private func anyCodableDictToAny(_ dict: [String: AnyCodable]?) -> [String: Any]? {
        guard let dict else { return nil }
        var result: [String: Any] = [:]
        for (k, v) in dict {
            result[k] = anyCodableToAny(v)
        }
        return result
    }

    private func anyCodableToAny(_ value: AnyCodable) -> Any {
        switch value {
        case .string(let s): return s
        case .int(let i): return i
        case .double(let d): return d
        case .bool(let b): return b
        case .object_(let obj):
            var result: [String: Any] = [:]
            for (k, v) in obj { result[k] = anyCodableToAny(v) }
            return result
        case .array(let arr): return arr.map { anyCodableToAny($0) }
        case .null_: return NSNull()
        }
    }
}

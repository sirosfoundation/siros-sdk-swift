// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

#if canImport(EngineAdapterSdk)
import EngineAdapterSdk

/// The LOCAL engine's trust stack: the backend proxy's PDP routes
/// (`/v1/evaluate`, `/v1/resolve`) - the same routes the REMOTE engine's
/// deployment trusts server-side (its `ENGINE_PDP_URL`). The local engine
/// evaluates in-process, so its trust crosses this port: the sample app's
/// own answer to "is this issuer/verifier trusted".
///
/// The routes are TAC-gated: a `wallet-backend`-audience bearer with `tac`
/// covering `r` passes - exactly the wallet's own backend token, carried by
/// `bearerProvider` (a fresh mint per call, the wallet's cached-until-expired
/// manager behind it).
///
/// The wire shape mirrors siros-wallet-core's server adapter
/// (`engine-adapter-server/ports.rs`): subject `{type: "key", id}`,
/// resource `{type: jwk|x5c|kid, id, key}`, action `{name:
/// credential-issuer | credential-verifier}` - the backend proxy's allowed
/// set. Fail closed: a route error or an unparseable answer is a refusal,
/// never a permit.
///
/// The `#if canImport(EngineAdapterSdk)` guard matches
/// `WmpUniFFITransport.swift`'s: the trust port's protocol lives in the
/// engine bindings, which ride the iOS-scoped XCFramework.
final class ProxyPdp: Pdp {

    private let baseUrl: String
    private let bearerProvider: @Sendable () async throws -> String?
    private let session: URLSession

    init(
        baseUrl: String,
        bearerProvider: @escaping @Sendable () async throws -> String?,
        session: URLSession = .shared
    ) {
        self.baseUrl = baseUrl
        self.bearerProvider = bearerProvider
        self.session = session
    }

    func evaluate(request: EvaluationRequest) async throws -> EvaluationResponse {
        // One binding: `try?` on the optional-returning provider already
        // flattens to a single optional (nil covers both a thrown error and
        // a nil bearer) - fail closed either way.
        guard let bearer = try? await bearerProvider() else {
            return EvaluationResponse(trusted: false, decision: "no bearer for the PDP routes")
        }
        var body: [String: Any] = [
            "subject": ["type": "key", "id": request.subject],
            "resource": [
                "type": Self.keyMaterialType(request.keyMaterial),
                "id": request.subject,
                "key": Self.keyMaterialValue(request.keyMaterial),
            ],
            "action": ["name": request.resourceType ?? "credential-issuer"],
        ]
        // The evaluation's context as the engine serialized it (raw JSON
        // text; an empty string is the empty context).
        if !request.context.isEmpty, let context = Self.jsonObject(request.context.data(using: .utf8)) {
            body["context"] = context
        }
        guard
            let answer = await post("/v1/evaluate", bearer: bearer, body: body),
            let parsed = Self.jsonObject(answer.data(using: .utf8))
        else {
            return EvaluationResponse(trusted: false, decision: "the PDP route did not answer")
        }
        let trusted = (parsed["decision"] as? Bool) ?? false
        return EvaluationResponse(trusted: trusted, decision: Self.reasonMessage(parsed["context"]))
    }

    func resolve(request: ResolveRequest) async throws -> ResolveResponse {
        guard let bearer = try? await bearerProvider() else {
            return ResolveResponse(metadata: Data(), trustInfo: nil)
        }
        let body: [String: Any] = [
            "subject_id": request.uri,
            "subject_type": request.resourceType == "did_document" ? "key" : "url",
            "resource_type": request.resourceType,
        ]
        guard
            let answer = await post("/v1/resolve", bearer: bearer, body: body),
            let parsed = Self.jsonObject(answer.data(using: .utf8))
        else {
            return ResolveResponse(metadata: Data(), trustInfo: nil)
        }
        let context = parsed["context"] as? [String: Any]
        guard let node = context?["trust_metadata"] ?? parsed["metadata"] else {
            return ResolveResponse(metadata: Data(), trustInfo: nil)
        }
        // The resolved document rides as raw JSON text bytes (the engine's
        // server adapter hands the metadata through verbatim).
        if let data = node as? Data {
            return ResolveResponse(metadata: data, trustInfo: nil)
        }
        if let string = node as? String {
            return ResolveResponse(metadata: Data(string.utf8), trustInfo: nil)
        }
        if JSONSerialization.isValidJSONObject(node),
           let data = try? JSONSerialization.data(withJSONObject: node) {
            return ResolveResponse(metadata: data, trustInfo: nil)
        }
        return ResolveResponse(metadata: Data(), trustInfo: nil)
    }

    /// The proxy has no entitlement route (the backend's PDP surface is
    /// evaluate + resolve): answer the engine's NOT-EVALUATED decision -
    /// allowed, OFF mode, nothing checked - the same shape a PdpError
    /// NotImplemented maps to (ARF 6.6.2.3's grace: no answer is no
    /// evaluation, nothing refused).
    func evaluateEntitlement(request: EntitlementRequest) async throws -> EntitlementDecision {
        EntitlementDecision(
            allowed: true,
            mode: .off,
            evaluated: false,
            findings: [],
            findingsTruncated: false
        )
    }

    // MARK: - plumbing

    private func post(_ path: String, bearer: String, body: [String: Any]) async -> String? {
        guard let url = URL(string: baseUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + path),
              let payload = try? JSONSerialization.data(withJSONObject: body)
        else { return nil }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(bearer)", forHTTPHeaderField: "Authorization")
        request.httpBody = payload
        guard let (data, response) = try? await session.data(for: request),
              let http = response as? HTTPURLResponse, http.statusCode == 200
        else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func jsonObject(_ data: Data?) -> [String: Any]? {
        guard let data else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }

    /// The proxy's decision reason, either shape: an array of findings or a
    /// single object, each carrying a `message`.
    private static func reasonMessage(_ context: Any?) -> String? {
        guard let context = context as? [String: Any], let reason = context["reason"] else { return nil }
        if let list = reason as? [[String: Any]] {
            return list.first?["message"] as? String
        }
        if let object = reason as? [String: Any] {
            return object["message"] as? String
        }
        return nil
    }

    /// The resource type the proxy accepts (its allowed set): a JSON object
    /// is a `jwk`, a `did:` string a `kid`, anything else `x5c`.
    private static func keyMaterialType(_ keyMaterial: Data) -> String {
        if jsonObject(keyMaterial) != nil { return "jwk" }
        let raw = String(decoding: keyMaterial, as: UTF8.self)
        if raw.hasPrefix("did:") { return "kid" }
        return "x5c"
    }

    /// The resource key: the parsed JSON as-is (a JWK), or the raw material.
    private static func keyMaterialValue(_ keyMaterial: Data) -> Any {
        if let object = jsonObject(keyMaterial) { return object }
        return String(decoding: keyMaterial, as: UTF8.self)
    }
}

#endif

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosTransport

// The Swift port of Kotlin's `CircuitZkMatching.kt` (#277 piece 1): the
// plan/filter/circuit types, the shared-matcher planner, and the
// shared-matcher serving. The prover/pseudonym/predicate machinery already
// exists in `CircuitZk/` (`CircuitZkFunction`, `PresentationConsentBuilder`,
// `NymAuthNativeProver`) — this file is the MATCH side that feeds it.
//
// Reference: `siros-sdk-kotlin` #404/#405 (device-validated end-to-end
// 2026-11-14), over the `siros-dc-matcher` FFI (`zkpReqPlan`,
// `matchDcqlWithContext`, `SirosBlobBuilder` — vendored, loading).
//
// The wallet's JSON currency here is `AnyCodable` (the matcher call sites');
// `CircuitZkFunction.params` is `JSONValue` (the existing type the consent
// builder consumes) — the bridge is `jsonValue(_:)` below.
//
// The FFI-touching halves (`SharedCircuitZkPlanner.planner`,
// `sharedCircuitZkServing`) are `#if canImport(siros_dc_matcher_ffiFFI)`-gated
// exactly as the generated module is: a macOS/Linux build (no FFI slices)
// compiles the engine out — the same gate `SharedDcqlMatcher` uses.

/// A request's circuit list: the verifier's two independent lists
/// (`proof_system_values`, `system_id_values`), kept as two lists. A circuit
/// is admitted when its system is in `proofSystems` AND its id (or an alias)
/// is in `circuitIds`; a list the verifier did not send is nil and constrains
/// nothing, and a list sent empty admits nothing.
///
/// They are deliberately not expanded into the pairs they imply: both lists
/// are verifier-controlled and planned before the trust decision, so their
/// product is an allocation an untrusted request could make arbitrarily
/// large. Membership needs only the two lists.
public struct CircuitZkCircuitFilter: Equatable {
    public let proofSystems: [String]?
    public let circuitIds: [String]?

    public init(proofSystems: [String]?, circuitIds: [String]?) {
        self.proofSystems = proofSystems
        self.circuitIds = circuitIds
    }

    /// Whether `circuit` is one this filter names (its id, or an alias).
    public func admits(_ circuit: CircuitZkCircuit) -> Bool {
        if let systems = proofSystems, !systems.contains(circuit.offeredProofSystem) { return false }
        if let ids = circuitIds {
            guard ids.contains(circuit.circuitId) || circuit.aliases.contains(where: ids.contains) else { return false }
        }
        return true
    }

    /// The `circuit_id` a response must state for `circuit`: one the request
    /// OFFERED (its id, else an alias). Nil when the request stated no
    /// circuit-id list or names neither — a request that offered nothing
    /// cannot be answered.
    public func offeredCircuitId(_ circuit: CircuitZkCircuit) -> String? {
        guard let ids = circuitIds else { return nil }
        return ids.contains(circuit.circuitId) ? circuit.circuitId : circuit.aliases.first { ids.contains($0) }
    }

    /// Whether the request accepts `circuit`'s proof system:
    /// `proof_system_values` is OPTIONAL, so no list accepts any.
    public func offersProofSystem(_ circuit: CircuitZkCircuit) -> Bool {
        proofSystems?.contains(circuit.offeredProofSystem) ?? true
    }
}

/// What a `circuit_zk` credential query asks for, as plain data: the
/// matcher's plan, without its types. `circuitFilter` is the verifier's own
/// list of acceptable circuits: nil means the verifier named none (any
/// circuit fits), and an EMPTY list in either of its two lists means it named
/// an empty list, which no circuit satisfies (the matcher's reading). `raw`
/// is the credential query the plan was made from.
public struct CircuitZkPlan {
    public let functions: [CircuitZkFunction]
    public let circuitFilter: CircuitZkCircuitFilter?
    public let raw: [String: AnyCodable]

    public init(
        functions: [CircuitZkFunction],
        circuitFilter: CircuitZkCircuitFilter? = nil,
        raw: [String: AnyCodable] = [:]
    ) {
        self.functions = functions
        self.circuitFilter = circuitFilter
        self.raw = raw
    }

    /// `meta.source_format`: the format of the attestation the proof is made
    /// over (`mso_mdoc`; `bbs_cd` is held). A hand-made plan without it is
    /// read as `mso_mdoc`, the only format this SDK stores.
    public var sourceFormat: String {
        let format = (raw["meta"]?.objectValue?["source_format"]?.stringValue) ?? ""
        return format.isEmpty ? "mso_mdoc" : format
    }

    /// `meta.doctype_value`, as the candidates' gate reads it. Empty when the
    /// plan carries none.
    public var docType: String {
        (raw["meta"]?.objectValue?["doctype_value"]?.stringValue) ?? ""
    }
}

/// The result of `CircuitZkPlanner.plan`.
public enum CircuitZkPlanResult {
    /// The query is a well-formed `circuit_zk` request.
    case plan(CircuitZkPlan)
    /// It is not. The wallet matches nothing.
    case invalidRequest
}

/// Turns a `circuit_zk` credential query into a `CircuitZkPlan`. The default
/// implementation, backed by the shared matcher, is
/// `SharedCircuitZkPlanner.planner`; tests use a fake.
public typealias CircuitZkPlanner =
    (_ credentialQuery: [String: AnyCodable], _ clientMetadata: [String: AnyCodable]?) -> CircuitZkPlanResult

/// The wallet's verdict on a plan. `AccessDenied.ruleId` is for local logs
/// and tests only and never leaves the wallet.
public enum CircuitZkVerdict {
    case ok
    case accessDenied(ruleId: String?)
}

/// Where the rulebook's satisfiability rules run in the wallet. Injected.
public typealias CircuitZkRequestValidator = (CircuitZkPlan) -> CircuitZkVerdict

/// The permissive default validator: accepts every plan, until real rules
/// are injected.
public let permissiveCircuitZkValidator: CircuitZkRequestValidator = { _ in .ok }

/// A circuit this wallet can prove with. `functions` is nil when the catalog
/// does not say which functions the circuit supports, in which case no
/// function filtering applies to it.
///
/// `credentialType` and `capabilities` are opaque strings passed to the
/// matcher when the circuit is registered (siros-dc-matcher 0.10.0) and
/// never read by the SDK. `credentialType` restricts the circuit to a
/// request naming that doctype or vct. `capabilities` is the catalog's
/// `capabilities` object as a JSON string; when present the matcher applies
/// its capability rule and reads neither `functions` nor `credentialType`.
/// A value the matcher cannot parse leaves the circuit not offered.
public struct CircuitZkCircuit {
    public let system: String
    public let circuitId: String
    public let docTypes: Set<String>
    public let functions: Set<String>?
    public let aliases: Set<String>
    public let credentialType: String?
    public let capabilities: String?
    /// The catalog `systemVersion`, for a prover that gates per
    /// (system, version); nil when the source does not know it.
    public let systemVersion: String?
    /// The proof-system identity offered to verifiers (the catalog's
    /// `proofSystem`), registered with the matcher and compared with
    /// `proof_system_values`. Nil for a hand-made circuit: `system` is then
    /// the identity (`offeredProofSystem`).
    public let proofSystem: String?

    public init(
        system: String,
        circuitId: String,
        docTypes: Set<String>,
        functions: Set<String>? = nil,
        aliases: Set<String> = [],
        credentialType: String? = nil,
        capabilities: String? = nil,
        systemVersion: String? = nil,
        proofSystem: String? = nil
    ) {
        self.system = system
        self.circuitId = circuitId
        self.docTypes = docTypes
        self.functions = functions
        self.aliases = aliases
        self.credentialType = credentialType
        self.capabilities = capabilities
        self.systemVersion = systemVersion
        self.proofSystem = proofSystem
    }

    /// The proof system a verifier sees: `proofSystem`, else `system`.
    public var offeredProofSystem: String { proofSystem ?? system }

    /// Whether the matcher, not this SDK, decides if the circuit serves a
    /// request: it declares `capabilities` or a `credentialType`.
    public var constrainedByMatcher: Bool { capabilities != nil || credentialType != nil }

    /// Whether this circuit can prove `plan` for a credential of `docType`:
    /// the doctype is one it serves, it is in the verifier's circuit list
    /// (if any), and it supports every planned function (if it declares any).
    ///
    /// A circuit that declares `capabilities` or a `credentialType` is never
    /// treated as unrestricted: this overload has no matcher to ask, so such
    /// a circuit does not fit. Use the overload taking a `CircuitZkServing`.
    public func supports(_ plan: CircuitZkPlan, docType: String) -> Bool {
        supports(plan, docType: docType, serving: nil)
    }

    /// As `supports`, with `serving` to ask the matcher whether a circuit
    /// that declares `capabilities` or a `credentialType` serves the
    /// request. The matcher is the only judge of that rule; without an
    /// answer (`serving` nil, or it returns nil) the circuit does not fit.
    public func supports(_ plan: CircuitZkPlan, docType: String, serving: CircuitZkServing?) -> Bool {
        docTypes.contains(docType) && CircuitZkMatching.fits(self, plan: plan, docType: docType, serving: serving)
    }
}

/// Whether the matcher offers `circuit` for a `circuit_zk` credential query
/// over a credential of `docType`: its capability rule, asked rather than
/// reimplemented. Nil means the matcher could not answer, which callers treat
/// as "no" (fail closed).
public typealias CircuitZkServing =
    (_ circuit: CircuitZkCircuit, _ docType: String, _ query: [String: AnyCodable]) -> Bool?

/// Everything the matcher needs to answer a `circuit_zk` query. The members
/// are non-nil by construction (see `init` defaults); a wallet that has not
/// turned the feature on passes no `CircuitZkSupport` at all.
public struct CircuitZkSupport {
    public let planner: CircuitZkPlanner
    public let validator: CircuitZkRequestValidator
    public let circuits: () -> [CircuitZkCircuit]
    /// Asks the matcher whether a circuit with `capabilities` or a
    /// `credential_type` serves a request; nil: none does.
    public let serving: CircuitZkServing?

    public init(
        planner: @escaping CircuitZkPlanner,
        validator: @escaping CircuitZkRequestValidator = permissiveCircuitZkValidator,
        circuits: @escaping () -> [CircuitZkCircuit],
        serving: CircuitZkServing? = sharedCircuitZkServing
    ) {
        self.planner = planner
        self.validator = validator
        self.circuits = circuits
        self.serving = serving
    }
}

#if canImport(siros_dc_matcher_ffiFFI)
import siros_dc_matcher_ffiFFI
import Generated

/// `CircuitZkServing` by the shared matcher, the engine the OS picker runs:
/// the circuit and a claimless credential of the doctype are registered in a
/// throwaway blob, and the request is matched against it. No capability rule
/// lives in this SDK.
public let sharedCircuitZkServing: CircuitZkServing = { circuit, docType, query in
    do {
        // The matcher registrations that declare `circuit`: one per id it
        // answers to (its id, then each alias).
        let capabilities = ([circuit.circuitId] + circuit.aliases.sorted()).map { id in
            var params: [String: String] = ["system_id": id]
            if let functions = circuit.functions { params["functions"] = functions.sorted().joined(separator: ",") }
            if let credentialType = circuit.credentialType { params["credential_type"] = credentialType }
            if let capabilities = circuit.capabilities { params["capabilities"] = capabilities }
            return FfiCapability(system: circuit.offeredProofSystem, params: params)
        }
        // `SirosBlobBuilder()` and `addCredential` are declared infallible in
        // Rust, so a panic there would trap rather than reach the catch —
        // see SharedDcqlMatcher's identical note; the two fallible calls
        // (`build()`, `matchDcqlWithContext`) are what the catch is for.
        let builder = SirosBlobBuilder()
        for capability in capabilities { builder.addZkpReqSystem(capability: capability) }
        builder.addCredential(credential: FfiCredential(
            id: "1", format: "mso_mdoc", doctype: docType, vct: nil,
            title: docType, subtitle: "", iconId: nil, claims: []
        ))
        let blob = try builder.build()
        let dcql = CircuitZkMatching.jsonText(["credentials": [.array([AnyCodable.object_(query)])]])
        let outcome = try matchDcqlWithContext(blob: blob, dcqlJson: dcql, clientMetadataJson: nil)
        return outcome.satisfiable && outcome.matches.contains { !$0.credentials.isEmpty }
    } catch {
        // No native library, or a request the matcher rejects: no answer,
        // which is a no.
        return nil
    }
}

/// The shared-matcher planner (#277 piece 1's core): `zkpReqPlan` over the
/// vendored binding, with the plan JSON read into `CircuitZkPlan`.
public enum SharedCircuitZkPlanner {
    /// The planner as a `CircuitZkPlanner` function.
    public static let planner: CircuitZkPlanner = { credentialQuery, clientMetadata in
        do {
            let queryText = try CircuitZkMatching.encode(credentialQuery)
            let metadataText = try clientMetadata.map(CircuitZkMatching.encode)
            let planText = try zkpReqPlan(credentialQueryJson: queryText, clientMetadataJson: metadataText)
            guard let planObject = CircuitZkMatching.decodeObject(planText) else { return .invalidRequest }
            return Self.toPlan(planObject).map(CircuitZkPlanResult.plan) ?? .invalidRequest
        } catch {
            return .invalidRequest
        }
    }

    /// The matcher's plan JSON as a `CircuitZkPlan`. Its two independent
    /// circuit lists become a `CircuitZkCircuitFilter`, which keeps them as
    /// two lists: one not sent is nil, one sent empty admits no circuit.
    ///
    /// Nil when the JSON is not a plan.
    static func toPlan(_ plan: [String: AnyCodable]) -> CircuitZkPlan? {
        guard let rawFunctions = plan["functions"]?.arrayValue else { return nil }
        var functions: [CircuitZkFunction] = []
        for element in rawFunctions {
            guard let o = element.objectValue,
                  let id = o["function_id"]?.stringValue, !id.isEmpty,
                  let handle = o["handle"]?.stringValue, !handle.isEmpty else { return nil }
            let params = (o["params"]?.objectValue ?? [:]).mapValues { CircuitZkMatching.jsonValue($0) }
            functions.append(CircuitZkFunction(id: id, handle: handle, params: params))
        }
        let filterObject = plan["system_filter"]?.objectValue
        let proofSystems = filterObject?["proof_systems"]?.arrayValue?.compactMap { $0.stringValue }
        let circuitIds = filterObject?["system_ids"]?.arrayValue?.compactMap { $0.stringValue }
        // Not expanded into pairs: see `CircuitZkCircuitFilter`.
        let circuitFilter: CircuitZkCircuitFilter? =
            (proofSystems == nil && circuitIds == nil)
                ? nil
                : CircuitZkCircuitFilter(proofSystems: proofSystems, circuitIds: circuitIds)
        guard let raw = plan["raw"]?.objectValue else { return nil }
        return CircuitZkPlan(functions: functions, circuitFilter: circuitFilter, raw: raw)
    }
}
#else
/// The platforms without the matcher FFI slices: the serving is absent
/// (fail closed — no capability-constrained circuit is offered).
public let sharedCircuitZkServing: CircuitZkServing? = nil
#endif

/// The match-side engine (the Kotlin `CircuitZkMatching` object's core):
/// the plan/fits/serving rules the matcher call sites share.
public enum CircuitZkMatching {

    /// Everything a `circuit_zk` credential query asks, matched against the
    /// wallet's credentials and circuit table. Fails closed: a query the
    /// planner rejects (or the planner cannot answer) matches nothing.
    ///
    /// Returns the plan and the matched candidates (empty when nothing
    /// matched or the request is invalid — the callers treat both as
    /// no-match, exactly as the Kotlin twin does).
    public static func evaluate(
        query: [String: AnyCodable],
        clientMetadata: [String: AnyCodable]?,
        credentials: [StoredCredential],
        support: CircuitZkSupport
    ) -> (plan: CircuitZkPlan, candidates: [StoredCredential])? {
        // 1. The plan (the shared matcher's): a query that is not a
        //    well-formed circuit_zk request matches nothing.
        guard case .plan(let plan) = support.planner(query, clientMetadata) else { return nil }
        // 2. The rulebook's satisfiability verdict.
        if case .accessDenied = support.validator(plan) { return nil }
        // 3. The candidates: a credential of the doctype the plan names, in
        //    the mso_mdoc form the planner declared.
        let docType = plan.docType
        let candidates: [StoredCredential] = (plan.sourceFormat == "mso_mdoc" && !docType.isEmpty)
            ? credentials.filter { SharedDcqlMatcher.docType(for: $0) == docType }
            : []
        // 4. A circuit that fits: the verifier's list (if any) admits it, it
        //    serves the doctype, the prover admits the plan. A response
        //    states one of its OFFERED ids — none offered: no match.
        let filter = plan.circuitFilter
        let answering = support.circuits().filter { circuit in
            circuit.supports(plan, docType: docType, serving: support.serving) &&
                filter?.offeredCircuitId(circuit) != nil &&
                (filter?.offersProofSystem(circuit) ?? true)
        }
        guard !answering.isEmpty else { return nil }
        return (plan, candidates)
    }

    /// Whether the matcher offers `circuit` for the plan: the filter admits
    /// it, and (for a circuit the matcher constrains) the serving answer is
    /// yes. A circuit that declares no functions and no capabilities fits
    /// nothing: it is not offered for circuit_zk unless a registered adapter
    /// claims it.
    static func fits(
        _ circuit: CircuitZkCircuit,
        plan: CircuitZkPlan,
        docType: String,
        serving: CircuitZkServing?
    ) -> Bool {
        if let filter = plan.circuitFilter, !filter.admits(circuit) { return false }
        if circuit.constrainedByMatcher {
            return serving?(circuit, docType, plan.raw) ?? false
        }
        guard let functions = circuit.functions else { return false }
        let planned = Set(plan.functions.map(\.id))
        return planned.isSubset(of: functions)
    }

    // ── The JSON plumbing (AnyCodable ↔ text/JSONValue ↔ the FFI) ──

    /// An object as JSON text (empty when unserialisable — the callers'
    /// fall-closed paths treat that as no-answer).
    static func encode(_ value: [String: AnyCodable]) throws -> String {
        let data = try JSONEncoder().encode(AnyCodable.object_(value))
        return String(data: data, encoding: .utf8) ?? ""
    }

    /// A JSON object's text, decoded; nil when it is not an object.
    static func decodeObject(_ text: String) -> [String: AnyCodable]? {
        guard let data = text.data(using: .utf8),
              let value = try? JSONDecoder().decode(AnyCodable.self, from: data) else { return nil }
        return value.objectValue
    }

    /// A query object as JSON text (the serving call's DCQL envelope).
    static func jsonText(_ object: [String: AnyCodable]) -> String {
        (try? encode(object)) ?? "{}"
    }

    /// One `AnyCodable` as the strict `JSONValue` the existing CircuitZk
    /// machinery consumes (the planner's bridge: the plan's params are
    /// `JSONValue`, the wallet's currency is `AnyCodable`).
    ///
    /// Numbers: `int` and `double` both carry over as themselves; the
    /// `decimal` case has no AnyCodable counterpart and is unreachable here.
    static func jsonValue(_ value: AnyCodable) -> JSONValue {
        switch value {
        case .string(let s): return .string(s)
        case .int(let i): return .int(Int64(i))
        case .double(let d): return .double(d)
        case .bool(let b): return .bool(b)
        case .null_: return .null
        case .object_(let o): return .object(o.mapValues { jsonValue($0) })
        case .array(let a): return .array(a.map { jsonValue($0) })
        }
    }
}
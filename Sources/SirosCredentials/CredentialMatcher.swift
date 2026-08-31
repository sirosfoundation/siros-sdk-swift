// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Client-side DCQL (Digital Credentials Query Language) matcher per OID4VP §6.
public enum CredentialMatcher {

    public struct MatchResult: Sendable, Equatable {
        public let queryId: String
        public let format: String?
        public let candidates: [StoredCredential]
        public let requestedClaims: [[String]]
        /// Parsed `meta.zk_system_type` (present only when `format` is
        /// `"mso_mdoc_zk"`) - the verifier's own list of acceptable ZK proof
        /// systems, in priority order, per multipaz's wire convention.
        /// Feed to `ZkProofSystem.matchingSpec`/`ZkProofSystemRegistry.resolve`
        /// to pick which one (if any) this wallet can actually satisfy.
        public let zkSystemTypes: [ZkSystemSpec]?
        /// Parsed `meta.ppid_context`, if the verifier supplied one - see
        /// `VerifierIdentity.ppidContext`'s doc comment. `nil` is a normal,
        /// common case (most requests won't set this).
        public let ppidContext: String?

        public init(
            queryId: String,
            format: String? = nil,
            candidates: [StoredCredential],
            requestedClaims: [[String]],
            zkSystemTypes: [ZkSystemSpec]? = nil,
            ppidContext: String? = nil
        ) {
            self.queryId = queryId
            self.format = format
            self.candidates = candidates
            self.requestedClaims = requestedClaims
            self.zkSystemTypes = zkSystemTypes
            self.ppidContext = ppidContext
        }
    }

    public struct CredentialSetQuery: Sendable, Equatable {
        public let options: [[String]]
        public let required: Bool

        public init(options: [[String]], required: Bool = true) {
            self.options = options
            self.required = required
        }
    }

    public struct SatisfiableOption: Sendable, Equatable {
        public let credentialSetIndex: Int
        public let optionIndex: Int
        public let queryIds: [String]

        public init(credentialSetIndex: Int, optionIndex: Int, queryIds: [String]) {
            self.credentialSetIndex = credentialSetIndex
            self.optionIndex = optionIndex
            self.queryIds = queryIds
        }
    }

    public struct DcqlMatchOutput: Sendable, Equatable {
        public let queryResults: [MatchResult]
        public let credentialSets: [CredentialSetQuery]?
        public let satisfiableOptions: [SatisfiableOption]

        public init(queryResults: [MatchResult], credentialSets: [CredentialSetQuery]?, satisfiableOptions: [SatisfiableOption]) {
            self.queryResults = queryResults
            self.credentialSets = credentialSets
            self.satisfiableOptions = satisfiableOptions
        }
    }

    // MARK: - Public API

    public static func match(dcqlQuery: [String: Any], credentials: [StoredCredential]) -> [MatchResult] {
        matchDcql(dcqlQuery: dcqlQuery, credentials: credentials).queryResults
    }

    public static func matchDcql(dcqlQuery: [String: Any], credentials: [StoredCredential]) -> DcqlMatchOutput {
        guard let credentialQueries = dcqlQuery["credentials"] as? [[String: Any]] else {
            return DcqlMatchOutput(
                queryResults: [MatchResult(
                    queryId: "_default",
                    format: nil,
                    candidates: credentials,
                    requestedClaims: []
                )],
                credentialSets: nil,
                satisfiableOptions: []
            )
        }

        let parsed = credentialQueries.compactMap { query in
            matchSingleQuery(query, credentials: credentials)
        }
        let queryResults = applySharedEngine(dcqlQuery: dcqlQuery, credentials: credentials, parsed: parsed)

        let credentialSets = parseCredentialSets(dcqlQuery)
        let satisfiableOptions: [SatisfiableOption]
        if let sets = credentialSets {
            satisfiableOptions = findSatisfiableOptions(credentialSets: sets, queryResults: queryResults)
        } else {
            satisfiableOptions = []
        }

        return DcqlMatchOutput(
            queryResults: queryResults,
            credentialSets: credentialSets,
            satisfiableOptions: satisfiableOptions
        )
    }

    /// Narrow the parsed results to what the shared engine says qualifies.
    ///
    /// Which credentials qualify is decided by the shared engine - the same one
    /// the Android credential picker runs, and the only implementation here
    /// tested against the specification's own examples. This matcher still
    /// parses everything else the wallet needs at presentation time (requested
    /// claims, `zk_system_type`, `ppid_context`), because those are read from
    /// the query rather than decided by it.
    ///
    /// The visible change is that a credential missing a claim the verifier
    /// asked for is no longer offered. OID4VP 1.0 §6.4.1 requires that; the
    /// parsing path never checked it, so such a credential would be offered,
    /// consented to, and then fail to satisfy the verifier.
    ///
    /// On platforms without the engine this returns `parsed` unchanged, which
    /// is what every platform did until now.
    private static func applySharedEngine(
        dcqlQuery: [String: Any],
        credentials: [StoredCredential],
        parsed: [MatchResult]
    ) -> [MatchResult] {
        #if os(iOS)
        guard let shared = SharedDcqlMatcher.evaluate(dcqlQuery: dcqlQuery, credentials: credentials) else {
            // No answer, not an empty answer. Falling back keeps presentations
            // working where the engine cannot decide, which is worth more than
            // consistency. SharedDcqlMatcher has already logged why - with the
            // error, when there was one - so repeating it here would only
            // double the noise on every call.
            return parsed
        }
        return narrow(parsed: parsed, with: shared)
        #else
        return parsed
        #endif
    }

    /// Apply an engine outcome to the parsed results.
    ///
    /// Separate from ``applySharedEngine(dcqlQuery:credentials:parsed:)``, and
    /// deliberately not `#if os(iOS)`: calling the engine needs the native
    /// library, but deciding what its answer *means* does not, and that
    /// decision is where the §6.4 rule lives. Keeping it platform-neutral is
    /// what lets the rule be tested on every platform this package builds for,
    /// rather than only on the one where it runs.
    static func narrow(parsed: [MatchResult], with shared: SharedDcqlMatcher.Outcome) -> [MatchResult] {
        guard shared.satisfiable else {
            // §6.4: "MUST NOT return any Credential(s)" - not even the queries
            // that were answerable on their own. A request can ask for two
            // credentials and get one; offering that one lets a user consent to
            // a presentation that cannot satisfy the verifier.
            //
            // Reported once for the request rather than per query. The
            // per-query line explains a decline as a missing claim, which is
            // the usual cause and the wrong one here.
            //
            // One credential can be a candidate for several queries; the log
            // names credentials, not candidacies.
            var seen = Set<Int64>()
            let offered = parsed.flatMap { $0.candidates.map(\.id) }.filter { seen.insert($0).inserted }
            SharedDcqlMatcher.reportUnsatisfiable(builtIn: offered)
            return parsed.map {
                MatchResult(
                    queryId: $0.queryId,
                    format: $0.format,
                    candidates: [],
                    requestedClaims: $0.requestedClaims,
                    zkSystemTypes: $0.zkSystemTypes,
                    ppidContext: $0.ppidContext
                )
            }
        }

        return parsed.map { result -> MatchResult in
            let ids = shared.candidatesByQuery[result.queryId] ?? []
            SharedDcqlMatcher.reportDifference(
                queryId: result.queryId,
                builtIn: result.candidates.map(\.id),
                shared: ids
            )
            // Built once per query, not once per candidate.
            let qualifying = Set(ids)
            return MatchResult(
                queryId: result.queryId,
                format: result.format,
                candidates: result.candidates.filter { qualifying.contains($0.id) },
                requestedClaims: result.requestedClaims,
                zkSystemTypes: result.zkSystemTypes,
                ppidContext: result.ppidContext
            )
        }
    }

    /// Match stored credentials against an ISO 18013-5 mdoc `docType`
    /// requested during a proximity (BLE) presentation - the mdoc proximity
    /// protocol has no DCQL query, just a bare docType string in the
    /// `DeviceRequest`'s `ItemsRequest`.
    public static func matchMdocDocType(_ credentials: [StoredCredential], docType: String) -> [StoredCredential] {
        credentials.filter { $0.format == "mso_mdoc" && CredentialUtils.parseMdocDocument($0.raw)?.docType == docType }
    }

    public static func matchedCredentialIds(dcqlQuery: [String: Any], credentials: [StoredCredential]) -> [Int64] {
        var seen = Set<Int64>()
        return match(dcqlQuery: dcqlQuery, credentials: credentials)
            .flatMap { $0.candidates }
            .compactMap { cred in
                if seen.contains(cred.id) { return nil }
                seen.insert(cred.id)
                return cred.id
            }
    }

    public static func parseCredentialSets(_ dcqlQuery: [String: Any]) -> [CredentialSetQuery]? {
        guard let setsArray = dcqlQuery["credential_sets"] as? [[String: Any]],
              !setsArray.isEmpty else {
            return nil
        }

        let sets = setsArray.compactMap { obj -> CredentialSetQuery? in
            guard let optionsArray = obj["options"] as? [[Any]] else { return nil }
            let options = optionsArray.compactMap { optElement -> [String]? in
                let strings = optElement.compactMap { $0 as? String }
                return strings.isEmpty ? nil : strings
            }
            guard !options.isEmpty else { return nil }

            let required = (obj["required"] as? Bool) ?? true
            return CredentialSetQuery(options: options, required: required)
        }

        return sets.isEmpty ? nil : sets
    }

    public static func findSatisfiableOptions(
        credentialSets: [CredentialSetQuery],
        queryResults: [MatchResult]
    ) -> [SatisfiableOption] {
        let queryResultsById = Dictionary(uniqueKeysWithValues: queryResults.map { ($0.queryId, $0) })

        return credentialSets.enumerated().flatMap { (setIndex, credentialSet) in
            credentialSet.options.enumerated().compactMap { (optionIndex, queryIds) in
                let allSatisfied = queryIds.allSatisfy { queryId in
                    guard let result = queryResultsById[queryId] else { return false }
                    return !result.candidates.isEmpty
                }
                return allSatisfied
                    ? SatisfiableOption(credentialSetIndex: setIndex, optionIndex: optionIndex, queryIds: queryIds)
                    : nil
            }
        }
    }

    // MARK: - Private

    private static func matchSingleQuery(
        _ query: [String: Any],
        credentials: [StoredCredential]
    ) -> MatchResult? {
        guard let queryId = query["id"] as? String else { return nil }
        let format = query["format"] as? String
        let meta = query["meta"] as? [String: Any]
        let claims = parseClaims(query["claims"])

        let vctValues: Set<String>?
        if let values = meta?["vct_values"] as? [String] {
            vctValues = Set(values)
        } else {
            vctValues = nil
        }

        let doctypeValue = meta?["doctype_value"] as? String
        let zkSystemTypes: [ZkSystemSpec]?
        if let zkArray = meta?["zk_system_type"] as? [[String: Any]] {
            let specs = zkArray.compactMap { parseZkSystemSpec($0) }
            zkSystemTypes = specs.isEmpty ? nil : specs
        } else {
            zkSystemTypes = nil
        }
        let ppidContext = meta?["ppid_context"] as? String

        let matched = credentials.filter { cred in
            matchesFormat(cred, format: format)
                && matchesVct(cred, vctValues: vctValues)
                && matchesDoctype(cred, doctypeValue: doctypeValue)
        }

        return MatchResult(
            queryId: queryId,
            format: format,
            candidates: matched,
            requestedClaims: claims,
            zkSystemTypes: zkSystemTypes,
            ppidContext: ppidContext
        )
    }

    /// Parses one entry of a DCQL query's `meta.zk_system_type` array into a
    /// `ZkSystemSpec` - `{id, system, ...params}`. Confirmed via multipaz's
    /// own parsing of this exact wire shape: every OTHER top-level key on the
    /// entry (e.g. `num_attributes`, `version`, `circuit_hash`,
    /// `block_enc_hash`, `block_enc_sig`) IS a param - there is no nested
    /// `"params"` object on the wire.
    private static func parseZkSystemSpec(_ obj: [String: Any]) -> ZkSystemSpec? {
        guard let id = obj["id"] as? String, let system = obj["system"] as? String else { return nil }
        var params: [String: String] = [:]
        for (key, value) in obj where key != "id" && key != "system" {
            params[key] = (value as? String) ?? (value as? CustomStringConvertible)?.description ?? ""
        }
        return ZkSystemSpec(id: id, system: system, params: params)
    }

    private static func matchesFormat(_ credential: StoredCredential, format: String?) -> Bool {
        guard let format else { return true }
        if format.caseInsensitiveCompare("mso_mdoc_zk") == .orderedSame {
            // A verifier requesting a ZK-wrapped presentation ("mso_mdoc_zk")
            // still matches a credential stored in the ordinary "mso_mdoc"
            // shape - producing a ZK proof is a presentation-time transform
            // (see ZkProofSystem.generateProof), not a distinct storage
            // format. There is no separate on-device "ZK credential" to store.
            return credential.format.caseInsensitiveCompare("mso_mdoc") == .orderedSame
        }
        return credential.format.caseInsensitiveCompare(format) == .orderedSame
    }

    private static func matchesVct(_ credential: StoredCredential, vctValues: Set<String>?) -> Bool {
        guard let vctValues, !vctValues.isEmpty else { return true }
        guard let credVct = credential.metadata?.vct else { return false }
        return vctValues.contains(credVct)
    }

    private static func matchesDoctype(_ credential: StoredCredential, doctypeValue: String?) -> Bool {
        guard let doctypeValue else { return true }
        guard let credDoctype = credential.metadata?.doctype else { return false }
        return credDoctype == doctypeValue
    }

    private static func parseClaims(_ element: Any?) -> [[String]] {
        guard let array = element as? [[String: Any]] else { return [] }
        return array.compactMap { obj in
            guard let path = obj["path"] as? [String] else { return nil }
            return path
        }
    }
}

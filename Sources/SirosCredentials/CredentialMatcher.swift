// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Client-side DCQL (Digital Credentials Query Language) matcher per OID4VP §6.
public enum CredentialMatcher {

    public struct MatchResult: Sendable, Equatable {
        public let queryId: String
        public let format: String?
        public let candidates: [StoredCredential]
        public let requestedClaims: [[String]]

        public init(queryId: String, format: String? = nil, candidates: [StoredCredential], requestedClaims: [[String]]) {
            self.queryId = queryId
            self.format = format
            self.candidates = candidates
            self.requestedClaims = requestedClaims
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

        let queryResults = credentialQueries.compactMap { query in
            matchSingleQuery(query, credentials: credentials)
        }

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

    public static func matchedCredentialIds(dcqlQuery: [String: Any], credentials: [StoredCredential]) -> [String] {
        var seen = Set<String>()
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

        let matched = credentials.filter { cred in
            matchesFormat(cred, format: format)
                && matchesVct(cred, vctValues: vctValues)
                && matchesDoctype(cred, doctypeValue: doctypeValue)
        }

        return MatchResult(
            queryId: queryId,
            format: format,
            candidates: matched,
            requestedClaims: claims
        )
    }

    private static func matchesFormat(_ credential: StoredCredential, format: String?) -> Bool {
        guard let format else { return true }
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

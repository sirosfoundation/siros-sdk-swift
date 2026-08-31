// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(os)
import os
private let logger = Logger(subsystem: "org.siros.sdk", category: "SharedDcqlMatcher")
#endif

/// Route a diagnostic line through the platform logger, or drop it where there
/// is none.
///
/// The identifiers below are interpolated as dynamic values on purpose. `os`
/// redacts those in released builds and shows them when a developer is attached
/// — which is exactly the audience for a line explaining why a credential was
/// declined. Marking them `public` would put credential identifiers into
/// device logs a host app does not control.
private func log(_ message: String) {
    #if canImport(os)
    logger.info("\(message, privacy: .private)")
    #endif
}

/// DCQL matching by the shared Rust engine — the same one the Android
/// credential picker runs, and the same one `siros-sdk-kotlin` calls.
///
/// ``CredentialMatcher`` implements a subset of DCQL: it filters on format and
/// type metadata, and does not check that a credential actually has the claims
/// a verifier asked for. OpenID4VP 1.0 §6.4.1 requires that check — a
/// credential missing a requested claim "MUST NOT" be returned — so today a
/// user can be offered a credential, consent, and have the presentation fail to
/// satisfy the verifier. `claim_sets` and `values` are missing too, and the
/// Kotlin SDK implemented a slightly different subset again.
///
/// This exists to retire those implementations in favour of one that is tested
/// against the specification's own examples.
///
/// ## Not yet trusted
///
/// ``CredentialMatcher`` still decides the result. This runs alongside it and
/// reports where the two disagree, because the change it brings is not
/// cosmetic: enforcing §6.4.1 *narrows* what a wallet offers, correctly, and a
/// user whose credential stops appearing deserves that to be one deliberate
/// change rather than a side effect of another. Switching over is a separate
/// step, once the disagreements on real requests are understood.
///
/// ## iOS only
///
/// The XCFramework ships iOS slices only. On macOS — which this package's CI
/// builds and tests — there is no engine to call, so ``evaluate(dcqlQuery:credentials:)``
/// is absent and ``CredentialMatcher`` keeps the parsing path it has always
/// used. The one piece with no native dependency, ``splitClaimKey(format:key:)``,
/// stays available everywhere so it can be tested on both.
public enum SharedDcqlMatcher {

    /// What the shared engine decided.
    ///
    /// ``satisfiable`` is not derivable from ``candidatesByQuery``. A request
    /// can ask for two credentials and get one: the answerable query has
    /// candidates, and the request as a whole must still offer nothing (§6.4).
    /// Carrying the flag rather than collapsing it into an empty dictionary
    /// keeps the two reasons for offering nothing distinguishable — which
    /// matters, because they are explained to a user differently.
    public struct Outcome: Sendable, Equatable {
        /// Whether anything at all may be offered (§6.4).
        public let satisfiable: Bool
        /// Per-query candidates, complete and uncapped.
        public let candidatesByQuery: [String: [Int64]]

        public init(satisfiable: Bool, candidatesByQuery: [String: [Int64]]) {
            self.satisfiable = satisfiable
            self.candidatesByQuery = candidatesByQuery
        }
    }

    /// Split a display-claim key into the path components DCQL matches against.
    ///
    /// mdoc element identifiers never contain dots while namespaces routinely
    /// do, so the split is on the last one — `org.iso.18013.5.1.family_name`
    /// is a namespace and an element, not five path components. JSON-based
    /// credentials keep the key whole; theirs are not dotted paths.
    static func splitClaimKey(format: String, key: String) -> [String] {
        guard format.lowercased() == "mso_mdoc", let dot = key.lastIndex(of: ".") else {
            return [key]
        }
        return [String(key[key.startIndex..<dot]), String(key[key.index(after: dot)...])]
    }

    /// Report where the two implementations disagree, for one credential query.
    ///
    /// Logged rather than thrown. The built-in matcher decides now, so a
    /// disagreement is not a fault — it is almost always the engine correctly
    /// declining a credential that lacks a claim the verifier asked for, which
    /// the built-in matcher never checked (OID4VP 1.0 §6.4.1). Recorded
    /// because "my credential stopped appearing" is a support question, and
    /// this is the line that answers it.
    static func reportDifference(queryId: String, builtIn: [Int64], shared: [Int64]) {
        let sharedSet = Set(shared)
        let builtInSet = Set(builtIn)
        let onlyBuiltIn = builtIn.filter { !sharedSet.contains($0) }
        let onlyShared = shared.filter { !builtInSet.contains($0) }
        guard !onlyBuiltIn.isEmpty || !onlyShared.isEmpty else { return }

        log("""
        DCQL query '\(queryId)': the shared engine declined \(onlyBuiltIn) that the \
        built-in matcher would have offered (most likely a requested claim the \
        credential lacks, OID4VP 1.0 §6.4.1), and offered \(onlyShared) it would not
        """)
    }

    /// Report a request the engine declined as a whole.
    ///
    /// Once for the request rather than once per query. The per-query line
    /// explains a decline as a missing claim, which is the usual cause and the
    /// wrong one here.
    static func reportUnsatisfiable(builtIn: [Int64]) {
        log("""
        The shared engine declined the request as a whole (OID4VP 1.0 §6.4): some \
        part of it cannot be answered, so none of it may be offered. The built-in \
        matcher would have offered \(builtIn). This is not a per-credential decline \
        - no credential here is missing a requested claim
        """)
    }
}

#if os(iOS)

extension SharedDcqlMatcher {

    /// What the shared engine matched, or `nil` if it could not run.
    ///
    /// `nil` is not "nothing matched". The native library may be unavailable,
    /// or the engine may reject a request this SDK would have accepted — both
    /// mean "no answer", and a caller must not read that as an empty match.
    static func evaluate(dcqlQuery: [String: Any], credentials: [StoredCredential]) -> Outcome? {
        guard let queryData = try? JSONSerialization.data(withJSONObject: dcqlQuery),
              let queryJson = String(data: queryData, encoding: .utf8) else {
            log("DCQL query is not serialisable JSON; keeping the built-in matcher's answer")
            return nil
        }

        do {
            let builder = SirosBlobBuilder()
            for credential in credentials {
                builder.addCredential(credential: toFfi(credential))
            }
            let blob = try builder.build()
            let outcome = try matchDcql(blob: blob, dcqlJson: queryJson)

            // `matches`, not `combinations`. The engine bounds how many
            // combinations it returns, because the count is a product of the
            // per-query candidate counts — so reconstructing per-query
            // candidates from them would omit credentials that do qualify, and
            // this result is used to *filter*. An omission there is a
            // credential silently missing from what the user is offered.
            //
            // `matches` is the engine's own per-query candidates, complete and
            // uncapped, so `dropped` does not bear on this answer at all. It is
            // also populated whether or not the request can be satisfied as a
            // whole, which is why `satisfiable` is carried alongside it rather
            // than inferred from it.
            var byQuery: [String: [Int64]] = [:]
            for queryMatch in outcome.matches {
                var seen = Set<Int64>()
                var ids: [Int64] = []
                for candidate in queryMatch.credentials {
                    guard let id = Int64(candidate.credentialId), seen.insert(id).inserted else { continue }
                    ids.append(id)
                }
                byQuery[queryMatch.queryId] = ids
            }
            return Outcome(satisfiable: outcome.satisfiable, candidatesByQuery: byQuery)
        } catch {
            // The engine declining a request is not a wallet fault: it means
            // "no answer", and the built-in matcher's answer stands.
            log("Shared DCQL engine unavailable; keeping the built-in matcher's answer: \(error)")
            return nil
        }
    }

    private static func toFfi(_ credential: StoredCredential) -> FfiCredential {
        FfiCredential(
            id: String(credential.id),
            format: credential.format,
            // The real docType, from the credential's own MSO - not issuer
            // metadata, which is only populated when the issuer happens to
            // expose a SIROS-internal schema endpoint.
            doctype: CredentialUtils.parseMdocDocument(credential.raw)?.docType ?? credential.metadata?.doctype,
            vct: credential.metadata?.vct,
            title: credential.metadata?.name ?? credential.format,
            subtitle: credential.metadata?.issuer?.name ?? "",
            iconId: nil,
            claims: CredentialUtils.extractClaims(credential).map { claim in
                FfiClaim(
                    path: splitClaimKey(format: credential.format, key: claim.key),
                    value: claim.value,
                    display: claim.label,
                    displayValue: nil
                )
            }
        )
    }
}

#endif

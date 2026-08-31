// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
// swift-crypto's `Crypto` mirrors CryptoKit 1:1, including the `SHA256` used
// to match a disclosure to its digest - the same arrangement ZkCircuitClient
// uses so this file compiles and behaves identically off Apple platforms.
import Crypto
#endif
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

// MARK: - Claims for matching

/// One claim as the engine sees it: a DCQL path and the value at it.
///
/// Deliberately not ``DisplayClaim``. That type is built for a credential
/// detail screen and carries a label, a description and an SVG id; this one
/// carries a *path*, because DCQL matches on claims path pointers (OpenID4VP
/// 1.0 §7) and a dotted display key is not one.
struct MatchClaim: Sendable, Equatable {
    let path: [String]
    let value: String
    let label: String
}

extension SharedDcqlMatcher {

    /// Every claim a verifier could ask for, at the path they would ask for it.
    ///
    /// Not ``CredentialUtils/extractClaims(_:)``, which exists to render a
    /// credential and is wrong here in two ways that both hide credentials from
    /// the user:
    ///
    /// - It reads only the JWT body. `parseJwtPayload` splits on `~` and keeps
    ///   the first segment, so for an SD-JWT VC stored as issued, every
    ///   *selectively disclosable* claim is missing — and `_sd` itself is in
    ///   its skip list. The engine would conclude the credential lacks the
    ///   claim, apply §6.4.1, and decline a credential that can in fact
    ///   disclose it.
    /// - It returns dotted display keys. `credentialSubject.given_name` is one
    ///   string; the DCQL path is `["credentialSubject", "given_name"]`, and
    ///   the two do not compare equal.
    ///
    /// Both fail in the same direction — a credential that qualifies is not
    /// offered — which is the failure this whole component exists to remove.
    static func matchingClaims(_ credential: StoredCredential) -> [MatchClaim] {
        // mdoc claims are already the real disclosed elements, read from the
        // credential's own namespaces rather than from issuer metadata, and
        // their path is `[namespace, element]`.
        if credential.format.lowercased() == "mso_mdoc" {
            return CredentialUtils.extractClaims(credential).map {
                MatchClaim(path: splitClaimKey(format: credential.format, key: $0.key),
                           value: $0.value,
                           label: $0.label)
            }
        }

        guard var payload = CredentialUtils.parseJwtPayload(credential.raw) else { return [] }
        payload = resolvingDisclosures(payload, in: credential.raw)

        var claims: [MatchClaim] = []
        flatten(payload, prefix: [], into: &claims)
        return claims
    }

    /// Reinstate selectively disclosed claims into the payload they were
    /// removed from.
    ///
    /// SD-JWT replaces a claim with the digest of its disclosure, collected in
    /// an `_sd` array on the object the claim belonged to. Resolving is
    /// therefore not a merge but a walk: hash each disclosure, find the `_sd`
    /// entry naming it, and put the claim back where that array lives.
    ///
    /// Repeated to a fixed point, because a disclosed value may itself carry an
    /// `_sd` array whose digests only become reachable once its parent is
    /// restored.
    private static func resolvingDisclosures(_ payload: [String: Any], in raw: String) -> [String: Any] {
        let segments = raw.split(separator: "~", omittingEmptySubsequences: true).map(String.init)
        guard segments.count > 1 else { return payload }

        // [digest: (name, value)]. Two-element disclosures are array elements
        // (§4.2.2), which carry no name and no path a DCQL pointer can address,
        // so they are not reinstated here.
        var byDigest: [String: (name: String, value: Any)] = [:]
        for segment in segments.dropFirst() {
            guard let json = CredentialUtils.base64UrlDecode(segment),
                  let parts = try? JSONSerialization.jsonObject(with: json) as? [Any],
                  parts.count == 3,
                  let name = parts[1] as? String else { continue }
            byDigest[sha256Base64Url(segment)] = (name, parts[2])
        }
        guard !byDigest.isEmpty else { return payload }

        var resolved = payload
        // Bounded by the number of disclosures: each pass must reinstate at
        // least one to continue, so this cannot spin on a malformed credential.
        for _ in 0..<byDigest.count {
            var planted = false
            resolved = reinstate(resolved, byDigest, &planted)
            if !planted { break }
        }
        return resolved
    }

    private static func reinstate(
        _ node: [String: Any],
        _ byDigest: [String: (name: String, value: Any)],
        _ planted: inout Bool
    ) -> [String: Any] {
        var out = node

        if let digests = node["_sd"] as? [Any] {
            var unresolved: [Any] = []
            for entry in digests {
                guard let digest = entry as? String, let claim = byDigest[digest] else {
                    unresolved.append(entry)
                    continue
                }
                out[claim.name] = claim.value
                planted = true
            }
            // Keep digests we have no disclosure for: the holder was not given
            // those claims, and dropping the array would erase the evidence
            // that they exist at all.
            if unresolved.isEmpty { out.removeValue(forKey: "_sd") } else { out["_sd"] = unresolved }
        }

        // Iterating `out`, not `node`, and the difference matters: the block
        // above has just planted disclosed claims into `out`, and a planted
        // value can carry an `_sd` array of its own. Walking `node` would never
        // descend into one, leaving a nested selectively-disclosed claim hidden.
        //
        // Mutating `out` while iterating it is safe here - `Dictionary` is a
        // value type, so the loop walks the value the sequence expression
        // produced and the assignment copies on write. There is no shared
        // buffer to invalidate.
        for (key, value) in out {
            if let child = value as? [String: Any] {
                out[key] = reinstate(child, byDigest, &planted)
            }
        }
        return out
    }

    /// Every node in the payload, at its DCQL path.
    ///
    /// Intermediate objects are emitted as well as leaves, because a claims
    /// path pointer may address either — `["address"]` is as valid a request as
    /// `["address", "locality"]`.
    private static func flatten(_ node: [String: Any], prefix: [String], into claims: inout [MatchClaim]) {
        for key in node.keys.sorted() {
            guard !jwtStructuralKeys.contains(key) else { continue }
            let path = prefix + [key]
            let value = node[key]
            if let child = value as? [String: Any] {
                claims.append(MatchClaim(path: path,
                                         value: CredentialUtils.formatClaimValue(value),
                                         label: CredentialUtils.formatClaimKey(key)))
                flatten(child, prefix: path, into: &claims)
            } else {
                claims.append(MatchClaim(path: path,
                                         value: CredentialUtils.formatClaimValue(value),
                                         label: CredentialUtils.formatClaimKey(key)))
            }
        }
    }

    /// SD-JWT bookkeeping, not claims. A verifier does not request `_sd_alg`.
    private static let jwtStructuralKeys: Set<String> = ["_sd", "_sd_alg", "...", "cnf"]

    private static func sha256Base64Url(_ text: String) -> String {
        let digest = SHA256.hash(data: Data(text.utf8))
        return Data(digest).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
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
            // `SirosBlobBuilder()` and `addCredential` are declared infallible in
            // Rust, so UniFFI generates `try!` for them and a Rust panic there
            // would trap rather than reach the `catch` below. They cannot panic:
            // the builder's lock is taken with
            // `unwrap_or_else(PoisonError::into_inner)`, so poisoning is handled
            // rather than unwrapped, and the body is a `Vec::push`. The two calls
            // that *can* fail - `build()` and `matchDcql` - are declared fallible
            // and are the ones this `catch` exists for.
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
            // matchingClaims, not extractClaims: the display extractor drops
            // every selectively disclosed claim and returns dotted keys rather
            // than DCQL paths. Both make a credential look like it lacks what a
            // verifier asked for.
            claims: matchingClaims(credential).map { claim in
                FfiClaim(
                    path: claim.path,
                    value: claim.value,
                    display: claim.label,
                    displayValue: nil
                )
            }
        )
    }
}

#endif

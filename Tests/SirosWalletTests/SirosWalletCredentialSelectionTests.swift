// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosCredentials
import SirosTransport
@testable import SirosWallet

/// Tests for `SirosWallet.buildConsentPayload` - the `"selected_credentials"`
/// flow-action payload construction for the `"credential_selection"`
/// flow_progress step (the real, live path exercised by redirect-flow/
/// haip-vp:// presentations - see `SirosWallet.handleCredentialSelection`'s
/// doc comment). `WalletEngineSession` is a `final class` with no injectable
/// transport seam, so a live engine round-trip can't be driven from a unit
/// test - these instead pin down the pure payload-construction logic
/// directly, mirroring this file's `SirosWalletDCAPITests` sibling's
/// precedent of testing wallet-facing logic without a live network.
final class SirosWalletCredentialSelectionTests: XCTestCase {
    private func makeCredential(id: Int64, format: String = "mso_mdoc") -> StoredCredential {
        StoredCredential(
            id: id,
            format: format,
            raw: "raw-\(id)",
            batchId: id,
            instanceId: 0
        )
    }

    /// A single matched query with a plain (non-ZK) mdoc candidate: the
    /// consent payload must carry `credential_query_id`, a stringified
    /// `credential_id`, and `disclosed_claims` trimmed to each path's LAST
    /// segment - matching go-wallet-backend's `ConsentSelection` wire shape
    /// and Kotlin's identical `handleCredentialSelection` construction.
    func testBuildConsentPayload_singleMatch_trimsClaimPathsToLastSegment() {
        let cred = makeCredential(id: 42)
        let matchResults = [
            CredentialMatcher.MatchResult(
                queryId: "pid-query",
                format: "mso_mdoc",
                candidates: [cred],
                requestedClaims: [
                    ["eu.europa.ec.eudi.pid.1", "given_name"],
                    ["eu.europa.ec.eudi.pid.1", "family_name"],
                ]
            ),
        ]

        let payload = SirosWallet.buildConsentPayload(matchResults: matchResults, selectedIds: [42], allCreds: [cred])

        guard case .array(let entries)? = payload["selected_credentials"] else {
            return XCTFail("Expected selected_credentials array")
        }
        XCTAssertEqual(entries.count, 1)
        guard case .object_(let entry) = entries[0] else {
            return XCTFail("Expected object entry")
        }
        XCTAssertEqual(entry["credential_query_id"]?.stringValue, "pid-query")
        XCTAssertEqual(entry["credential_id"]?.stringValue, "42")
        guard case .array(let disclosed)? = entry["disclosed_claims"] else {
            return XCTFail("Expected disclosed_claims array")
        }
        // Only the last path segment ("given_name"/"family_name") survives -
        // the leading namespace ("eu.europa.ec.eudi.pid.1") must be
        // stripped, or a strict verifier-side ZK claim check downstream
        // would reject the whole path as an unknown attribute.
        XCTAssertEqual(disclosed.compactMap(\.stringValue), ["given_name", "family_name"])
    }

    /// Two independent DCQL queries, each matching a different credential -
    /// each selected credential must be routed to ITS OWN query's id and
    /// claim list, not the first query's.
    func testBuildConsentPayload_multipleQueries_routesEachCredentialToItsOwnQuery() {
        let pidCred = makeCredential(id: 1, format: "mso_mdoc")
        let mdlCred = makeCredential(id: 2, format: "mso_mdoc")
        let matchResults = [
            CredentialMatcher.MatchResult(
                queryId: "pid-query", format: "mso_mdoc", candidates: [pidCred],
                requestedClaims: [["eu.europa.ec.eudi.pid.1", "given_name"]]
            ),
            CredentialMatcher.MatchResult(
                queryId: "mdl-query", format: "mso_mdoc", candidates: [mdlCred],
                requestedClaims: [["org.iso.18013.5.1", "document_number"]]
            ),
        ]

        let payload = SirosWallet.buildConsentPayload(
            matchResults: matchResults, selectedIds: [1, 2], allCreds: [pidCred, mdlCred]
        )

        guard case .array(let entries)? = payload["selected_credentials"] else {
            return XCTFail("Expected selected_credentials array")
        }
        XCTAssertEqual(entries.count, 2)
        let byCredId: [String: [String: AnyCodable]] = Dictionary(uniqueKeysWithValues: entries.compactMap {
            guard case .object_(let obj) = $0, let credId = obj["credential_id"]?.stringValue else { return nil }
            return (credId, obj)
        })
        XCTAssertEqual(byCredId["1"]?["credential_query_id"]?.stringValue, "pid-query")
        XCTAssertEqual(byCredId["2"]?["credential_query_id"]?.stringValue, "mdl-query")
    }

    /// A credential id the caller passed in `selectedIds` but that isn't
    /// actually present in `allCreds` must be silently skipped, not crash or
    /// produce a malformed entry - defense against a listener returning an
    /// id it wasn't actually offered.
    func testBuildConsentPayload_selectedIdNotInAllCreds_isSkipped() {
        let cred = makeCredential(id: 1)
        let matchResults = [
            CredentialMatcher.MatchResult(queryId: "q", format: nil, candidates: [cred], requestedClaims: []),
        ]

        let payload = SirosWallet.buildConsentPayload(matchResults: matchResults, selectedIds: [1, 999], allCreds: [cred])

        guard case .array(let entries)? = payload["selected_credentials"] else {
            return XCTFail("Expected selected_credentials array")
        }
        XCTAssertEqual(entries.count, 1)
    }

    /// A selected id that IS in `allCreds` but isn't a candidate of any
    /// `matchResults` entry (e.g. an inconsistent listener return, a race, or
    /// a future matcher change - flagged in PR review) must still produce an
    /// entry carrying a `credential_query_id` (falling back to `"_default"`,
    /// mirroring `matchAndSelectCredentials`'s synthetic no-DCQL
    /// MatchResult), never omit the field - go-wallet-backend's
    /// ConsentSelection wire contract requires it on every entry.
    func testBuildConsentPayload_selectedIdNotInAnyMatchResult_fallsBackToDefaultQueryId() {
        let matchedCred = makeCredential(id: 1)
        let orphanCred = makeCredential(id: 2)
        let matchResults = [
            CredentialMatcher.MatchResult(queryId: "q", format: nil, candidates: [matchedCred], requestedClaims: []),
        ]

        let payload = SirosWallet.buildConsentPayload(
            matchResults: matchResults, selectedIds: [2], allCreds: [matchedCred, orphanCred]
        )

        guard case .array(let entries)? = payload["selected_credentials"] else {
            return XCTFail("Expected selected_credentials array")
        }
        XCTAssertEqual(entries.count, 1)
        guard case .object_(let entry) = entries[0] else {
            return XCTFail("Expected object entry")
        }
        XCTAssertEqual(entry["credential_query_id"]?.stringValue, "_default")
    }

    /// Duplicate claim paths across a query's requestedClaims (e.g. the
    /// same element requested under two DCQL alternatives) must be
    /// deduplicated in the final disclosed_claims list.
    func testBuildConsentPayload_duplicateClaimPaths_areDeduplicated() {
        let cred = makeCredential(id: 7)
        let matchResults = [
            CredentialMatcher.MatchResult(
                queryId: "q", format: "mso_mdoc", candidates: [cred],
                requestedClaims: [
                    ["eu.europa.ec.eudi.pid.1", "given_name"],
                    ["some.other.ns", "given_name"],
                ]
            ),
        ]

        let payload = SirosWallet.buildConsentPayload(matchResults: matchResults, selectedIds: [7], allCreds: [cred])

        guard case .array(let entries)? = payload["selected_credentials"] else {
            return XCTFail("Expected selected_credentials array")
        }
        guard case .object_(let entry) = entries[0], case .array(let disclosed)? = entry["disclosed_claims"] else {
            return XCTFail("Expected disclosed_claims array")
        }
        XCTAssertEqual(disclosed.compactMap(\.stringValue), ["given_name"])
    }

    /// No requested claims at all (e.g. a `"_default"` fallback query with
    /// no DCQL) must produce an empty (not missing/nil) disclosed_claims
    /// array - go-wallet-backend's ConsentSelection expects the field
    /// present.
    func testBuildConsentPayload_noRequestedClaims_producesEmptyArray() {
        let cred = makeCredential(id: 3)
        let matchResults = [
            CredentialMatcher.MatchResult(queryId: "_default", format: nil, candidates: [cred], requestedClaims: []),
        ]

        let payload = SirosWallet.buildConsentPayload(matchResults: matchResults, selectedIds: [3], allCreds: [cred])

        guard case .array(let entries)? = payload["selected_credentials"] else {
            return XCTFail("Expected selected_credentials array")
        }
        guard case .object_(let entry) = entries[0] else {
            return XCTFail("Expected object entry")
        }
        XCTAssertEqual(entry["credential_query_id"]?.stringValue, "_default")
        guard case .array(let disclosed)? = entry["disclosed_claims"] else {
            return XCTFail("Expected disclosed_claims array")
        }
        XCTAssertTrue(disclosed.isEmpty)
    }
}

/// Integration-style tests exercising `CredentialMatcher.match` (the real
/// DCQL matcher, already unit-tested on its own in
/// `Tests/SirosCredentialsTests/CredentialMatcherTests.swift`) the same way
/// `handleCredentialSelection`/`handleMatchRequest`/`handleWmpMatchRequest`
/// now do: parse a `dcql_query` JSON payload into `[String: Any]`, match it
/// against stored credentials, and confirm the query id + zk metadata a
/// `sign_presentation` ZK branch depends on survive the round trip.
final class SirosWalletCredentialSelectionDcqlIntegrationTests: XCTestCase {
    private func makeCredential(id: Int64, format: String, doctype: String? = nil) -> StoredCredential {
        StoredCredential(
            id: id, format: format, raw: "raw-\(id)",
            metadata: doctype.map { CredentialMetadata(doctype: $0) },
            batchId: id, instanceId: 0
        )
    }

    /// Mirrors the exact `dcql_query` shape a `"credential_selection"`
    /// flow_progress payload carries - a plain (non-ZK) mdoc query filtered
    /// by `doctype_value`.
    func testDcqlQueryFromPayload_filtersByDoctype() throws {
        let payloadJson = """
        {
            "credentials": [
                {
                    "id": "mdl-query",
                    "format": "mso_mdoc",
                    "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                    "claims": [{ "path": ["org.iso.18013.5.1", "document_number"] }]
                }
            ]
        }
        """
        let dcqlQuery = try JSONSerialization.jsonObject(with: Data(payloadJson.utf8)) as! [String: Any]

        let mdl = makeCredential(id: 1, format: "mso_mdoc", doctype: "org.iso.18013.5.1.mDL")
        let wrongDoctype = makeCredential(id: 2, format: "mso_mdoc", doctype: "eu.europa.ec.eudi.pid.1")
        let wrongFormat = makeCredential(id: 3, format: "dc+sd-jwt", doctype: "org.iso.18013.5.1.mDL")

        let results = CredentialMatcher.match(dcqlQuery: dcqlQuery, credentials: [mdl, wrongDoctype, wrongFormat])
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results[0].queryId, "mdl-query")
        XCTAssertEqual(results[0].candidates.map(\.id), [1])
    }

    /// A `"mso_mdoc_zk"` query must parse `meta.zk_system_type` /
    /// `meta.ppid_context` and still match ordinary `"mso_mdoc"`-stored
    /// credentials - producing a ZK proof is a presentation-time transform,
    /// not a distinct storage format (see `CredentialMatcher`'s own doc
    /// comment on this). This is exactly what `handleSignRequest`'s new ZK
    /// branch depends on `pendingMatchResultsByFlow` having captured.
    func testDcqlQueryFromPayload_zkFormat_matchesOrdinaryMdocAndParsesZkMeta() throws {
        let payloadJson = """
        {
            "credentials": [
                {
                    "id": "zk-query",
                    "format": "mso_mdoc_zk",
                    "meta": {
                        "doctype_value": "eu.europa.ec.eudi.pid.1",
                        "zk_system_type": [{ "id": "longfellow-libzk-v1-c1", "system": "longfellow-libzk-v1", "circuit_id": "c1" }],
                        "ppid_context": "some-context"
                    },
                    "claims": [{ "path": ["eu.europa.ec.eudi.pid.1", "pairwise_pseudonym"] }]
                }
            ]
        }
        """
        let dcqlQuery = try JSONSerialization.jsonObject(with: Data(payloadJson.utf8)) as! [String: Any]
        let pid = makeCredential(id: 5, format: "mso_mdoc", doctype: "eu.europa.ec.eudi.pid.1")

        let results = CredentialMatcher.match(dcqlQuery: dcqlQuery, credentials: [pid])
        XCTAssertEqual(results.count, 1)
        let result = results[0]
        XCTAssertEqual(result.queryId, "zk-query")
        XCTAssertEqual(result.format, "mso_mdoc_zk")
        XCTAssertTrue(result.candidates.contains(where: { $0.id == 5 }))
        XCTAssertEqual(result.ppidContext, "some-context")
        XCTAssertNotNil(result.zkSystemTypes)
        XCTAssertEqual(result.zkSystemTypes?.count, 1)

        // What buildConsentPayload/handleSignRequest's ZK branch actually
        // consume from this MatchResult.
        let consentPayload = SirosWallet.buildConsentPayload(matchResults: results, selectedIds: [5], allCreds: [pid])
        guard case .array(let entries)? = consentPayload["selected_credentials"],
              case .object_(let entry) = entries.first else {
            return XCTFail("Expected one consent entry")
        }
        guard case .array(let disclosed)? = entry["disclosed_claims"] else {
            return XCTFail("Expected disclosed_claims array")
        }
        XCTAssertEqual(disclosed.compactMap(\.stringValue), ["pairwise_pseudonym"])
    }
}

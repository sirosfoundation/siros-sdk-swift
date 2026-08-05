// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials
@preconcurrency import SwiftCBOR

final class CredentialMatcherTests: XCTestCase {

    private func parseJSON(_ string: String) -> [String: Any] {
        let data = string.data(using: .utf8)!
        return try! JSONSerialization.jsonObject(with: data) as! [String: Any]
    }

    /// A minimal but REAL CBOR-encoded bare `IssuerSigned` structure (no
    /// enclosing `{documents: [...]}` envelope), base64url-encoded the same
    /// way `StoredCredential.raw` is stored - see `MdocCborTests`'s matching
    /// fixture builder for why the payload must be a real double-encoded
    /// byte string, not an in-memory tagged value.
    private func mdocRaw(docType: String) -> String {
        let item: CBOR = .tagged(.encodedCBORDataItem, .byteString(CBOR.map([
            .utf8String("digestID"): .unsignedInt(0),
            .utf8String("random"): .byteString([UInt8](repeating: 0, count: 16)),
            .utf8String("elementIdentifier"): .utf8String("given_name"),
            .utf8String("elementValue"): .utf8String("Jane"),
        ]).encode()))
        let nameSpaces: CBOR = .map([.utf8String("org.iso.18013.5.1"): .array([item])])

        let mso: CBOR = .map([.utf8String("docType"): .utf8String(docType)])
        let taggedMso: CBOR = .tagged(.encodedCBORDataItem, .byteString(mso.encode()))
        let issuerAuth: CBOR = .array([
            .byteString([]),
            .map([:]),
            .byteString(taggedMso.encode()),
            .byteString([UInt8](repeating: 0, count: 64)),
        ])

        let bareIssuerSigned: CBOR = .map([
            .utf8String("nameSpaces"): nameSpaces,
            .utf8String("issuerAuth"): issuerAuth,
        ])

        return Data(bareIssuerSigned.encode()).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// StoredCredential now requires batchId/instanceId - defaults batchId
    /// to id (a standalone test credential is simplest modeled as a batch
    /// of one). Note: the DCQL query "id" strings used throughout this file
    /// (e.g. "q-pid", "pid", "mdl") are a separate, unrelated identifier
    /// space (the query's own key) and are NOT StoredCredential ids - only
    /// StoredCredential(id:) itself is numeric.
    private func storedCredential(
        id: Int64,
        format: String,
        raw: String,
        metadata: CredentialMetadata? = nil
    ) -> StoredCredential {
        StoredCredential(id: id, format: format, raw: raw, metadata: metadata, batchId: id, instanceId: 0)
    }

    func testMatchFiltersByFormatAndVct() {
        let credentials = [
            storedCredential(id: 1, format: "dc+sd-jwt", raw: "raw-1",
                              metadata: CredentialMetadata(vct: "urn:eu:pid:1")),
            storedCredential(id: 2, format: "mso_mdoc", raw: "raw-2",
                              metadata: CredentialMetadata(doctype: "eu.europa.ec.eudi.pid.1")),
        ]

        let query = parseJSON("""
        {
          "credentials": [
            {
              "id": "q-pid",
              "format": "dc+sd-jwt",
              "meta": { "vct_values": ["urn:eu:pid:1"] },
              "claims": [{ "path": ["given_name"] }]
            }
          ]
        }
        """)

        let results = CredentialMatcher.match(dcqlQuery: query, credentials: credentials)

        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results.first?.queryId, "q-pid")
        XCTAssertEqual(results.first?.candidates.map(\.id), [1])
        XCTAssertEqual(results.first?.requestedClaims, [["given_name"]])
    }

    func testMatchFiltersByDoctypeForMdoc() {
        let credentials = [
            storedCredential(id: 1, format: "mso_mdoc", raw: "raw-1",
                              metadata: CredentialMetadata(doctype: "eu.europa.ec.eudi.pid.1")),
            storedCredential(id: 2, format: "mso_mdoc", raw: "raw-2",
                              metadata: CredentialMetadata(doctype: "com.example.other")),
        ]

        let query = parseJSON("""
        {
          "credentials": [
            {
              "id": "q-doc",
              "format": "mso_mdoc",
              "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" }
            }
          ]
        }
        """)

        let matchedIds = CredentialMatcher.matchedCredentialIds(dcqlQuery: query, credentials: credentials)
        XCTAssertEqual(matchedIds, [1])
    }

    func testMatchReturnsAllWhenQueryHasNoCredentialsArray() {
        let credentials = [
            storedCredential(id: 1, format: "dc+sd-jwt", raw: "raw-a"),
            storedCredential(id: 2, format: "mso_mdoc", raw: "raw-b"),
        ]

        let query = parseJSON("{ \"unexpected\": true }")
        let results = CredentialMatcher.match(dcqlQuery: query, credentials: credentials)

        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results.first?.queryId, "_default")
        let ids = Set(results.first?.candidates.map(\.id) ?? [])
        XCTAssertTrue(ids.contains(1))
        XCTAssertTrue(ids.contains(2))
    }

    func testMatchedCredentialIdsAreDistinct() {
        let credentials = [
            storedCredential(id: 1, format: "dc+sd-jwt", raw: "raw-1",
                              metadata: CredentialMetadata(vct: "urn:eu:pid:1")),
        ]

        let query = parseJSON("""
        {
          "credentials": [
            { "id": "q-1", "format": "DC+SD-JWT", "meta": { "vct_values": ["urn:eu:pid:1"] } },
            { "id": "q-2", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eu:pid:1"] } }
          ]
        }
        """)

        let matchedIds = CredentialMatcher.matchedCredentialIds(dcqlQuery: query, credentials: credentials)
        XCTAssertEqual(matchedIds, [1])
    }

    func testMatchExcludesCredentialsWithoutRequiredMetadata() {
        let credentials = [
            storedCredential(id: 1, format: "dc+sd-jwt", raw: "raw-1"),
            storedCredential(id: 2, format: "mso_mdoc", raw: "raw-2"),
        ]

        let query = parseJSON("""
        {
          "credentials": [
            { "id": "q-vct", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eu:pid:1"] } },
            { "id": "q-doc", "format": "mso_mdoc", "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" } }
          ]
        }
        """)

        let results = CredentialMatcher.match(dcqlQuery: query, credentials: credentials)
        XCTAssertTrue(results.first(where: { $0.queryId == "q-vct" })?.candidates.isEmpty ?? false)
        XCTAssertTrue(results.first(where: { $0.queryId == "q-doc" })?.candidates.isEmpty ?? false)
    }

    func testMatchSkipsQueriesWithoutId() {
        let credentials = [
            storedCredential(id: 1, format: "dc+sd-jwt", raw: "raw-1",
                              metadata: CredentialMetadata(vct: "urn:eu:pid:1")),
        ]

        let query = parseJSON("""
        {
          "credentials": [
            { "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eu:pid:1"] } },
            {
              "id": "q-valid",
              "format": "dc+sd-jwt",
              "meta": { "vct_values": ["urn:eu:pid:1"] },
              "claims": [{ "path": ["given_name"] }]
            }
          ]
        }
        """)

        let results = CredentialMatcher.match(dcqlQuery: query, credentials: credentials)
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results.first?.queryId, "q-valid")
        XCTAssertEqual(results.first?.requestedClaims, [["given_name"]])
    }

    // MARK: - credential_sets tests

    func testParseCredentialSetsReturnsNilWhenAbsent() {
        let query = parseJSON("{ \"credentials\": [] }")
        XCTAssertNil(CredentialMatcher.parseCredentialSets(query))
    }

    func testParseCredentialSetsParsesRequiredAndOptional() {
        let query = parseJSON("""
        {
          "credentials": [],
          "credential_sets": [
            { "options": [["pid"], ["other_pid"], ["cred_1", "cred_2"]] },
            { "required": false, "options": [["nice_to_have"]] }
          ]
        }
        """)

        let sets = CredentialMatcher.parseCredentialSets(query)!
        XCTAssertEqual(sets.count, 2)

        XCTAssertTrue(sets[0].required)
        XCTAssertEqual(sets[0].options.count, 3)
        XCTAssertEqual(sets[0].options[0], ["pid"])
        XCTAssertEqual(sets[0].options[1], ["other_pid"])
        XCTAssertEqual(sets[0].options[2], ["cred_1", "cred_2"])

        XCTAssertFalse(sets[1].required)
        XCTAssertEqual(sets[1].options, [["nice_to_have"]])
    }

    func testFindSatisfiableOptions() {
        let queryResults = [
            CredentialMatcher.MatchResult(queryId: "pid", format: "dc+sd-jwt",
                candidates: [storedCredential(id: 1, format: "dc+sd-jwt", raw: "r")],
                requestedClaims: []),
            CredentialMatcher.MatchResult(queryId: "other_pid", format: "dc+sd-jwt",
                candidates: [], requestedClaims: []),
            CredentialMatcher.MatchResult(queryId: "cred_1", format: "dc+sd-jwt",
                candidates: [storedCredential(id: 2, format: "dc+sd-jwt", raw: "r")],
                requestedClaims: []),
            CredentialMatcher.MatchResult(queryId: "cred_2", format: "dc+sd-jwt",
                candidates: [storedCredential(id: 3, format: "dc+sd-jwt", raw: "r")],
                requestedClaims: []),
        ]

        let credentialSets = [
            CredentialMatcher.CredentialSetQuery(
                options: [["pid"], ["other_pid"], ["cred_1", "cred_2"]],
                required: true
            ),
        ]

        let satisfiable = CredentialMatcher.findSatisfiableOptions(
            credentialSets: credentialSets, queryResults: queryResults)

        XCTAssertEqual(satisfiable.count, 2)
        XCTAssertEqual(satisfiable[0].credentialSetIndex, 0)
        XCTAssertEqual(satisfiable[0].optionIndex, 0)
        XCTAssertEqual(satisfiable[0].queryIds, ["pid"])
        XCTAssertEqual(satisfiable[1].optionIndex, 2)
        XCTAssertEqual(satisfiable[1].queryIds, ["cred_1", "cred_2"])
    }

    func testMatchDcqlReturnsFullOutputWithCredentialSets() {
        let credentials = [
            storedCredential(id: 1, format: "dc+sd-jwt", raw: "raw-1",
                              metadata: CredentialMetadata(vct: "urn:eu:pid:1")),
            storedCredential(id: 2, format: "mso_mdoc", raw: "raw-2",
                              metadata: CredentialMetadata(doctype: "org.iso.18013.5.1.mDL")),
        ]

        let query = parseJSON("""
        {
          "credentials": [
            { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eu:pid:1"] },
              "claims": [{ "path": ["given_name"] }] },
            { "id": "mdl", "format": "mso_mdoc", "meta": { "doctype_value": "org.iso.18013.5.1.mDL" } }
          ],
          "credential_sets": [{ "options": [["pid"], ["mdl"]] }]
        }
        """)

        let output = CredentialMatcher.matchDcql(dcqlQuery: query, credentials: credentials)

        XCTAssertEqual(output.queryResults.count, 2)
        XCTAssertEqual(output.queryResults[0].queryId, "pid")
        XCTAssertEqual(output.queryResults[0].candidates.count, 1)
        XCTAssertEqual(output.queryResults[1].queryId, "mdl")
        XCTAssertEqual(output.queryResults[1].candidates.count, 1)

        XCTAssertNotNil(output.credentialSets)
        XCTAssertEqual(output.credentialSets?.count, 1)
        XCTAssertEqual(output.satisfiableOptions.count, 2)
    }

    func testMatchMdocDocTypeFiltersByRealDocTypeParsedFromCbor() {
        let credentials = [
            storedCredential(id: 1, format: "mso_mdoc", raw: mdocRaw(docType: "org.iso.18013.5.1.mDL")),
            storedCredential(id: 2, format: "mso_mdoc", raw: mdocRaw(docType: "eu.europa.ec.eudi.pid.1")),
        ]

        let matches = CredentialMatcher.matchMdocDocType(credentials, docType: "org.iso.18013.5.1.mDL")

        XCTAssertEqual(matches.map(\.id), [1])
    }

    func testMatchMdocDocTypeExcludesNonMdocFormatsEvenWithMatchingDocType() {
        // A DCQL/SD-JWT credential should never be selectable by an
        // ISO 18013-5 proximity request's bare docType string, regardless
        // of what its (irrelevant) format-specific fields happen to contain.
        let credentials = [
            storedCredential(id: 1, format: "dc+sd-jwt", raw: "not-cbor-at-all"),
            storedCredential(id: 2, format: "mso_mdoc", raw: mdocRaw(docType: "org.iso.18013.5.1.mDL")),
        ]

        let matches = CredentialMatcher.matchMdocDocType(credentials, docType: "org.iso.18013.5.1.mDL")

        XCTAssertEqual(matches.map(\.id), [2])
    }

    func testMatchMdocDocTypeReturnsEmptyWhenNoDocTypeMatches() {
        let credentials = [
            storedCredential(id: 1, format: "mso_mdoc", raw: mdocRaw(docType: "com.example.other")),
        ]

        let matches = CredentialMatcher.matchMdocDocType(credentials, docType: "org.iso.18013.5.1.mDL")

        XCTAssertTrue(matches.isEmpty)
    }
}

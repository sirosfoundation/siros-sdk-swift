// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

final class CredentialMatcherTests: XCTestCase {

    private func parseJSON(_ string: String) -> [String: Any] {
        let data = string.data(using: .utf8)!
        return try! JSONSerialization.jsonObject(with: data) as! [String: Any]
    }

    func testMatchFiltersByFormatAndVct() {
        let credentials = [
            StoredCredential(id: "1", format: "dc+sd-jwt", raw: "raw-1",
                             metadata: CredentialMetadata(vct: "urn:eu:pid:1")),
            StoredCredential(id: "2", format: "mso_mdoc", raw: "raw-2",
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
        XCTAssertEqual(results.first?.candidates.map(\.id), ["1"])
        XCTAssertEqual(results.first?.requestedClaims, [["given_name"]])
    }

    func testMatchFiltersByDoctypeForMdoc() {
        let credentials = [
            StoredCredential(id: "pid-doc", format: "mso_mdoc", raw: "raw-1",
                             metadata: CredentialMetadata(doctype: "eu.europa.ec.eudi.pid.1")),
            StoredCredential(id: "other-doc", format: "mso_mdoc", raw: "raw-2",
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
        XCTAssertEqual(matchedIds, ["pid-doc"])
    }

    func testMatchReturnsAllWhenQueryHasNoCredentialsArray() {
        let credentials = [
            StoredCredential(id: "a", format: "dc+sd-jwt", raw: "raw-a"),
            StoredCredential(id: "b", format: "mso_mdoc", raw: "raw-b"),
        ]

        let query = parseJSON("{ \"unexpected\": true }")
        let results = CredentialMatcher.match(dcqlQuery: query, credentials: credentials)

        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results.first?.queryId, "_default")
        let ids = Set(results.first?.candidates.map(\.id) ?? [])
        XCTAssertTrue(ids.contains("a"))
        XCTAssertTrue(ids.contains("b"))
    }

    func testMatchedCredentialIdsAreDistinct() {
        let credentials = [
            StoredCredential(id: "pid-1", format: "dc+sd-jwt", raw: "raw-1",
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
        XCTAssertEqual(matchedIds, ["pid-1"])
    }

    func testMatchExcludesCredentialsWithoutRequiredMetadata() {
        let credentials = [
            StoredCredential(id: "missing-vct", format: "dc+sd-jwt", raw: "raw-1"),
            StoredCredential(id: "missing-doc", format: "mso_mdoc", raw: "raw-2"),
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
            StoredCredential(id: "1", format: "dc+sd-jwt", raw: "raw-1",
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
                candidates: [StoredCredential(id: "1", format: "dc+sd-jwt", raw: "r")],
                requestedClaims: []),
            CredentialMatcher.MatchResult(queryId: "other_pid", format: "dc+sd-jwt",
                candidates: [], requestedClaims: []),
            CredentialMatcher.MatchResult(queryId: "cred_1", format: "dc+sd-jwt",
                candidates: [StoredCredential(id: "2", format: "dc+sd-jwt", raw: "r")],
                requestedClaims: []),
            CredentialMatcher.MatchResult(queryId: "cred_2", format: "dc+sd-jwt",
                candidates: [StoredCredential(id: "3", format: "dc+sd-jwt", raw: "r")],
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
            StoredCredential(id: "my-pid", format: "dc+sd-jwt", raw: "raw-1",
                             metadata: CredentialMetadata(vct: "urn:eu:pid:1")),
            StoredCredential(id: "my-mdl", format: "mso_mdoc", raw: "raw-2",
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
}

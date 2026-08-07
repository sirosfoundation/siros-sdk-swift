// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

final class MddlSchemaFetcherTests: XCTestCase {

    private let sampleMddlSchemaJson = """
    {
      "format": "mso_mdoc",
      "doctype": "org.iso.18013.5.1.mDL",
      "display": [
        { "locale": "en", "name": "Driving Licence" }
      ]
    }
    """

    func testParseMddlSchemaParsesValidJson() {
        let fetcher = MddlSchemaFetcher()
        let schema = fetcher.parseMddlSchema(sampleMddlSchemaJson)

        XCTAssertNotNil(schema)
        XCTAssertEqual(schema?.format, "mso_mdoc")
        XCTAssertEqual(schema?.doctype, "org.iso.18013.5.1.mDL")
        XCTAssertEqual(schema?.display?.first?.name, "Driving Licence")
    }

    func testParseMddlSchemaDefaultsRequiredKeyStorageToNilWhenAbsent() {
        let fetcher = MddlSchemaFetcher()
        let schema = fetcher.parseMddlSchema(sampleMddlSchemaJson)

        XCTAssertNil(schema?.requiredKeyStorage, "absent attestation_los must mean no requirement declared")
    }

    func testParseMddlSchemaParsesAttestationLosAsRequiredKeyStorage() {
        let json = """
        {
          "format": "mso_mdoc",
          "doctype": "org.iso.18013.5.1.mDL",
          "attestation_los": "iso_18045_moderate"
        }
        """
        let fetcher = MddlSchemaFetcher()
        let schema = fetcher.parseMddlSchema(json)

        XCTAssertEqual(schema?.requiredKeyStorage, "iso_18045_moderate")
    }

    func testParseMddlSchemaReturnsNilForInvalidJson() {
        let fetcher = MddlSchemaFetcher()
        XCTAssertNil(fetcher.parseMddlSchema("not json"))
        XCTAssertNil(fetcher.parseMddlSchema(""))
    }

    func testFetchFromTypeMetadataEndpoint() async {
        let fetcher = MddlSchemaFetcher(httpGet: { url in
            if url == "https://issuer.example.com/type-metadata/mdl" {
                return self.sampleMddlSchemaJson
            }
            return nil
        })

        let schema = await fetcher.fetch(issuerUrl: "https://issuer.example.com", scope: "mdl")

        XCTAssertNotNil(schema)
        XCTAssertEqual(schema?.doctype, "org.iso.18013.5.1.mDL")
    }

    func testFetchReturnsNilWhenNotFound() async {
        let fetcher = MddlSchemaFetcher(httpGet: { _ in nil })

        let schema = await fetcher.fetch(issuerUrl: "https://issuer.example.com", scope: "mdl")

        XCTAssertNil(schema)
    }
}

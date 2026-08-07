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

    // MARK: - Registry-service strategy (go-wallet-backend's TS11-backed registry)

    func testFetchUsesRegistryStrategyFirstWhenAvailable() async {
        var calledUrls: [String] = []
        let fetcher = MddlSchemaFetcher(httpGet: { url in
            calledUrls.append(url)
            // Confirmed live: the generic `vct` query param name is used for
            // mdoc doctypes too - same handler/store serves both formats.
            if url == "https://wallet.example.com/registry/type-metadata?vct=org.iso.18013.5.1.mDL" {
                return self.sampleMddlSchemaJson
            }
            XCTFail("registry strategy should short-circuit before issuer-direct fallback: \(url)")
            return nil
        })

        let schema = await fetcher.fetch(
            issuerUrl: "https://issuer.example.com",
            scope: "mdl",
            doctype: "org.iso.18013.5.1.mDL",
            registryUrl: "https://wallet.example.com/registry"
        )

        XCTAssertNotNil(schema)
        XCTAssertEqual(schema?.doctype, "org.iso.18013.5.1.mDL")
        XCTAssertEqual(calledUrls, ["https://wallet.example.com/registry/type-metadata?vct=org.iso.18013.5.1.mDL"])
    }

    func testFetchFallsBackToIssuerDirectWhenRegistryHasNoEntry() async {
        let fetcher = MddlSchemaFetcher(httpGet: { url in
            if url.hasPrefix("https://wallet.example.com/registry") {
                return nil
            }
            if url == "https://issuer.example.com/type-metadata/mdl" {
                return self.sampleMddlSchemaJson
            }
            return nil
        })

        let schema = await fetcher.fetch(
            issuerUrl: "https://issuer.example.com",
            scope: "mdl",
            doctype: "org.iso.18013.5.1.mDL",
            registryUrl: "https://wallet.example.com/registry"
        )

        XCTAssertNotNil(schema, "must fall through to the issuer-direct strategy when the registry has no entry")
    }

    func testFetchSkipsRegistryStrategyWhenRegistryUrlIsNil() async {
        var calledUrls: [String] = []
        let fetcher = MddlSchemaFetcher(httpGet: { url in
            calledUrls.append(url)
            if url == "https://issuer.example.com/type-metadata/mdl" {
                return self.sampleMddlSchemaJson
            }
            return nil
        })

        let schema = await fetcher.fetch(
            issuerUrl: "https://issuer.example.com",
            scope: "mdl",
            doctype: "org.iso.18013.5.1.mDL",
            registryUrl: nil
        )

        XCTAssertNotNil(schema)
        XCTAssertEqual(calledUrls, ["https://issuer.example.com/type-metadata/mdl"], "no registry lookup should ever be attempted")
    }

    func testFetchSkipsRegistryStrategyWhenDoctypeIsNil() async {
        var calledUrls: [String] = []
        let fetcher = MddlSchemaFetcher(httpGet: { url in
            calledUrls.append(url)
            if url == "https://issuer.example.com/type-metadata/mdl" {
                return self.sampleMddlSchemaJson
            }
            return nil
        })

        let schema = await fetcher.fetch(
            issuerUrl: "https://issuer.example.com",
            scope: "mdl",
            doctype: nil,
            registryUrl: "https://wallet.example.com/registry"
        )

        XCTAssertNotNil(schema)
        XCTAssertEqual(calledUrls, ["https://issuer.example.com/type-metadata/mdl"], "no registry lookup should ever be attempted")
    }
}

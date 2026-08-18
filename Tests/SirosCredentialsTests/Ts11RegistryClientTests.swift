// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

final class Ts11RegistryClientTests: XCTestCase {

    private func schemaJson(_ id: String, attestationLoS: String = "iso_18045_high") -> String {
        """
        {
          "id": "\(id)",
          "version": "1.0",
          "attestationLoS": "\(attestationLoS)",
          "bindingType": "jwk",
          "supportedFormats": ["dc+sd-jwt"],
          "schemaURIs": [
            { "formatIdentifier": "dc+sd-jwt", "uri": "https://registry.siros.org/schemas/\(id)/vctm.json" }
          ],
          "rulebookURI": "https://registry.siros.org/schemas/\(id)/rulebook.json"
        }
        """
    }

    // MARK: - Current (paginated data/total/limit/offset) shape

    func testFetchSchemasFollowsPaginationAcrossMultiplePagesOfTheCurrentShape() async {
        let page1 = """
        {"data": [\(schemaJson("diploma")), \(schemaJson("mdl"))], "total": 4, "limit": 2, "offset": 0}
        """
        let page2 = """
        {"data": [\(schemaJson("passport")), \(schemaJson("visa"))], "total": 4, "limit": 2, "offset": 2}
        """

        final class URLBox: @unchecked Sendable { var urls: [String] = [] }
        let calledUrls = URLBox()
        let client = Ts11RegistryClient(httpGet: { url in
            calledUrls.urls.append(url)
            switch url {
            case "https://registry.siros.org/api/v1/schemas.json": return page1
            case "https://registry.siros.org/api/v1/schemas.json?offset=2": return page2
            default: return nil
            }
        })

        let schemas = await client.fetchSchemas()

        XCTAssertEqual(schemas.count, 4)
        XCTAssertEqual(schemas.map(\.id), ["diploma", "mdl", "passport", "visa"])
        XCTAssertEqual(calledUrls.urls.count, 2)
        XCTAssertEqual(schemas[0].attestationLoS, "iso_18045_high")
        XCTAssertEqual(schemas[0].bindingType, "jwk")
        XCTAssertEqual(schemas[0].supportedFormats, ["dc+sd-jwt"])
        XCTAssertEqual(schemas[0].schemaURIs.count, 1)
        XCTAssertEqual(schemas[0].schemaURIs[0].formatIdentifier, "dc+sd-jwt")
    }

    func testFetchSchemasStopsPaginationWhenOffsetPlusEntriesReachesTotal() async {
        final class CallCounter: @unchecked Sendable { var count = 0 }
        let counter = CallCounter()
        let client = Ts11RegistryClient(httpGet: { url in
            counter.count += 1
            if url == "https://registry.siros.org/api/v1/schemas.json" {
                return """
                {"data": [\(self.schemaJson("only-one"))], "total": 1, "limit": 20, "offset": 0}
                """
            }
            return nil
        })

        let schemas = await client.fetchSchemas()

        XCTAssertEqual(schemas.count, 1)
        XCTAssertEqual(schemas[0].id, "only-one")
        XCTAssertEqual(counter.count, 1) // no second page fetched
    }

    // MARK: - Legacy (schemas/next) shape

    func testFetchSchemasFollowsPaginationAcrossTheLegacySchemasNextShape() async {
        let page1 = """
        {"schemas": [\(schemaJson("legacy-a"))], "next": "https://registry.siros.org/api/v1/schemas.json?page=2"}
        """
        let page2 = """
        {"schemas": [\(schemaJson("legacy-b"))], "next": ""}
        """

        let client = Ts11RegistryClient(httpGet: { url in
            switch url {
            case "https://registry.siros.org/api/v1/schemas.json": return page1
            case "https://registry.siros.org/api/v1/schemas.json?page=2": return page2
            default: return nil
            }
        })

        let schemas = await client.fetchSchemas()

        XCTAssertEqual(schemas.count, 2)
        XCTAssertEqual(schemas.map(\.id), ["legacy-a", "legacy-b"])
    }

    func testFetchSchemasHandlesASinglePageLegacyResponseWithNoNextField() async {
        let client = Ts11RegistryClient(httpGet: { url in
            if url == "https://registry.siros.org/api/v1/schemas.json" {
                return """
                {"schemas": [\(self.schemaJson("solo"))]}
                """
            }
            return nil
        })

        let schemas = await client.fetchSchemas()

        XCTAssertEqual(schemas.count, 1)
        XCTAssertEqual(schemas[0].id, "solo")
    }

    // MARK: - registry.json (all-credentials, non-paginated) shape

    func testFetchSchemasParsesTheNonPaginatedRegistryJsonShape() async {
        let client = Ts11RegistryClient(
            sources: ["https://registry.siros.org/api/v1/registry.json"],
            httpGet: { url in
                if url == "https://registry.siros.org/api/v1/registry.json" {
                    return """
                    {
                      "total": 2,
                      "credentials": [
                        {"id": "diploma", "version": "1.0", "supportedFormats": ["dc+sd-jwt"], "attestationLoS": "iso_18045_basic", "bindingType": "jwk"},
                        {"id": "mdl", "version": "1.0", "supportedFormats": ["mso_mdoc"], "attestationLoS": "iso_18045_high", "bindingType": "cose_key"}
                      ]
                    }
                    """
                }
                return nil
            }
        )

        let schemas = await client.fetchSchemas()

        XCTAssertEqual(schemas.count, 2)
        XCTAssertEqual(schemas[0].id, "diploma")
        XCTAssertEqual(schemas[0].attestationLoS, "iso_18045_basic")
        XCTAssertEqual(schemas[1].id, "mdl")
        XCTAssertEqual(schemas[1].attestationLoS, "iso_18045_high")
        XCTAssertTrue(schemas[0].schemaURIs.isEmpty)
    }

    // MARK: - Empty result

    func testFetchSchemasReturnsAnEmptyListForAnEmptyResult() async {
        let client = Ts11RegistryClient(httpGet: { url in
            if url == "https://registry.siros.org/api/v1/schemas.json" {
                return """
                {"data": [], "total": 0, "limit": 20, "offset": 0}
                """
            }
            return nil
        })

        let schemas = await client.fetchSchemas()

        XCTAssertTrue(schemas.isEmpty)
    }

    // MARK: - Malformed / error responses

    func testFetchSchemasReturnsAnEmptyListForAMalformedJsonResponse() async {
        let client = Ts11RegistryClient(httpGet: { _ in "this is not { valid json" })

        let schemas = await client.fetchSchemas()

        XCTAssertTrue(schemas.isEmpty)
    }

    func testFetchSchemasReturnsAnEmptyListWhenTheHttpFetchFails() async {
        let client = Ts11RegistryClient(httpGet: { _ in nil })

        let schemas = await client.fetchSchemas()

        XCTAssertTrue(schemas.isEmpty)
    }

    func testFetchSchemasStopsPaginationGracefullyWhenALaterPageIsMalformed() async {
        let client = Ts11RegistryClient(httpGet: { url in
            switch url {
            case "https://registry.siros.org/api/v1/schemas.json":
                return """
                {"data": [\(self.schemaJson("first"))], "total": 4, "limit": 1, "offset": 0}
                """
            case "https://registry.siros.org/api/v1/schemas.json?offset=1":
                return "not valid json"
            default:
                return nil
            }
        })

        let schemas = await client.fetchSchemas()

        // First page's entries are preserved even though the second page failed.
        XCTAssertEqual(schemas.count, 1)
        XCTAssertEqual(schemas[0].id, "first")
    }

    // MARK: - Multi-source config

    func testFetchSchemasDefaultsToASingleRegistrySirosOrgSource() async {
        final class URLBox: @unchecked Sendable { var url: String? }
        let box = URLBox()
        let client = Ts11RegistryClient(httpGet: { url in
            box.url = url
            return nil
        })

        _ = await client.fetchSchemas()

        XCTAssertEqual(box.url, "https://registry.siros.org/api/v1/schemas.json")
    }

    func testFetchSchemasMergesEntriesAcrossSourcesWithLaterSourcesOverwritingEarlierOnes() async {
        let client = Ts11RegistryClient(
            sources: [
                "https://registry.siros.org",
                "https://other-registry.example.org",
            ],
            httpGet: { url in
                switch url {
                case "https://registry.siros.org/api/v1/schemas.json":
                    return """
                    {"data": [\(self.schemaJson("diploma", attestationLoS: "iso_18045_basic")), \(self.schemaJson("mdl"))], "total": 2, "limit": 20, "offset": 0}
                    """
                case "https://other-registry.example.org/api/v1/schemas.json":
                    return """
                    {"data": [\(self.schemaJson("diploma", attestationLoS: "iso_18045_high"))], "total": 1, "limit": 20, "offset": 0}
                    """
                default:
                    return nil
                }
            }
        )

        let schemas = await client.fetchSchemas()

        XCTAssertEqual(schemas.count, 2)
        let diploma = schemas.first { $0.id == "diploma" }
        // The second source's entry for "diploma" overwrote the first's.
        XCTAssertEqual(diploma?.attestationLoS, "iso_18045_high")
        XCTAssertTrue(schemas.contains { $0.id == "mdl" })
    }

    func testFetchSchemasSkipsAFailingSourceAndStillReturnsEntriesFromASucceedingOne() async {
        let client = Ts11RegistryClient(
            sources: [
                "https://unreachable-registry.example.org",
                "https://registry.siros.org",
            ],
            httpGet: { url in
                if url == "https://registry.siros.org/api/v1/schemas.json" {
                    return """
                    {"data": [\(self.schemaJson("diploma"))], "total": 1, "limit": 20, "offset": 0}
                    """
                }
                return nil // unreachable source fails
            }
        )

        let schemas = await client.fetchSchemas()

        XCTAssertEqual(schemas.count, 1)
        XCTAssertEqual(schemas[0].id, "diploma")
    }

    func testFetchSchemasUsesAnExplicitJsonUrlSourceAsIs() async {
        final class URLBox: @unchecked Sendable { var url: String? }
        let box = URLBox()
        let client = Ts11RegistryClient(
            sources: ["https://registry.siros.org/api/v1/registry.json"],
            httpGet: { url in
                box.url = url
                return nil
            }
        )

        _ = await client.fetchSchemas()

        XCTAssertEqual(box.url, "https://registry.siros.org/api/v1/registry.json")
    }

    // MARK: - Ts11CredentialDiscovery: display-identity enrichment

    func testDiscoverResolvesVctNameAndDescriptionFromAMockedVctmDocument() async {
        let registryClient = Ts11RegistryClient(httpGet: { url in
            if url == "https://registry.siros.org/api/v1/schemas.json" {
                return """
                {"data": [\(self.schemaJson("diploma"))], "total": 1, "limit": 20, "offset": 0}
                """
            }
            return nil
        })
        let discovery = Ts11CredentialDiscovery(
            registryClient: registryClient,
            httpGet: { url in
                if url == "https://registry.siros.org/schemas/diploma/vctm.json" {
                    return """
                    {
                      "vct": "https://example.org/vct/diploma",
                      "name": "University Diploma",
                      "description": "A verifiable higher-education diploma"
                    }
                    """
                }
                return nil
            }
        )

        let discovered = await discovery.discover()

        XCTAssertEqual(discovered.count, 1)
        let dc = discovered[0]
        XCTAssertEqual(dc.schema.id, "diploma")
        XCTAssertEqual(dc.identifier, "https://example.org/vct/diploma")
        XCTAssertEqual(dc.name, "University Diploma")
        XCTAssertEqual(dc.description, "A verifiable higher-education diploma")
        XCTAssertEqual(dc.displayName, "University Diploma")
    }

    func testDiscoverResolvesDoctypeAndDisplayNameFromAMockedMddlDocument() async {
        let mdlSchemaJson = """
        {
          "id": "mdl",
          "version": "1.0",
          "attestationLoS": "iso_18045_high",
          "bindingType": "cose_key",
          "supportedFormats": ["mso_mdoc"],
          "schemaURIs": [
            { "formatIdentifier": "mso_mdoc", "uri": "https://registry.siros.org/schemas/mdl/mddl.json" }
          ]
        }
        """
        let registryClient = Ts11RegistryClient(httpGet: { url in
            if url == "https://registry.siros.org/api/v1/schemas.json" {
                return """
                {"data": [\(mdlSchemaJson)], "total": 1, "limit": 20, "offset": 0}
                """
            }
            return nil
        })
        let discovery = Ts11CredentialDiscovery(
            registryClient: registryClient,
            httpGet: { url in
                if url == "https://registry.siros.org/schemas/mdl/mddl.json" {
                    return """
                    {
                      "format": "mso_mdoc",
                      "doctype": "org.iso.18013.5.1.mDL",
                      "display": [
                        {"locale": "en", "name": "Mobile Driving Licence", "description": "ISO 18013-5 mDL"}
                      ]
                    }
                    """
                }
                return nil
            }
        )

        let discovered = await discovery.discover()

        XCTAssertEqual(discovered.count, 1)
        let dc = discovered[0]
        XCTAssertEqual(dc.schema.id, "mdl")
        XCTAssertEqual(dc.identifier, "org.iso.18013.5.1.mDL")
        XCTAssertEqual(dc.name, "Mobile Driving Licence")
        XCTAssertEqual(dc.description, "ISO 18013-5 mDL")
    }

    func testDiscoverFallsBackToTheRawRegistryIdWhenTheSchemaDocumentFetchFails() async {
        let registryClient = Ts11RegistryClient(httpGet: { url in
            if url == "https://registry.siros.org/api/v1/schemas.json" {
                return """
                {"data": [\(self.schemaJson("diploma"))], "total": 1, "limit": 20, "offset": 0}
                """
            }
            return nil
        })
        // Document fetch always fails - discovery must degrade gracefully to
        // the raw id, not throw, and not drop the entry.
        let discovery = Ts11CredentialDiscovery(
            registryClient: registryClient,
            httpGet: { _ in nil }
        )

        let discovered = await discovery.discover()

        XCTAssertEqual(discovered.count, 1)
        let dc = discovered[0]
        XCTAssertEqual(dc.identifier, "diploma")
        XCTAssertNil(dc.name)
        XCTAssertNil(dc.description)
        XCTAssertEqual(dc.displayName, "diploma")
    }

    func testDiscoverFallsBackToTheRawRegistryIdWhenNoRecognizedFormatIsInSchemaUris() async {
        let unknownFormatSchema = """
        {
          "id": "unknown-fmt",
          "version": "1.0",
          "attestationLoS": "iso_18045_basic",
          "bindingType": "jwk",
          "supportedFormats": ["some_future_format"],
          "schemaURIs": [
            { "formatIdentifier": "some_future_format", "uri": "https://registry.siros.org/schemas/unknown-fmt/doc.json" }
          ]
        }
        """
        let registryClient = Ts11RegistryClient(httpGet: { url in
            if url == "https://registry.siros.org/api/v1/schemas.json" {
                return """
                {"data": [\(unknownFormatSchema)], "total": 1, "limit": 20, "offset": 0}
                """
            }
            return nil
        })
        let discovery = Ts11CredentialDiscovery(
            registryClient: registryClient,
            httpGet: { _ in
                XCTFail("should never fetch a document for an unrecognized format")
                return nil
            }
        )

        let discovered = await discovery.discover()

        XCTAssertEqual(discovered.count, 1)
        XCTAssertEqual(discovered[0].identifier, "unknown-fmt")
        XCTAssertNil(discovered[0].name)
    }

    func testDiscoverFallsBackToTheRawRegistryIdWhenTheDocumentBodyIsUnparseable() async {
        let registryClient = Ts11RegistryClient(httpGet: { url in
            if url == "https://registry.siros.org/api/v1/schemas.json" {
                return """
                {"data": [\(self.schemaJson("diploma"))], "total": 1, "limit": 20, "offset": 0}
                """
            }
            return nil
        })
        let discovery = Ts11CredentialDiscovery(
            registryClient: registryClient,
            httpGet: { _ in "not valid json at all" }
        )

        let discovered = await discovery.discover()

        XCTAssertEqual(discovered.count, 1)
        XCTAssertEqual(discovered[0].identifier, "diploma")
        XCTAssertNil(discovered[0].name)
    }

    func testDiscoverEnrichesMultipleEntriesIndependentlyOneBadEntryDoesNotBlockTheRest() async {
        let page = """
        {"data": [\(schemaJson("diploma")), \(schemaJson("passport"))], "total": 2, "limit": 20, "offset": 0}
        """
        let registryClient = Ts11RegistryClient(httpGet: { url in
            url == "https://registry.siros.org/api/v1/schemas.json" ? page : nil
        })
        let discovery = Ts11CredentialDiscovery(
            registryClient: registryClient,
            httpGet: { url in
                if url == "https://registry.siros.org/schemas/diploma/vctm.json" {
                    return """
                    {"vct": "https://example.org/vct/diploma", "name": "Diploma"}
                    """
                }
                // passport's document fetch fails - only that entry should fall back.
                return nil
            }
        )

        let discovered = await discovery.discover()

        XCTAssertEqual(discovered.count, 2)
        let diploma = discovered.first { $0.schema.id == "diploma" }
        let passport = discovered.first { $0.schema.id == "passport" }
        XCTAssertEqual(diploma?.name, "Diploma")
        XCTAssertEqual(diploma?.identifier, "https://example.org/vct/diploma")
        XCTAssertNil(passport?.name)
        XCTAssertEqual(passport?.identifier, "passport")
    }
}

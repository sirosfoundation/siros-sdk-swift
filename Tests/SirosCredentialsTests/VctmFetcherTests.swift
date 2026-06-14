// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

final class VctmFetcherTests: XCTestCase {

    private let sampleVctmJson = """
    {
      "vct": "urn:eu:pid:1",
      "display": [
        {
          "locale": "en",
          "name": "PID",
          "description": "Person Identification Data",
          "rendering": {
            "simple": {
              "background_color": "#003366",
              "text_color": "#ffffff",
              "logo": { "uri": "https://example.com/logo.png", "alt_text": "Logo" }
            }
          }
        }
      ],
      "claims": [
        {
          "path": ["given_name"],
          "display": [{ "locale": "en", "label": "Given Name" }],
          "sd": "always",
          "mandatory": true
        }
      ]
    }
    """

    func testParseVctmParsesValidJson() {
        let fetcher = VctmFetcher()
        let vctm = fetcher.parseVctm(sampleVctmJson)

        XCTAssertNotNil(vctm)
        XCTAssertEqual(vctm?.vct, "urn:eu:pid:1")
        XCTAssertEqual(vctm?.display?.count, 1)
        XCTAssertEqual(vctm?.display?.first?.name, "PID")
        XCTAssertEqual(vctm?.display?.first?.rendering?.simple?.backgroundColor, "#003366")
        XCTAssertEqual(vctm?.claims?.count, 1)
        XCTAssertEqual(vctm?.claims?.first?.path, ["given_name"])
        XCTAssertEqual(vctm?.claims?.first?.mandatory, true)
    }

    func testParseVctmReturnsNilForInvalidJson() {
        let fetcher = VctmFetcher()
        XCTAssertNil(fetcher.parseVctm("not json"))
        XCTAssertNil(fetcher.parseVctm(""))
    }

    func testFetchFromTypeMetadataEndpoint() async {
        let fetcher = VctmFetcher(httpGet: { url in
            if url == "https://issuer.example.com/type-metadata/diploma" {
                return self.sampleVctmJson
            }
            return nil
        })

        let vctm = await fetcher.fetch(
            issuerUrl: "https://issuer.example.com",
            scope: "diploma"
        )

        XCTAssertNotNil(vctm)
        XCTAssertEqual(vctm?.vct, "urn:eu:pid:1")
    }

    func testFetchTrimsTrailingSlashFromIssuerUrl() async {
        let fetcher = VctmFetcher(httpGet: { url in
            if url == "https://issuer.example.com/type-metadata/scope" {
                return self.sampleVctmJson
            }
            return nil
        })

        let vctm = await fetcher.fetch(
            issuerUrl: "https://issuer.example.com/",
            scope: "scope"
        )

        XCTAssertNotNil(vctm)
    }

    func testFetchFallsBackToWellKnownUrl() async {
        let fetcher = VctmFetcher(httpGet: { url in
            if url == "https://example.com/.well-known/vct/types/pid" {
                return self.sampleVctmJson
            }
            return nil
        })

        let vctm = await fetcher.fetch(
            issuerUrl: "https://issuer.example.com",
            scope: "diploma",
            vct: "https://example.com/types/pid"
        )

        XCTAssertNotNil(vctm)
        XCTAssertEqual(vctm?.vct, "urn:eu:pid:1")
    }

    func testFetchReturnsNilWhenBothFail() async {
        let fetcher = VctmFetcher(httpGet: { _ in nil })

        let vctm = await fetcher.fetch(
            issuerUrl: "https://issuer.example.com",
            scope: "diploma",
            vct: "https://example.com/types/pid"
        )

        XCTAssertNil(vctm)
    }

    func testFetchReturnsNilForInvalidVctUrl() async {
        let fetcher = VctmFetcher(httpGet: { _ in nil })

        let vctm = await fetcher.fetch(
            issuerUrl: "https://issuer.example.com",
            scope: "diploma",
            vct: "not-a-url"
        )

        XCTAssertNil(vctm)
    }

    func testFetchReturnsNilWhenNoVctProvided() async {
        let fetcher = VctmFetcher(httpGet: { _ in nil })

        let vctm = await fetcher.fetch(
            issuerUrl: "https://issuer.example.com",
            scope: "diploma"
        )

        XCTAssertNil(vctm)
    }
}

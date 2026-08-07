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

    func testParseVctmDefaultsRequiredKeyStorageToNilWhenAbsent() {
        let fetcher = VctmFetcher()
        let vctm = fetcher.parseVctm(sampleVctmJson)

        XCTAssertNotNil(vctm)
        XCTAssertNil(vctm?.requiredKeyStorage, "absent attestation_los must mean no requirement declared")
    }

    func testParseVctmParsesAttestationLosAsRequiredKeyStorage() {
        let json = """
        {
          "vct": "urn:eu:pid:1",
          "attestation_los": "iso_18045_high"
        }
        """
        let fetcher = VctmFetcher()
        let vctm = fetcher.parseVctm(json)

        XCTAssertEqual(vctm?.requiredKeyStorage, "iso_18045_high")
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

    // MARK: - Registry-service strategy (go-wallet-backend's TS11-backed registry)

    func testFetchUsesRegistryStrategyFirstWhenAvailable() async {
        var calledUrls: [String] = []
        let fetcher = VctmFetcher(httpGet: { url in
            calledUrls.append(url)
            if url == "https://wallet.example.com/registry/type-metadata?vct=urn:eudi:diploma:1" {
                return self.sampleVctmJson
            }
            // The issuer-direct strategies must NOT even be reached.
            XCTFail("registry strategy should short-circuit before issuer-direct fallbacks: \(url)")
            return nil
        })

        let vctm = await fetcher.fetch(
            issuerUrl: "https://issuer.example.com",
            scope: "diploma",
            vct: "urn:eudi:diploma:1",
            registryUrl: "https://wallet.example.com/registry"
        )

        XCTAssertNotNil(vctm)
        XCTAssertEqual(vctm?.vct, "urn:eu:pid:1")
        XCTAssertEqual(calledUrls, ["https://wallet.example.com/registry/type-metadata?vct=urn:eudi:diploma:1"])
    }

    func testFetchFallsBackToIssuerDirectWhenRegistryHasNoEntry() async {
        // Registry returns nothing (e.g. a live 404 - `fetchFromUrl` already
        // treats any non-200 as `nil`), so the existing issuer-hosted
        // `/type-metadata/<scope>` strategy must still run as a fallback.
        let fetcher = VctmFetcher(httpGet: { url in
            if url.hasPrefix("https://wallet.example.com/registry") {
                return nil
            }
            if url == "https://issuer.example.com/type-metadata/diploma" {
                return self.sampleVctmJson
            }
            return nil
        })

        let vctm = await fetcher.fetch(
            issuerUrl: "https://issuer.example.com",
            scope: "diploma",
            vct: "urn:eudi:diploma:1",
            registryUrl: "https://wallet.example.com/registry"
        )

        XCTAssertNotNil(vctm, "must fall through to the issuer-direct strategy when the registry has no entry")
    }

    func testFetchSkipsRegistryStrategyWhenRegistryUrlIsNil() async {
        var calledUrls: [String] = []
        let fetcher = VctmFetcher(httpGet: { url in
            calledUrls.append(url)
            if url == "https://issuer.example.com/type-metadata/diploma" {
                return self.sampleVctmJson
            }
            return nil
        })

        let vctm = await fetcher.fetch(
            issuerUrl: "https://issuer.example.com",
            scope: "diploma",
            vct: "urn:eudi:diploma:1",
            registryUrl: nil
        )

        XCTAssertNotNil(vctm)
        XCTAssertEqual(calledUrls, ["https://issuer.example.com/type-metadata/diploma"], "no registry lookup should ever be attempted")
    }

    func testFetchSkipsRegistryStrategyWhenVctIsNil() async {
        // A registry URL is configured, but this call site doesn't know the
        // vct yet (e.g. resolved only after a credential is issued) - the
        // registry strategy can't run, matching the existing well-known
        // strategy's own nil-vct behavior.
        var calledUrls: [String] = []
        let fetcher = VctmFetcher(httpGet: { url in
            calledUrls.append(url)
            if url == "https://issuer.example.com/type-metadata/diploma" {
                return self.sampleVctmJson
            }
            return nil
        })

        let vctm = await fetcher.fetch(
            issuerUrl: "https://issuer.example.com",
            scope: "diploma",
            vct: nil,
            registryUrl: "https://wallet.example.com/registry"
        )

        XCTAssertNotNil(vctm)
        XCTAssertEqual(calledUrls, ["https://issuer.example.com/type-metadata/diploma"], "no registry lookup should ever be attempted")
    }

    // MARK: - In-memory TTL cache

    func testFetchCachesSuccessfulResultWithinTtl() async {
        var callCount = 0
        let fetcher = VctmFetcher(httpGet: { _ in
            callCount += 1
            return self.sampleVctmJson
        }, cacheTtlSeconds: 1800)

        let first = await fetcher.fetch(issuerUrl: "https://issuer.example.com", scope: "diploma")
        let second = await fetcher.fetch(issuerUrl: "https://issuer.example.com", scope: "diploma")

        XCTAssertNotNil(first)
        XCTAssertNotNil(second)
        XCTAssertEqual(callCount, 1, "second call within TTL must be served from cache, not hit the network again")
    }

    func testFetchDoesNotServeCacheForDifferentParameters() async {
        var callCount = 0
        let fetcher = VctmFetcher(httpGet: { _ in
            callCount += 1
            return self.sampleVctmJson
        }, cacheTtlSeconds: 1800)

        _ = await fetcher.fetch(issuerUrl: "https://issuer.example.com", scope: "diploma")
        _ = await fetcher.fetch(issuerUrl: "https://issuer.example.com", scope: "degree")
        _ = await fetcher.fetch(issuerUrl: "https://other-issuer.example.com", scope: "diploma")

        XCTAssertEqual(callCount, 3, "different scope/issuerUrl must never be served from another key's cache entry")
    }

    func testFetchDoesNotServeCacheForDifferentVctOrRegistryUrl() async {
        var callCount = 0
        let fetcher = VctmFetcher(httpGet: { _ in
            callCount += 1
            return self.sampleVctmJson
        }, cacheTtlSeconds: 1800)

        _ = await fetcher.fetch(
            issuerUrl: "https://issuer.example.com",
            scope: "diploma",
            vct: "urn:eudi:diploma:1",
            registryUrl: "https://wallet.example.com/registry"
        )
        _ = await fetcher.fetch(
            issuerUrl: "https://issuer.example.com",
            scope: "diploma",
            vct: "urn:eudi:diploma:2",
            registryUrl: "https://wallet.example.com/registry"
        )
        _ = await fetcher.fetch(
            issuerUrl: "https://issuer.example.com",
            scope: "diploma",
            vct: "urn:eudi:diploma:1",
            registryUrl: "https://other-wallet.example.com/registry"
        )

        XCTAssertEqual(callCount, 3, "different vct/registryUrl must never be served from another key's cache entry")
    }

    func testFetchRefetchesAfterTtlExpires() async {
        var callCount = 0
        let fetcher = VctmFetcher(httpGet: { _ in
            callCount += 1
            return self.sampleVctmJson
        }, cacheTtlSeconds: 0.05)

        _ = await fetcher.fetch(issuerUrl: "https://issuer.example.com", scope: "diploma")
        try? await Task.sleep(nanoseconds: 150_000_000) // 150ms > 50ms TTL
        _ = await fetcher.fetch(issuerUrl: "https://issuer.example.com", scope: "diploma")

        XCTAssertEqual(callCount, 2, "a call after TTL expiry must hit the network again")
    }

    func testFetchNeverCachesAFailedLookup() async {
        var callCount = 0
        let fetcher = VctmFetcher(httpGet: { _ in
            callCount += 1
            return nil
        }, cacheTtlSeconds: 1800)

        let first = await fetcher.fetch(issuerUrl: "https://issuer.example.com", scope: "diploma")
        let second = await fetcher.fetch(issuerUrl: "https://issuer.example.com", scope: "diploma")

        XCTAssertNil(first)
        XCTAssertNil(second)
        XCTAssertEqual(callCount, 2, "a nil result must never be cached - every call must retry all strategies fresh")
    }
}

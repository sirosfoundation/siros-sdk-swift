// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Resolution directed by `vct#integrity`.
///
/// A credential pins a digest over its type metadata so the issuer, rather than
/// whoever serves the document, decides what the type means. These tests cover
/// what that means for resolution: a document that does not hash to the pin is
/// not the document, whatever cache or source produced it.
///
/// The bug these were written for (siros-sdk-kotlin#191, found on a Pixel): a
/// wallet checked an issued credential against a copy of the type metadata
/// cached earlier, refused the credential, and stayed wrong until the cache
/// expired — no server-side fix could reach the device.
///
/// Mirrors the Kotlin SDK's `VctmIntegrityDirectedFetchTest`, minus its
/// negative-cache cases: this fetcher's cache is in-memory and positive-only,
/// so there is no negative entry to serve a stale body and no retry window to
/// bypass. See the PR for why that half does not port.
final class VctmIntegrityDirectedFetchTests: XCTestCase {

    private let issuer = "https://issuer.example"
    private let scope = "pid_1_8"
    private let registry = "https://backend.example/registry"
    private let vct = "urn:eudi:pid:arf-1.8:1"

    private let current = #"{"vct":"urn:eudi:pid:arf-1.8:1","name":"PID"}"#
    private let stale = #"{"vct":"urn:eudi:pid:arf-1.8:1","name":"PID (old)"}"#

    private func sri(_ body: String) -> String {
        "sha256-" + Data(SHA256.hash(data: Data(body.utf8))).base64EncodedString()
    }

    /// Counts requests so a test can tell a cache hit from a fetch.
    private final class Server: @unchecked Sendable {
        private let lock = NSLock()
        private var count = 0
        private let bodyForUrl: @Sendable (String) -> String?
        var served: Int { lock.lock(); defer { lock.unlock() }; return count }

        init(_ bodyForUrl: @escaping @Sendable (String) -> String?) {
            self.bodyForUrl = bodyForUrl
        }

        var httpGet: @Sendable (String) async -> String? {
            { [self] url in
                self.lock.lock(); self.count += 1; self.lock.unlock()
                return self.bodyForUrl(url)
            }
        }
    }

    /// A cached document is only a hit for a caller it can satisfy. The whole
    /// point: a document cached before the issuer changed what it publishes
    /// must not keep being handed to credentials pinned to the new one - which
    /// is exactly how the device in the original report stayed wrong.
    func testACachedDocumentThatDoesNotMatchThePinIsNotUsed() async {
        var bodies = [stale, current]
        let lock = NSLock()
        let fetcher = VctmFetcher(httpGet: { @Sendable _ in
            lock.lock(); defer { lock.unlock() }
            return bodies.isEmpty ? nil : bodies.removeFirst()
        })

        let first = await fetcher.fetchDocument(issuerUrl: issuer, scope: scope, registryUrl: registry)
        XCTAssertEqual(first?.raw, stale, "an unpinned caller takes what it is given")

        let second = await fetcher.fetchDocument(
            issuerUrl: issuer,
            scope: scope,
            registryUrl: registry,
            expectedIntegrity: sri(current)
        )
        XCTAssertEqual(second?.raw, current, "the pinned caller is not served the cached stale document")
    }

    /// With an expectation, a source answering with the wrong document is no
    /// better than one that does not answer.
    func testASourceServingTheWrongDocumentIsPassedOverForOneThatMatches() async {
        // The registry answers with the old document; the issuer's own endpoint
        // has the one the credential was signed over.
        let registryPrefix = registry
        let fetcher = VctmFetcher(httpGet: { @Sendable url in
            url.hasPrefix(registryPrefix) ? self.stale : self.current
        })

        let doc = await fetcher.fetchDocument(
            issuerUrl: issuer,
            scope: scope,
            vct: vct,
            registryUrl: registry,
            expectedIntegrity: sri(current)
        )

        XCTAssertEqual(doc?.raw, current)
    }

    /// Never the wrong document: a wallet that cannot find what was pinned
    /// resolves to nothing, and its caller decides what that means.
    func testNothingMatchingAnywhereResolvesToNothing() async {
        let fetcher = VctmFetcher(httpGet: { @Sendable _ in self.stale })

        let doc = await fetcher.fetchDocument(
            issuerUrl: issuer,
            scope: scope,
            vct: vct,
            registryUrl: registry,
            expectedIntegrity: sri(current)
        )

        XCTAssertNil(doc)
    }

    /// Without a pin, nothing changes: the first parseable body still wins and
    /// the cache still answers.
    func testWithoutAPinTheFirstSourceStillWins() async {
        let server = Server { _ in self.stale }
        let fetcher = VctmFetcher(httpGet: server.httpGet)

        let first = await fetcher.fetchDocument(issuerUrl: issuer, scope: scope, registryUrl: registry)
        let second = await fetcher.fetchDocument(issuerUrl: issuer, scope: scope, registryUrl: registry)

        XCTAssertEqual(first?.raw, stale)
        XCTAssertEqual(second?.raw, stale)
        XCTAssertEqual(server.served, 1, "the second call is served from cache, exactly as before")
    }

    /// A document that matches the pin is cached, so the heal is not paid for
    /// on every credential in a batch.
    func testADocumentThatMatchesThePinIsCached() async {
        let server = Server { _ in self.current }
        let fetcher = VctmFetcher(httpGet: server.httpGet)
        let pin = sri(current)

        _ = await fetcher.fetchDocument(
            issuerUrl: issuer, scope: scope, registryUrl: registry, expectedIntegrity: pin
        )
        let servedAfterFirst = server.served
        let again = await fetcher.fetchDocument(
            issuerUrl: issuer, scope: scope, registryUrl: registry, expectedIntegrity: pin
        )

        XCTAssertEqual(again?.raw, current)
        XCTAssertEqual(server.served, servedAfterFirst, "the second pinned call is a cache hit")
    }
}

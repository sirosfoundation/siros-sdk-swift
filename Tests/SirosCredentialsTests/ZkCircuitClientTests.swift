// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosTransport
@testable import SirosCredentials
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

final class ZkCircuitClientTests: XCTestCase {

    private let sampleManifestJson = """
    {
      "manifestVersion": 1,
      "generatedAt": "2026-08-01T00:00:00Z",
      "catalog": "siros-zk-circuits",
      "circuits": [
        {
          "id": "mdl-age-over-18-v1",
          "system": "longfellow",
          "systemVersion": "1.0.0",
          "docTypes": ["org.iso.18013.5.1.mDL"],
          "published": true,
          "status": "active",
          "params": {"num_attributes": 1},
          "artifact": {
            "url": "/v1/artifacts/sha256/1276a67e4b3be8107acb7588aecdc33284ed6c5e663b13d13fe67f2cb91cf1e5",
            "hash": "1276a67e4b3be8107acb7588aecdc33284ed6c5e663b13d13fe67f2cb91cf1e5",
            "size": 22,
            "compression": "none",
            "mediaType": "application/octet-stream"
          },
          "publishedAt": "2026-08-01T00:00:00Z"
        }
      ],
      "next": null
    }
    """

    private let sampleCircuitJson = """
    {
      "id": "mdl-age-over-18-v1",
      "aliases": ["mdl-age-over-18"],
      "system": "longfellow",
      "systemVersion": "1.0.0",
      "docTypes": ["org.iso.18013.5.1.mDL"],
      "published": true,
      "status": "active",
      "params": {"num_attributes": 1},
      "publishedAt": "2026-08-01T00:00:00Z"
    }
    """

    // MARK: - fetchManifest

    func testFetchManifestSucceedsFromFirstSource() async throws {
        let client = ZkCircuitClient(sources: ["https://primary.example.com"], httpGet: { url in
            XCTAssertEqual(url.absoluteString, "https://primary.example.com/v1/manifest.json")
            return Data(self.sampleManifestJson.utf8)
        })

        let manifest = try await client.fetchManifest()

        XCTAssertEqual(manifest.manifestVersion, 1)
        XCTAssertEqual(manifest.catalog, "siros-zk-circuits")
        XCTAssertEqual(manifest.circuits.count, 1)
        XCTAssertEqual(manifest.circuits.first?.id, "mdl-age-over-18-v1")
        XCTAssertEqual(manifest.circuits.first?.params["num_attributes"]?.intValue, 1)
        XCTAssertNil(manifest.next)
    }

    func testFetchManifestFallsBackToSecondSourceWhenFirstFails() async throws {
        var calledUrls: [String] = []
        let client = ZkCircuitClient(
            sources: ["https://down.example.com", "https://mirror.example.com"],
            httpGet: { url in
                calledUrls.append(url.absoluteString)
                if url.host == "down.example.com" {
                    throw SirosError.network(message: "connection refused")
                }
                return Data(self.sampleManifestJson.utf8)
            }
        )

        let manifest = try await client.fetchManifest()

        XCTAssertEqual(manifest.catalog, "siros-zk-circuits")
        XCTAssertEqual(calledUrls, [
            "https://down.example.com/v1/manifest.json",
            "https://mirror.example.com/v1/manifest.json",
        ], "must try sources in order and stop at the first success, not merge/race them")
    }

    func testFetchManifestThrowsAllSourcesFailedWhenEveryMirrorFails() async {
        let client = ZkCircuitClient(
            sources: ["https://down1.example.com", "https://down2.example.com"],
            httpGet: { _ in throw SirosError.network(message: "boom") }
        )

        do {
            _ = try await client.fetchManifest()
            XCTFail("expected allSourcesFailed to be thrown")
        } catch let error as ZkCircuitClientError {
            guard case .allSourcesFailed(let underlying) = error else {
                XCTFail("expected .allSourcesFailed, got \(error)")
                return
            }
            XCTAssertEqual(underlying.count, 2, "one underlying error per attempted source")
        } catch {
            XCTFail("expected ZkCircuitClientError, got \(error)")
        }
    }

    // MARK: - fetchCircuit

    func testFetchCircuitById() async throws {
        let client = ZkCircuitClient(sources: ["https://primary.example.com"], httpGet: { url in
            XCTAssertEqual(url.absoluteString, "https://primary.example.com/v1/circuits/mdl-age-over-18-v1.json")
            return Data(self.sampleCircuitJson.utf8)
        })

        let descriptor = try await client.fetchCircuit(id: "mdl-age-over-18-v1")

        XCTAssertEqual(descriptor.id, "mdl-age-over-18-v1")
        XCTAssertEqual(descriptor.aliases, ["mdl-age-over-18"])
        XCTAssertEqual(descriptor.system, "longfellow")
        XCTAssertEqual(descriptor.docTypes, ["org.iso.18013.5.1.mDL"])
        XCTAssertNil(descriptor.artifact, "this fixture has no artifact field")
    }

    // MARK: - downloadArtifact

    func testDownloadArtifactSucceedsWhenHashMatches() async throws {
        let bytes = Data("hello-zk-circuit-bytes".utf8)
        let expectedHash = "1276a67e4b3be8107acb7588aecdc33284ed6c5e663b13d13fe67f2cb91cf1e5"
        let descriptor = ZkCircuitDescriptor(
            id: "test-circuit",
            system: "longfellow",
            systemVersion: "1.0.0",
            published: true,
            status: "active",
            artifact: ZkArtifact(
                url: "/v1/artifacts/sha256/\(expectedHash)",
                hash: expectedHash,
                size: Int64(bytes.count),
                compression: "none",
                mediaType: "application/octet-stream"
            ),
            publishedAt: "2026-08-01T00:00:00Z"
        )
        let client = ZkCircuitClient(sources: ["https://primary.example.com"], httpGet: { url in
            XCTAssertEqual(url.absoluteString, "https://primary.example.com/v1/artifacts/sha256/\(expectedHash)")
            return bytes
        })

        let downloaded = try await client.downloadArtifact(descriptor)

        XCTAssertEqual(downloaded, bytes)
    }

    func testDownloadArtifactMatchesARealSha256PrefixedDescriptorHashNotJustABareHexFixture() async throws {
        // Real go-zk-circuits descriptors wire the hash as "sha256:<hex>"
        // (confirmed live against zk-circuits.fly.dev) - unlike this file's
        // other fixtures, which use a bare hex hash and would not have
        // caught the real bug this regression-tests: the comparison used to
        // always fail for a correct download because one side of the
        // comparison never had the prefix stripped.
        let bytes = Data("circuit-bytes".utf8)
        let digest = SHA256.hash(data: bytes)
        let hash = digest.map { String(format: "%02x", $0) }.joined()
        let descriptor = ZkCircuitDescriptor(
            id: "longfellow-mdl-v1",
            system: "longfellow",
            systemVersion: "1.0.0",
            published: true,
            status: "active",
            artifact: ZkArtifact(
                url: "/v1/artifacts/sha256/\(hash)",
                hash: "sha256:\(hash)",
                size: Int64(bytes.count),
                compression: "none",
                mediaType: "application/octet-stream"
            ),
            publishedAt: "2026-08-01T00:00:00Z"
        )
        let client = ZkCircuitClient(sources: ["https://zk-circuits.fly.dev"], httpGet: { url in
            XCTAssertEqual(url.absoluteString, "https://zk-circuits.fly.dev/v1/artifacts/sha256/\(hash)")
            return bytes
        })

        let downloaded = try await client.downloadArtifact(descriptor)

        XCTAssertEqual(downloaded, bytes)
    }

    func testDownloadArtifactThrowsOnHashMismatch() async {
        let bytes = Data("tampered-bytes".utf8)
        let descriptor = ZkCircuitDescriptor(
            id: "test-circuit",
            system: "longfellow",
            systemVersion: "1.0.0",
            published: true,
            status: "active",
            artifact: ZkArtifact(
                url: "/v1/artifacts/sha256/deadbeef",
                hash: "1276a67e4b3be8107acb7588aecdc33284ed6c5e663b13d13fe67f2cb91cf1e5",
                size: Int64(bytes.count),
                compression: "none",
                mediaType: "application/octet-stream"
            ),
            publishedAt: "2026-08-01T00:00:00Z"
        )
        let client = ZkCircuitClient(sources: ["https://primary.example.com"], httpGet: { _ in bytes })

        do {
            _ = try await client.downloadArtifact(descriptor)
            XCTFail("expected hashMismatch to be thrown")
        } catch ZkCircuitClientError.hashMismatch(let expected, let actual) {
            XCTAssertEqual(expected, "1276a67e4b3be8107acb7588aecdc33284ed6c5e663b13d13fe67f2cb91cf1e5")
            XCTAssertNotEqual(actual, expected, "actual hash of tampered bytes must differ from expected")
        } catch {
            XCTFail("expected ZkCircuitClientError.hashMismatch, got \(error)")
        }
    }

    func testDownloadArtifactThrowsNoArtifactWhenDescriptorHasNone() async {
        let descriptor = ZkCircuitDescriptor(
            id: "spec-only-circuit",
            system: "longfellow",
            systemVersion: "1.0.0",
            published: true,
            status: "active",
            publishedAt: "2026-08-01T00:00:00Z"
        )
        let client = ZkCircuitClient(sources: ["https://primary.example.com"], httpGet: { _ in
            XCTFail("must not attempt a network fetch when there is no artifact")
            return Data()
        })

        do {
            _ = try await client.downloadArtifact(descriptor)
            XCTFail("expected noArtifact to be thrown")
        } catch ZkCircuitClientError.noArtifact(let id) {
            XCTAssertEqual(id, "spec-only-circuit")
        } catch {
            XCTFail("expected ZkCircuitClientError.noArtifact, got \(error)")
        }
    }
}

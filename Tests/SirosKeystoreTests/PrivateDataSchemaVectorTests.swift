// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore

#if canImport(CryptoKit)
import CryptoKit

/// privatedata-spec 2.8 (`S.schemaVersion` 4) at the keystore: the spec's vendored
/// vectors, and the rules the vectors do not exercise (refusal, migration,
/// writer rules, preservation).
final class PrivateDataSchemaVectorTests: XCTestCase {

    /// SHA-256 of the vendored files. Re-vendoring changes them; see
    /// `Resources/privatedata-spec/vectors.PROVENANCE.txt`.
    private static let vectorsSha256 = "50e8f8bd53372ea3e6339a5a3c92609a71407c6e979c2392b5bed60641f73faf"
    private static let sumsSha256 = "1e17e9c92775bb713968248ac20486c1750294d54490d3fac6b4c5ffc4643b73"

    private let prf = Data(repeating: 0x42, count: 32)
    private let salt = Data(repeating: 0x07, count: 32)
    private let info = Data("eDiplomas PRF".utf8)

    // MARK: - Fixtures

    private func resourceDirectory() throws -> URL {
        let url = try XCTUnwrap(
            Bundle.module.url(forResource: "vectors", withExtension: "jsonl", subdirectory: "privatedata-spec")
        )
        return url.deletingLastPathComponent()
    }

    private func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func vectors() throws -> [[String: Any]] {
        let text = try String(contentsOf: resourceDirectory().appendingPathComponent("vectors.jsonl"), encoding: .utf8)
        return try text.split(separator: "\n").compactMap { line in
            try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any]
        }
    }

    private func vector(_ id: String) throws -> [String: Any] {
        try XCTUnwrap(vectors().first { ($0["id"] as? String) == id }, "vector \(id)")
    }

    private func plaintextState(of vector: [String: Any]) throws -> [String: Any]? {
        (vector["inputs"] as? [String: Any])?["plaintextState"] as? [String: Any]
    }

    private func open(_ state: [String: Any]) async throws -> (JweKeystore, Data) {
        let container = try ContainerTestSupport.buildContainer(
            prfOutput: prf, hkdfSalt: salt, hkdfInfo: info, plaintextState: state
        )
        let keystore = JweKeystore()
        try await keystore.unlock(prfOutput: prf, encryptedContainer: container, hkdfSalt: salt, hkdfInfo: info)
        return (keystore, container)
    }

    private func rewritten(_ keystore: JweKeystore) async throws -> [String: Any] {
        let bytes = try await keystore.exportEncryptedContainer()
        return try ContainerTestSupport.plaintext(of: bytes, prfOutput: prf, hkdfSalt: salt)
    }

    private func s(_ state: [String: Any]) -> [String: Any] { state["S"] as? [String: Any] ?? [:] }

    private func state(
        version: Any = 4,
        events: [[String: Any]] = [],
        credentials: [[String: Any]] = [],
        extra: [String: Any] = [:]
    ) -> [String: Any] {
        var sMember: [String: Any] = [
            "schemaVersion": version,
            "keypairs": [] as [Any],
            "credentials": credentials,
            "presentations": [] as [Any],
            "settings": ["openidRefreshTokenMaxAgeInSeconds": "0"],
            "credentialIssuanceSessions": [] as [Any],
        ]
        for (key, value) in extra { sMember[key] = value }
        return ["lastEventHash": "h-0", "events": events, "S": sMember]
    }

    private func credential(id: Int, extra: [String: Any] = [:]) -> [String: Any] {
        var entry: [String: Any] = [
            "credentialId": id, "format": "dc+sd-jwt", "data": "<credential \(id)>", "kid": "kid-1",
            "instanceId": 0, "batchId": 1, "credentialIssuerIdentifier": "https://issuer.example.com",
            "credentialConfigurationId": "org.siros.nym_auth",
        ]
        for (key, value) in extra { entry[key] = value }
        return entry
    }

    // MARK: - Vendored vectors

    func testTheVendoredVectorsAreTheSpecsByDigest() throws {
        let dir = try resourceDirectory()
        XCTAssertEqual(sha256Hex(try Data(contentsOf: dir.appendingPathComponent("vectors.jsonl"))), Self.vectorsSha256)
        let sums = try Data(contentsOf: dir.appendingPathComponent("vectors.SHA256SUMS"))
        XCTAssertEqual(sha256Hex(sums), Self.sumsSha256)
        var checked = 0
        for line in String(decoding: sums, as: UTF8.self).split(separator: "\n") {
            let parts = line.components(separatedBy: "  ")
            XCTAssertEqual(parts.count, 2, "malformed line \(line)")
            let file = try Data(contentsOf: dir.appendingPathComponent(parts[1]))
            XCTAssertEqual(sha256Hex(file), parts[0], parts[1])
            checked += 1
        }
        XCTAssertGreaterThanOrEqual(checked, 11)
    }

    /// Vectors that need nothing from the keystore container: the delivered-secret
    /// vectors are the receipt's (siros-sdk-swift DeliveredSecretReceipt), and the
    /// merge vectors need an event merger this SDK does not have (it never merges
    /// histories; see the PR description). Listed so a NEW vector id is a decision.
    private static let notContainerRoundTrips: Set<String> = [
        "multi-passkey-v3-001",
        "extensions-unknown-event-001", "extensions-concurrent-keys-001", "extensions-tombstone-001",
        "extensions-stale-peer-001", "extensions-size-accounting-001", "extensions-lww-fold-order-001",
        "extensions-lww-tiebreak-001", "extensions-unknown-namespace-retained-001",
        "extensions-version-coexistence-001",
        "delivered-secret-commitment-001", "delivered-secret-wire-001", "delivered-secret-malformed-001",
        "delivered-secret-refusal-001", "delivered-secret-strip-001", "delivered-secret-advertise-001",
    ]

    func testEveryVectorWithAStateRoundTripsThroughTheKeystoreAsTheSpecSays() async throws {
        var roundTripped: [String] = []
        for vector in try vectors() {
            let id = try XCTUnwrap(vector["id"] as? String)
            guard !Self.notContainerRoundTrips.contains(id) else { continue }
            let input = try XCTUnwrap(plaintextState(of: vector), "vector \(id) has no plaintextState; classify it")
            let (keystore, _) = try await open(input)
            XCTAssertNil(keystore.unsupportedSchemaVersion, id)
            let output = try await rewritten(keystore)

            var expected = ((vector["expected"] as? [String: Any])?["roundTripState"] as? [String: Any]) ?? input
            var expectedS = s(expected)
            expectedS["schemaVersion"] = 4   // a rewrite writes version 4; nothing else changes
            expected["S"] = expectedS

            XCTAssertEqual(output["lastEventHash"] as? String, expected["lastEventHash"] as? String, id)
            XCTAssertTrue(ContainerTestSupport.jsonEqual(output["events"], expected["events"]), "\(id): events")
            for member in Set(s(output).keys).union(expectedS.keys) {
                XCTAssertTrue(
                    ContainerTestSupport.jsonEqual(s(output)[member], expectedS[member]),
                    "\(id): S.\(member) differs\n got \(String(describing: s(output)[member]))\n want \(String(describing: expectedS[member]))"
                )
            }
            roundTripped.append(id)
        }
        XCTAssertTrue(roundTripped.contains("credential-metadata-001"))
        XCTAssertTrue(roundTripped.contains("credential-unknown-member-001"))
        XCTAssertTrue(roundTripped.contains("container-unknown-top-level-member-001"))
        XCTAssertTrue(roundTripped.contains("single-credential-v3-001"))
    }

    func testTheUnknownEventVectorIsRefusedAsUnsupportedAndNothingIsRewritten() async throws {
        let v = try vector("extensions-unknown-event-001")
        let history = try XCTUnwrap(((v["inputs"] as? [String: Any])?["historyA"]) as? [[String: Any]])
        let (keystore, container) = try await open(state(events: history))
        // Reading is unaffected; rewriting is refused, typed.
        XCTAssertNotNil(keystore.unsupportedSchemaVersion)
        await assertRefused(keystore, subject: .eventType(index: 0, type: "a_type_this_reader_does_not_know"))
        // The container the caller holds is untouched, so nothing was overwritten.
        let still = try ContainerTestSupport.plaintext(of: container, prfOutput: prf, hkdfSalt: salt)
        XCTAssertTrue(ContainerTestSupport.jsonEqual(still["events"], history))
    }

    // MARK: - Refusal

    private func assertRefused(
        _ keystore: JweKeystore, subject: UnsupportedSchemaVersion.Subject,
        file: StaticString = #filePath, line: UInt = #line
    ) async {
        do {
            _ = try await keystore.exportEncryptedContainer()
            XCTFail("export succeeded", file: file, line: line)
        } catch KeystoreError.unsupportedSchemaVersion(let unsupported) {
            XCTAssertEqual(unsupported.subject, subject, file: file, line: line)
        } catch {
            XCTFail("expected unsupportedSchemaVersion, got \(error)", file: file, line: line)
        }
        do {
            try await keystore.saveCredential(id: 9, json: "{\"id\":9}")
            XCTFail("saveCredential succeeded", file: file, line: line)
        } catch KeystoreError.unsupportedSchemaVersion {
            // expected
        } catch {
            XCTFail("expected unsupportedSchemaVersion, got \(error)", file: file, line: line)
        }
    }

    func testStateSchemaVersionFiveIsReadableButRefusedOnRewrite() async throws {
        let (keystore, _) = try await open(state(version: 5, credentials: [credential(id: 1)]))
        XCTAssertTrue(keystore.isUnlocked)
        let readable = try await keystore.getCredential(id: 1)
        XCTAssertNotNil(readable, "reading still works")
        await assertRefused(keystore, subject: .state)
        XCTAssertEqual(keystore.unsupportedSchemaVersion?.found, "5")
    }

    func testAnEventWithSchemaVersionFiveIsRefusedOnRewrite() async throws {
        let events: [[String: Any]] = [["type": "alter_settings", "schemaVersion": 5, "eventId": 1]]
        let (keystore, _) = try await open(state(version: 4, events: events))
        await assertRefused(keystore, subject: .event(index: 0))
    }

    func testAnUnknownEventTypeIsRefusedOnRewrite() async throws {
        let events: [[String: Any]] = [["type": "from_the_future", "schemaVersion": 4, "eventId": 1]]
        let (keystore, _) = try await open(state(version: 4, events: events))
        await assertRefused(keystore, subject: .eventType(index: 0, type: "from_the_future"))
    }

    func testVersionTwoIsReadableButNotRewritten() async throws {
        let (keystore, _) = try await open(state(version: 2, credentials: [credential(id: 1)]))
        let readable = try await keystore.getCredential(id: 1)
        XCTAssertNotNil(readable)
        await assertRefused(keystore, subject: .state)
    }

    func testTheRefusalClearsWhenTheStoreIsLockedAndReopenedOnASupportedContainer() async throws {
        let (keystore, _) = try await open(state(version: 5))
        XCTAssertNotNil(keystore.unsupportedSchemaVersion)
        keystore.lock()
        XCTAssertNil(keystore.unsupportedSchemaVersion)
        let ok = try ContainerTestSupport.buildContainer(
            prfOutput: prf, hkdfSalt: salt, hkdfInfo: info, plaintextState: state(version: 4)
        )
        try await keystore.unlock(prfOutput: prf, encryptedContainer: ok, hkdfSalt: salt, hkdfInfo: info)
        XCTAssertNil(keystore.unsupportedSchemaVersion)
        _ = try await keystore.exportEncryptedContainer()
    }

    // MARK: - Migration and writer rules

    func testMigratingVersionThreeToFourChangesOnlySchemaVersion() async throws {
        let input = try XCTUnwrap(plaintextState(of: try vector("single-credential-v3-001")))
        XCTAssertEqual(s(input)["schemaVersion"] as? Int, 3)
        let (keystore, _) = try await open(input)
        let output = try await rewritten(keystore)

        XCTAssertEqual(s(output)["schemaVersion"] as? Int, 4)
        var inputS = s(input)
        inputS["schemaVersion"] = 4
        for member in Set(inputS.keys).union(s(output).keys) {
            XCTAssertTrue(ContainerTestSupport.jsonEqual(inputS[member], s(output)[member]), "S.\(member) changed")
        }
        XCTAssertEqual(output["lastEventHash"] as? String, input["lastEventHash"] as? String)
        XCTAssertTrue(ContainerTestSupport.jsonEqual(output["events"], input["events"]))
        XCTAssertEqual(Set(output.keys), Set(input.keys))
    }

    func testNoVersionThreeContainerIsEverWrittenWithMetadataOrExtensions() async throws {
        // Pre-existing version 3 containers can carry both (spec section 6); they are read as 4
        // and written as 4, never as 3.
        let withBoth = state(
            version: 3,
            credentials: [credential(id: 1, extra: ["metadata": [["type": "org.siros.secret_seed", "value": ["ns": "00"]]]])],
            extra: ["extensions": ["org.siros.bbs": ["1": "opaque"]]]
        )
        let (keystore, _) = try await open(withBoth)
        // ... and a store that adds extensions to a plain version 3 container.
        try await keystore.setExtensionEntry(namespace: "org.siros.wscd", key: "kid-a", value: "v")
        let output = try await rewritten(keystore)
        XCTAssertEqual(s(output)["schemaVersion"] as? Int, 4)
        XCTAssertNotNil(s(output)["extensions"])
        XCTAssertTrue(WalletStateSchema.versionFourMembers(in: output).contains("S.extensions"))
        XCTAssertNoThrow(try WalletStateSchema.requireWriterRules(output))

        let (plain, _) = try await open(state(version: 3))
        try await plain.setExtensionEntry(namespace: "org.siros.wscd", key: "kid-a", value: "v")
        let plainOut = try await rewritten(plain)
        XCTAssertEqual(s(plainOut)["schemaVersion"] as? Int, 4)
    }

    func testAFreshContainerIsWrittenAtVersionFour() async throws {
        let keystore = JweKeystore()
        try await keystore.unlock(prfOutput: prf, encryptedContainer: Data(), hkdfSalt: salt, hkdfInfo: info)
        let output = try await rewritten(keystore)
        XCTAssertEqual(s(output)["schemaVersion"] as? Int, 4)
    }

    func testEmptyOrNullMetadataIsNotWrittenBack() async throws {
        let creds = [
            credential(id: 1, extra: ["metadata": [] as [Any]]),
            credential(id: 2, extra: ["metadata": NSNull()]),
        ]
        let (keystore, _) = try await open(state(credentials: creds))
        let output = try await rewritten(keystore)
        let out = (s(output)["credentials"] as? [[String: Any]]) ?? []
        XCTAssertEqual(out.count, 2)
        for entry in out { XCTAssertNil(entry["metadata"], "metadata must be absent, not [] or null") }
    }

    // MARK: - Preservation

    func testUnknownMembersAndMetadataAreWrittenBackWithIdenticalValuesInOrder() async throws {
        let meta: [[String: Any]] = [
            ["type": "org.siros.secret_seed", "value": ["org.siros.nym_auth": "00112233445566778899aabbccddeeff"], "x-entry-member": [1, [2, NSNull()]] as [Any]],
            ["type": "example.dup", "value": "first"],
            ["type": "example.dup", "value": "second"],
            ["type": "example.unicode", "value": "Körkort – Åland テスト 😀"],
        ]
        let creds = [
            credential(id: 30, extra: ["metadata": meta, "x-unknown": ["k": [1, 2, 3], "n": NSNull(), "b": false] as [String: Any]]),
            credential(id: 10, extra: ["x-other": "o"]),
            credential(id: 20),
        ]
        let input = state(credentials: creds, extra: [
            "futureMember": ["nested": ["a": true]],
            "extensions": ["com.example.unknown": ["entity": "opaque"]],
        ])
        let (keystore, _) = try await open(input)
        let output = try await rewritten(keystore)

        // Same array, same order (30, 10, 20 - not sorted, not hash order).
        XCTAssertTrue(ContainerTestSupport.jsonEqual(s(output)["credentials"], creds))
        XCTAssertTrue(ContainerTestSupport.jsonEqual(s(output)["futureMember"], s(input)["futureMember"]))
        XCTAssertTrue(ContainerTestSupport.jsonEqual(s(output)["extensions"], s(input)["extensions"]))
    }

    func testDeletingACredentialDeletesItsMetadataAndAddingOneAppendsIt() async throws {
        let creds = [
            credential(id: 1, extra: ["metadata": [["type": "t", "value": 1]], "x-unknown": 1]),
            credential(id: 2),
        ]
        let (keystore, _) = try await open(state(credentials: creds))
        try await keystore.deleteCredential(id: 1)
        try await keystore.saveCredential(id: 3, json: "{\"id\":3,\"format\":\"dc+sd-jwt\",\"raw\":\"r\"}")
        let output = try await rewritten(keystore)
        let out = (s(output)["credentials"] as? [[String: Any]]) ?? []
        XCTAssertEqual(out.compactMap { ($0["credentialId"] as? NSNumber)?.int64Value }, [2, 3])
        XCTAssertTrue(out.allSatisfy { $0["metadata"] == nil && $0["x-unknown"] == nil })
    }

    func testUnknownKeypairMembersAndAnUnloadableKeypairSurvive() async throws {
        let stub: [String: Any] = ["kid": "hw-1", "keypair": ["kid": "hw-1", "alg": "ES384", "x-future": ["a": 1]] as [String: Any], "x-entry": true]
        let (keystore, _) = try await open(state(extra: ["keypairs": [stub]]))
        let output = try await rewritten(keystore)
        XCTAssertTrue(ContainerTestSupport.jsonEqual(s(output)["keypairs"], [stub]))
    }
}

#else
final class PrivateDataSchemaVectorTests: XCTestCase {
    func testCryptoKitUnavailable() {
        // No-op placeholder: CryptoKit is unavailable on this platform.
    }
}
#endif

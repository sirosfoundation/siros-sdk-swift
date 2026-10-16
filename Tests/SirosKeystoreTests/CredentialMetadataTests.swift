// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosCredentials
@testable import SirosKeystore

#if canImport(CryptoKit)

/// `S.credentials[].metadata` (privatedata-spec, optional core member):
/// `[{"type": <non-empty string>, "value": <any JSON>}]`, kept exactly as
/// received, plus the rule that a rewriting client preserves per-credential
/// and top-level members it does not know.
///
/// privatedata-spec's vendored `vectors.jsonl` has no credential carrying
/// `metadata`, so these cases use local fixtures built here. An upstream
/// vector would need: a credential with a `metadata` array (one string value,
/// one object value), an unknown per-credential member, and an expected
/// byte-identical round trip.
final class CredentialMetadataTests: XCTestCase {

    private let prf = Data(0..<32)
    private let salt = Data((0..<32).map { UInt8($0 + 0x10) })
    private let info = Data("SIROS Wallet PRF".utf8)
    private let seedHex = "00112233445566778899aabbccddeeff"

    private func seedEntry() -> [String: Any] {
        ["type": "org.siros.NS.secret_seed", "value": seedHex]
    }

    private func credEntry(_ id: Int, extra: [String: Any] = [:]) -> [String: Any] {
        var e: [String: Any] = [
            "credentialId": id, "format": "dc+sd-jwt", "data": "raw-\(id)", "kid": "kid-\(id)",
            "instanceId": 0, "batchId": id, "credentialIssuerIdentifier": "https://iss.example",
            "credentialConfigurationId": "cfg",
        ]
        e.merge(extra) { _, new in new }
        return e
    }

    private func container(credentials: [[String: Any]], extraS: [String: Any] = [:]) throws -> Data {
        var s: [String: Any] = [
            "schemaVersion": 3, "keypairs": [] as [Any], "credentials": credentials,
            "presentations": [] as [Any], "settings": ["openidRefreshTokenMaxAgeInSeconds": "0"],
            "credentialIssuanceSessions": [] as [Any],
        ]
        s.merge(extraS) { _, new in new }
        return try ContainerTestSupport.buildContainer(
            prfOutput: prf, hkdfSalt: salt, hkdfInfo: info,
            plaintextState: ["lastEventHash": "", "events": [] as [Any], "S": s]
        )
    }

    private func reopen(_ c: Data) async throws -> JweKeystore {
        let k = JweKeystore()
        try await k.unlock(prfOutput: prf, encryptedContainer: c, hkdfSalt: salt, hkdfInfo: info)
        return k
    }

    private func creds(of k: JweKeystore) async throws -> [[String: Any]] {
        let state = try ContainerTestSupport.plaintext(
            of: try await k.exportEncryptedContainer(), prfOutput: prf, hkdfSalt: salt)
        return ((state["S"] as? [String: Any])?["credentials"] as? [[String: Any]]) ?? []
    }

    private func entry(_ id: Int, in list: [[String: Any]]) -> [String: Any]? {
        list.first { ($0["credentialId"] as? Int) == id }
    }

    private func fresh() async throws -> JweKeystore {
        let k = JweKeystore()
        try await k.unlock(prfOutput: prf, encryptedContainer: Data(), hkdfSalt: salt, hkdfInfo: info)
        return k
    }

    // MARK: -

    func testSetMetadataSurvivesExportAndReimport() async throws {
        let k = try await fresh()
        try await k.saveCredential(id: 1, json: "{\"id\":1,\"format\":\"dc+sd-jwt\",\"raw\":\"r\",\"batch_id\":1,\"instance_id\":0}")
        let entries: [[String: Any]] = [
            seedEntry(),
            ["type": "org.example.tok", "value": ["n": 9007199254740993, "f": 1.5, "b": true, "z": NSNull(), "l": [1, "x"]] as [String: Any]],
        ]
        try await k.setCredentialMetadata(id: 1, entries)

        let exported = try await creds(of: k)
        XCTAssertTrue(ContainerTestSupport.jsonEqual(entries, entry(1, in: exported)?["metadata"]))

        let reopened = try await reopen(try await k.exportEncryptedContainer())
        let back = await reopened.credentialMetadata(id: 1)
        XCTAssertTrue(ContainerTestSupport.jsonEqual(entries, back))
        XCTAssertEqual((back?[0]["value"] as? String), seedHex)
        let big = ((back?[1]["value"] as? [String: Any])?["n"] as? NSNumber)?.int64Value
        XCTAssertEqual(big, 9007199254740993, "integers beyond 2^53 must stay exact")
    }

    func testUnknownPerCredentialMemberSurvivesAndOwnedFieldsStillWin() async throws {
        let future: [String: Any] = ["a": [1, 2], "b": ["c": false]]
        let c = try container(credentials: [credEntry(1, extra: ["futureMember": future, "format": "dc+sd-jwt"])],
                              extraS: ["unknownTop": ["x": 1]])
        let k = try await reopen(c)
        let once = try await creds(of: k)
        XCTAssertTrue(ContainerTestSupport.jsonEqual(future, entry(1, in: once)?["futureMember"]))
        // Second hop through a fresh client.
        let twice = try await creds(of: try await reopen(try await k.exportEncryptedContainer()))
        XCTAssertTrue(ContainerTestSupport.jsonEqual(future, entry(1, in: twice)?["futureMember"]))
        XCTAssertNil(entry(1, in: twice)?["metadata"], "absent metadata must be omitted, not null or []")
    }

    func testMetadataSurvivesAddingDeletingAndPresentationRecord() async throws {
        let c = try container(credentials: [
            credEntry(1, extra: ["metadata": [seedEntry()]]),
            credEntry(2, extra: ["metadata": [["type": "t", "value": "other"]]]),
        ])
        let k = try await reopen(c)
        try await k.saveCredential(id: 3, json: "{\"id\":3,\"format\":\"dc+sd-jwt\",\"raw\":\"r3\",\"batch_id\":3,\"instance_id\":0}")
        try await k.deleteCredential(id: 2)
        try await k.savePresentationRecord(id: 5, json: "{\"credential_ids\":[1],\"timestamp\":1000,\"verifier_name\":\"v\"}")

        let out = try await creds(of: try await reopen(try await k.exportEncryptedContainer()))
        XCTAssertTrue(ContainerTestSupport.jsonEqual([seedEntry()], entry(1, in: out)?["metadata"]))
        XCTAssertNil(entry(2, in: out), "deleted credential must be gone")
        XCTAssertNil(entry(3, in: out)?["metadata"])
    }

    func testDeletedCredentialsMetadataIsGoneEvenWhenSameIdReturns() async throws {
        let k = try await reopen(try container(credentials: [credEntry(1, extra: ["metadata": [seedEntry()]])]))
        try await k.deleteCredential(id: 1)
        try await k.saveCredential(id: 1, json: "{\"id\":1,\"format\":\"dc+sd-jwt\",\"raw\":\"r\",\"batch_id\":1,\"instance_id\":0}")
        let out = try await creds(of: k)
        XCTAssertNil(entry(1, in: out)?["metadata"])
        let none = await k.credentialMetadata(id: 1)
        XCTAssertNil(none)
    }

    func testClearCredentialsDropsMetadata() async throws {
        let k = try await reopen(try container(credentials: [credEntry(1, extra: ["metadata": [seedEntry()]])]))
        try await k.clearCredentials()
        try await k.saveCredential(id: 1, json: "{\"id\":1,\"format\":\"dc+sd-jwt\",\"raw\":\"r\",\"batch_id\":1,\"instance_id\":0}")
        let none = await k.credentialMetadata(id: 1)
        XCTAssertNil(none)
        let after = try await creds(of: k)
        XCTAssertNil(entry(1, in: after)?["metadata"])
    }

    func testLockClearsMetadata() async throws {
        let k = try await reopen(try container(credentials: [credEntry(1, extra: ["metadata": [seedEntry()]])]))
        k.lock()
        let none = await k.credentialMetadata(id: 1)
        XCTAssertNil(none)
    }

    /// Regression: `StoredCredential.metadata` is DISPLAY metadata (an
    /// object). The container's `metadata` array must never reach the JSON
    /// the credential store decodes, or the credential silently vanishes.
    func testCredentialWithBothKindsOfMetadataStaysDecodable() async throws {
        let k = try await reopen(try container(credentials: [credEntry(1, extra: ["metadata": [seedEntry()]])]))
        let json = try await k.getCredential(id: 1)
        let stored = try JSONDecoder().decode(StoredCredential.self, from: Data(XCTUnwrap(json).utf8))
        XCTAssertEqual(stored.id, 1)
        XCTAssertNil(stored.metadata, "container metadata must not leak into display metadata")
        let meta = await k.credentialMetadata(id: 1)
        XCTAssertEqual(meta?.count, 1)
    }

    func testMalformedMetadataIsPreservedVerbatimAndNotInterpreted() async throws {
        for malformed in [["oops": 1] as [String: Any], "str", 7, NSNull()] as [Any] {
            let k = try await reopen(try container(credentials: [credEntry(1, extra: ["metadata": malformed])]))
            let json = try await k.getCredential(id: 1)
            XCTAssertNotNil(try? JSONDecoder().decode(StoredCredential.self, from: Data(XCTUnwrap(json).utf8)))
            let none = await k.credentialMetadata(id: 1)
            XCTAssertNil(none)
            let written = try await creds(of: k)
            XCTAssertTrue(ContainerTestSupport.jsonEqual(malformed, entry(1, in: written)?["metadata"]),
                          "malformed \(malformed) must be written back verbatim")
        }
    }

    func testSettingNilOrEmptyOmitsMemberAndInvalidEntriesAreRejected() async throws {
        let k = try await reopen(try container(credentials: [credEntry(1, extra: ["metadata": [seedEntry()]])]))
        try await k.setCredentialMetadata(id: 1, [])
        let afterEmpty = try await creds(of: k)
        XCTAssertNil(entry(1, in: afterEmpty)?["metadata"])
        try await k.setCredentialMetadata(id: 1, [seedEntry()])
        try await k.setCredentialMetadata(id: 1, nil)
        let afterNil = try await creds(of: k)
        XCTAssertNil(entry(1, in: afterNil)?["metadata"])

        do { try await k.setCredentialMetadata(id: 1, [["type": "", "value": "v"]]); XCTFail("empty type") } catch {}
        do { try await k.setCredentialMetadata(id: 1, [["type": "t"]]); XCTFail("missing value") } catch {}
        do { try await k.setCredentialMetadata(id: 99, [seedEntry()]); XCTFail("no such credential") } catch {}
    }

    func testAdapterForwardsMetadataAccessors() async throws {
        let adapter = WscdKeystoreAdapter(signer: NoopSigner())
        try await adapter.unlock(prfOutput: prf, encryptedContainer: Data(), hkdfSalt: salt, hkdfInfo: info)
        try await adapter.saveCredential(id: 1, json: "{\"id\":1,\"format\":\"dc+sd-jwt\",\"raw\":\"r\",\"batch_id\":1,\"instance_id\":0}")
        try await adapter.setCredentialMetadata(id: 1, [seedEntry()])
        let got = await adapter.credentialMetadata(id: 1)
        XCTAssertTrue(ContainerTestSupport.jsonEqual([seedEntry()], got))
    }
}

private final class NoopSigner: Signer, @unchecked Sendable {
    func generateKey(algorithm: String) async throws -> String { "k" }
    func sign(keyId: String, data: Data) async throws -> Data { Data(count: 64) }
    func listKeys() async throws -> [SignerKeyInfo] { [] }
    func deleteKey(keyId: String) async throws {}
    func attestationChain(keyId: String) async throws -> AttestationChain? { nil }
    func exportPublicKey(keyId: String) async throws -> Data { Data() }
    func migrateKey(keyId: String, targetPlugin: String) async throws -> MigrationResult { .migrated(newKeyId: keyId) }
    func securityProperties(keyId: String) async throws -> SignerSecurityProperties {
        SignerSecurityProperties(keyStorage: ["software"], userAuthentication: [])
    }
}

#else
final class CredentialMetadataTests: XCTestCase {
    func testCryptoKitUnavailable() { XCTAssertTrue(true) }
}
#endif

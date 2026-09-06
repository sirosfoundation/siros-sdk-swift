// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosCredentials
@testable import SirosKeystore

#if canImport(CryptoKit)

/// A `Signer` that answers every call with something harmless - the
/// counterpart of the Kotlin suite's `mockk<Signer>(relaxed = true)`. These
/// tests never sign; they only need a `WscdKeystoreAdapter` to exist.
private final class RelaxedSigner: Signer, @unchecked Sendable {
    func generateKey(algorithm: String) async throws -> String { "relaxed-key" }
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

/// `S.extensions` in the container - privatedata-spec §6.1.
///
/// The property under test throughout is the one the whole extension design
/// rests on: a client must be able to carry a namespace it does not
/// implement. Everything else here is bookkeeping; that one is the reason
/// the mechanism exists.
final class ExtensionStoreTests: XCTestCase {

    private let fakePrfOutput = Data(0..<32)
    private let hkdfSalt = Data((0..<32).map { UInt8($0 + 0x10) })
    private let hkdfInfo = Data("SIROS Wallet PRF".utf8)

    private func freshKeystore() async throws -> JweKeystore {
        let keystore = JweKeystore()
        try await keystore.unlock(prfOutput: fakePrfOutput, encryptedContainer: Data(), hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)
        return keystore
    }

    private func reopen(_ container: Data) async throws -> JweKeystore {
        let keystore = JweKeystore()
        try await keystore.unlock(prfOutput: fakePrfOutput, encryptedContainer: container, hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)
        return keystore
    }

    private func freshAdapter() async throws -> WscdKeystoreAdapter {
        let adapter = WscdKeystoreAdapter(signer: RelaxedSigner())
        try await adapter.unlock(prfOutput: fakePrfOutput, encryptedContainer: Data(), hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)
        return adapter
    }

    private func extensionsOf(_ container: Data) throws -> [String: Any]? {
        try ContainerTestSupport.extensions(of: container, prfOutput: fakePrfOutput, hkdfSalt: hkdfSalt)
    }

    // -----------------------------------------------------------------------

    func testEntriesSurviveExportAndReopen() async throws {
        let keystore = try await freshKeystore()
        try await keystore.setExtensionEntry(namespace: "org.siros.bbs", key: "cred-1", value: "state-one")
        try await keystore.setExtensionEntry(namespace: "org.siros.bbs", key: "cred-2", value: "state-two")
        try await keystore.setExtensionEntry(namespace: "org.siros.wscd", key: "kid-a1b2", value: "key-metadata")

        let reopened = try await reopen(try await keystore.exportEncryptedContainer())

        let bbs = await reopened.extensionEntries(namespace: "org.siros.bbs")
        XCTAssertEqual(["cred-1": "state-one", "cred-2": "state-two"], bbs)
        let wscd = await reopened.extensionEntries(namespace: "org.siros.wscd")
        XCTAssertEqual(["kid-a1b2": "key-metadata"], wscd)
    }

    /// A namespace this build has never heard of must round-trip untouched.
    ///
    /// This is the invariant. A client that drops what it does not recognise
    /// does not degrade a credential, it destroys one - the state a blind BBS
    /// credential needs cannot be reconstructed after the fact. And the
    /// failure lands on whichever client is *last*, not the one that caused
    /// it.
    func testAnUnknownNamespaceIsCarriedVerbatim() async throws {
        let keystore = try await freshKeystore()
        try await keystore.setExtensionEntry(namespace: "com.example.not.implemented.here", key: "entity-7", value: "opaque-payload")
        try await keystore.setExtensionEntry(namespace: "org.siros.bbs", key: "cred-1", value: "state-one")

        // Two round trips, so a client that reads and rewrites twice is
        // covered rather than only the first hop.
        let once = try await reopen(try await keystore.exportEncryptedContainer())
        let twice = try await reopen(try await once.exportEncryptedContainer())

        let unknown = await twice.extensionEntries(namespace: "com.example.not.implemented.here")
        XCTAssertEqual(["entity-7": "opaque-payload"], unknown)
        let bbs = await twice.extensionEntries(namespace: "org.siros.bbs")
        XCTAssertEqual(["cred-1": "state-one"], bbs)
    }

    func testAnAbsentNamespaceIsEmptyRatherThanAnError() async throws {
        let keystore = try await freshKeystore()
        let entries = await keystore.extensionEntries(namespace: "org.siros.bbs")
        XCTAssertEqual([:], entries)
    }

    /// Deleting the entity an entry names must delete the entry
    /// (privatedata-spec §6.1.2). An entry left behind is a long-lived secret
    /// belonging to a credential that no longer exists.
    func testRemovingAnEntryDropsItAndEmptiesTheNamespace() async throws {
        let keystore = try await freshKeystore()
        try await keystore.setExtensionEntry(namespace: "org.siros.bbs", key: "cred-1", value: "state-one")
        try await keystore.setExtensionEntry(namespace: "org.siros.bbs", key: "cred-2", value: "state-two")

        try await keystore.removeExtensionEntry(namespace: "org.siros.bbs", key: "cred-1")
        let afterFirst = await keystore.extensionEntries(namespace: "org.siros.bbs")
        XCTAssertEqual(["cred-2": "state-two"], afterFirst)

        try await keystore.removeExtensionEntry(namespace: "org.siros.bbs", key: "cred-2")
        let reopened = try await reopen(try await keystore.exportEncryptedContainer())
        let afterSecond = await reopened.extensionEntries(namespace: "org.siros.bbs")
        XCTAssertEqual([:], afterSecond)

        // And the namespace leaves no empty object behind in the container.
        let written = try extensionsOf(try await reopened.exportEncryptedContainer())
        XCTAssertNil(written?["org.siros.bbs"])
    }

    /// The wire shape is what privatedata-spec §6.1 specifies: namespace ->
    /// entry key -> opaque string. Checked against the container rather than
    /// the accessors, since another client reads the container.
    func testTheWireShapeMatchesTheSpecification() async throws {
        let keystore = try await freshKeystore()
        try await keystore.setExtensionEntry(namespace: "org.siros.bbs", key: "cred-1", value: "state-one")

        let extensions = try extensionsOf(try await keystore.exportEncryptedContainer())
        XCTAssertNotNil(extensions, "S.extensions must be present")
        let ns = extensions?["org.siros.bbs"] as? [String: Any]
        XCTAssertEqual("state-one", ns?["cred-1"] as? String)
    }

    /// Later writes to one key replace earlier ones - last-write-wins.
    func testWritingTheSameKeyTwiceKeepsTheLaterValue() async throws {
        let keystore = try await freshKeystore()
        try await keystore.setExtensionEntry(namespace: "org.siros.bbs", key: "cred-1", value: "first")
        try await keystore.setExtensionEntry(namespace: "org.siros.bbs", key: "cred-1", value: "second")
        let entries = await keystore.extensionEntries(namespace: "org.siros.bbs")
        XCTAssertEqual(["cred-1": "second"], entries)
    }

    // MARK: - BbsHolderStateVault through a real container

    func testHolderStateRoundTripsThroughTheContainer() async throws {
        let keystore = try await freshKeystore()
        let vault = BbsHolderStateVault(keystore: keystore)
        let state = BbsHolderState(
            issuerPublicKey: [1, 2, 3],
            secretProverBlind: (0..<32).map { UInt8($0) },
            committedMessages: [[9], [8, 7]],
            keybindPublicKeys: [[4, 5]]
        )

        try await vault.put(credentialId: "cred-1", state: state)
        let reopened = try await reopen(try await keystore.exportEncryptedContainer())
        let restored = await BbsHolderStateVault(keystore: reopened).get(credentialId: "cred-1")

        XCTAssertEqual(state, restored)
    }

    /// A corrupt entry reads as absent rather than throwing.
    ///
    /// The caller's contract is already "nil means this cannot be
    /// presented"; surfacing a decode failure as an error from a lookup
    /// would give it a second way to fail with the same meaning.
    func testAnUndecodableEntryReadsAsAbsent() async throws {
        let keystore = try await freshKeystore()
        try await keystore.setExtensionEntry(namespace: BbsHolderStateVault.namespace, key: "cred-1", value: "not json at all")
        let restored = await BbsHolderStateVault(keystore: keystore).get(credentialId: "cred-1")
        XCTAssertNil(restored)
    }

    // MARK: - what a non-conforming or second container does

    /// §6.1 makes an entry value a string, and this keystore writes every
    /// entry back as one. A peer that stored a number or a boolean must
    /// therefore not have it read in and handed back re-typed on the next
    /// round trip - quietly changing another client's data is worse than
    /// declining to carry a value the spec does not allow, and it is what
    /// objects and arrays in that position already get.
    func testANonStringEntryValueIsSkippedRatherThanRetyped() async throws {
        let keystore = try await freshKeystore()
        try await keystore.setExtensionEntry(namespace: "org.siros.bbs", key: "cred-1", value: "state-one")

        let tampered = try ContainerTestSupport.rewriteExtensions(
            try await keystore.exportEncryptedContainer(), prfOutput: fakePrfOutput, hkdfSalt: hkdfSalt
        ) { extensions in
            extensions["com.example.peer"] = [
                "number": 42,
                "boolean": true,
                "null": NSNull(),
                "object": ["nested": "x"],
                "array": ["y"],
                "text": "carried",
            ] as [String: Any]
        }

        let reopened = try await reopen(tampered)
        let peer = await reopened.extensionEntries(namespace: "com.example.peer")
        XCTAssertEqual(["text": "carried"], peer)
        // And nothing re-typed reaches the container on the way back out.
        let written = try extensionsOf(try await reopened.exportEncryptedContainer())?["com.example.peer"] as? [String: Any]
        XCTAssertEqual(["text"], Set((written ?? [:]).keys))
        let bbs = await reopened.extensionEntries(namespace: "org.siros.bbs")
        XCTAssertEqual(["cred-1": "state-one"], bbs)
    }

    /// A namespace whose every entry is non-string (or which is not an
    /// object at all) is dropped rather than kept as an empty object.
    func testANamespaceWithNoStringEntriesIsDropped() async throws {
        let keystore = try await freshKeystore()
        try await keystore.setExtensionEntry(namespace: "org.siros.bbs", key: "cred-1", value: "state-one")

        let tampered = try ContainerTestSupport.rewriteExtensions(
            try await keystore.exportEncryptedContainer(), prfOutput: fakePrfOutput, hkdfSalt: hkdfSalt
        ) { extensions in
            extensions["com.example.numbers"] = ["n": 1]
            extensions["com.example.notanobject"] = "just a string"
        }

        let reopened = try await reopen(tampered)
        let written = try extensionsOf(try await reopened.exportEncryptedContainer())
        XCTAssertEqual(["org.siros.bbs"], Set((written ?? [:]).keys))
    }

    /// Unlocking is a load, not a merge.
    ///
    /// The same instance can be unlocked against a second container - another
    /// account on a shared device, or a re-unlock after entries were dropped
    /// elsewhere. Carrying the first container's entries into the second and
    /// writing them back on export would put one account's state, including
    /// long-lived BBS secrets, into another's container.
    func testUnlockingASecondContainerReplacesRatherThanMergesEntries() async throws {
        let first = try await freshKeystore()
        try await first.setExtensionEntry(namespace: "org.siros.bbs", key: "cred-1", value: "state-one")

        let second = try await freshKeystore()
        try await second.setExtensionEntry(namespace: "org.siros.bbs", key: "cred-2", value: "state-two")

        let keystore = try await reopen(try await first.exportEncryptedContainer())
        let fromFirst = await keystore.extensionEntries(namespace: "org.siros.bbs")
        XCTAssertEqual(["cred-1": "state-one"], fromFirst)

        try await keystore.unlock(
            prfOutput: fakePrfOutput, encryptedContainer: try await second.exportEncryptedContainer(),
            hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo
        )

        let fromSecond = await keystore.extensionEntries(namespace: "org.siros.bbs")
        XCTAssertEqual(["cred-2": "state-two"], fromSecond)
        let written = try await reopen(try await keystore.exportEncryptedContainer()).extensionEntries(namespace: "org.siros.bbs")
        XCTAssertEqual(
            ["cred-2": "state-two"], written,
            "the first container's entry must not be written back into the second"
        )
    }

    /// A write to a locked keystore has nowhere to go: `JweKeystore.lock` has
    /// already dropped the in-memory map and the next unlock loads rather
    /// than merges. Silently accepting it would tell a caller its state was
    /// stored when it was not - and for BBS that state cannot be recomputed.
    func testMutatingWhileLockedFailsRatherThanBeingDiscarded() async throws {
        let keystore = try await freshKeystore()
        try await keystore.setExtensionEntry(namespace: "org.siros.bbs", key: "cred-1", value: "state-one")
        keystore.lock()

        do {
            try await keystore.setExtensionEntry(namespace: "org.siros.bbs", key: "cred-1", value: "state-one")
            XCTFail("setExtensionEntry on a locked keystore must throw")
        } catch KeystoreError.locked {
            // expected
        }
        do {
            try await keystore.removeExtensionEntry(namespace: "org.siros.bbs", key: "cred-1")
            XCTFail("removeExtensionEntry on a locked keystore must throw")
        } catch KeystoreError.locked {
            // expected
        }

        // Reading, though, stays a plain "nothing available" - the answer a
        // presentation-time lookup already has to handle.
        let entries = await keystore.extensionEntries(namespace: "org.siros.bbs")
        XCTAssertEqual([:], entries)
    }

    // MARK: - the other container owner

    /// `WscdKeystoreAdapter` must write extension state into the same
    /// container its credentials live in.
    ///
    /// Two classes own a container, and which one a wallet has depends on
    /// whether its signing keys are WSCD-backed - a deployment detail that
    /// has nothing to do with extension state. If this adapter kept its own
    /// copy, or dropped writes, a WSCD-backed wallet would issue BBS
    /// credentials whose holder state never reached the account's other
    /// devices. Same failure as not storing it at all, only harder to see.
    func testTheWscdAdapterWritesIntoTheContainerItExports() async throws {
        let adapter = try await freshAdapter()

        try await BbsHolderStateVault(keystore: adapter).put(
            credentialId: "cred-1",
            state: BbsHolderState(issuerPublicKey: [1], secretProverBlind: [UInt8](repeating: 2, count: 32), committedMessages: [[3]], keybindPublicKeys: [])
        )

        let extensions = try extensionsOf(try await adapter.exportEncryptedContainer())
        XCTAssertEqual(
            1, (extensions?[BbsHolderStateVault.namespace] as? [String: Any])?.count,
            "the entry must be in the exported container, not only in the adapter"
        )
    }

    /// And a container written by one owner must be readable by the other -
    /// they are the same format by design, so a user moving between a
    /// WSCD-backed build and a software one keeps their credentials usable.
    func testEitherOwnerCanReadWhatTheOtherWrote() async throws {
        let state = BbsHolderState(issuerPublicKey: [9], secretProverBlind: [UInt8](repeating: 4, count: 32), committedMessages: [[5]], keybindPublicKeys: [])

        let adapter = try await freshAdapter()
        try await BbsHolderStateVault(keystore: adapter).put(credentialId: "cred-1", state: state)

        let plain = try await reopen(try await adapter.exportEncryptedContainer())
        let viaPlain = await BbsHolderStateVault(keystore: plain).get(credentialId: "cred-1")
        XCTAssertEqual(state, viaPlain)

        // ...and back the other way.
        try await BbsHolderStateVault(keystore: plain).put(credentialId: "cred-2", state: state)
        let adapter2 = WscdKeystoreAdapter(signer: RelaxedSigner())
        try await adapter2.unlock(
            prfOutput: fakePrfOutput, encryptedContainer: try await plain.exportEncryptedContainer(),
            hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo
        )
        let viaAdapter = await BbsHolderStateVault(keystore: adapter2).get(credentialId: "cred-2")
        XCTAssertEqual(state, viaAdapter)
    }

    /// The adapter's locked-store behaviour is `JweKeystore`'s, not a
    /// silently-swallowing wrapper around it.
    func testTheWscdAdapterThrowsWhileLockedToo() async throws {
        let adapter = WscdKeystoreAdapter(signer: RelaxedSigner())
        do {
            try await adapter.setExtensionEntry(namespace: "org.siros.bbs", key: "cred-1", value: "state-one")
            XCTFail("setExtensionEntry on a locked adapter must throw")
        } catch KeystoreError.locked {
            // expected
        }
        let entries = await adapter.extensionEntries(namespace: "org.siros.bbs")
        XCTAssertEqual([:], entries)
    }
}

#else
final class ExtensionStoreTests: XCTestCase {
    func testCryptoKitUnavailable() {
        // No-op placeholder: CryptoKit is unavailable on this platform. The
        // vault's own encoding is covered on every platform by
        // BbsHolderStateVaultTests.
    }
}
#endif

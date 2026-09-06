// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosCredentials
@testable import SirosKeystore

/// An in-memory `ExtensionStore` with `JweKeystore`'s observable semantics
/// (empty namespaces dropped, mutation throws while locked, reads do not),
/// so the vault's own behaviour - above all the bytes it writes - can be
/// checked on every platform, including the Linux CI where `JweKeystore`
/// itself does not compile.
private final class InMemoryExtensionStore: ExtensionStore, @unchecked Sendable {
    var entries: [String: [String: String]] = [:]
    var locked = false

    func extensionEntries(namespace: String) async -> [String: String] {
        entries[namespace] ?? [:]
    }

    func setExtensionEntry(namespace: String, key: String, value: String) async throws {
        if locked { throw KeystoreError.locked }
        entries[namespace, default: [:]][key] = value
    }

    func removeExtensionEntry(namespace: String, key: String) async throws {
        if locked { throw KeystoreError.locked }
        guard var ns = entries[namespace] else { return }
        ns.removeValue(forKey: key)
        entries[namespace] = ns.isEmpty ? nil : ns
    }
}

/// `BbsHolderStateVault` - the `org.siros.bbs` namespace of privatedata-spec
/// §6.1 `S.extensions`, and the byte-for-byte contract with siros-sdk-kotlin's
/// vault that lets a credential issued by either SDK be presented by the other.
final class BbsHolderStateVaultTests: XCTestCase {

    private let sampleState = BbsHolderState(
        issuerPublicKey: [1, 2, 3],
        secretProverBlind: (0..<32).map { UInt8($0) },
        committedMessages: [[9], [8, 7]],
        keybindPublicKeys: [[4, 5]]
    )

    // MARK: - The wire format

    /// The entry value is what Kotlin's `BbsHolderStateVault.Stored` serialises
    /// to: those four field names, in that order, every byte field base64url
    /// without padding, no whitespace. Pinned as a literal because another
    /// SDK reads it - a change here that still round-trips through this
    /// class is exactly the kind that would break the other one.
    func testTheStoredEntryIsByteIdenticalToKotlins() async throws {
        let store = InMemoryExtensionStore()
        try await BbsHolderStateVault(keystore: store).put(credentialId: "cred-1", state: sampleState)

        let expected = "{\"issuerPublicKey\":\"AQID\""
            + ",\"secretProverBlind\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\""
            + ",\"committedMessages\":[\"CQ\",\"CAc\"]"
            + ",\"keybindPublicKeys\":[\"BAU\"]}"
        XCTAssertEqual(expected, store.entries["org.siros.bbs"]?["cred-1"])
    }

    func testTheNamespaceIsTheRegisteredOne() {
        XCTAssertEqual("org.siros.bbs", BbsHolderStateVault.namespace)
    }

    /// base64url, not base64: the two alphabets differ exactly on bytes that
    /// produce `+`/`/`, and padding must be absent.
    func testBytesThatDifferBetweenBase64AlphabetsUseTheUrlSafeOne() async throws {
        let store = InMemoryExtensionStore()
        // 0xFB 0xFF -> "+/8=" in plain base64; "-_8" in unpadded base64url.
        let state = BbsHolderState(issuerPublicKey: [0xFB, 0xFF], secretProverBlind: [], committedMessages: [], keybindPublicKeys: [])
        try await BbsHolderStateVault(keystore: store).put(credentialId: "cred-1", state: state)

        let raw = store.entries["org.siros.bbs"]?["cred-1"] ?? ""
        XCTAssertTrue(raw.contains("\"issuerPublicKey\":\"-_8\""), raw)
        XCTAssertFalse(raw.contains("="), raw)
        XCTAssertFalse(raw.contains("+"), raw)
        XCTAssertFalse(raw.contains("/"), raw)
    }

    /// What Kotlin writes must read back here - including padded input
    /// (Java's URL decoder accepts either) and keys this build does not know
    /// (Kotlin decodes with `ignoreUnknownKeys`, and a future field must not
    /// make today's builds drop the credential).
    func testAnEntryWrittenByKotlinDecodes() async throws {
        let store = InMemoryExtensionStore()
        store.entries["org.siros.bbs"] = [
            "cred-1": "{\"issuerPublicKey\":\"AQID\",\"secretProverBlind\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\","
                + "\"committedMessages\":[\"CQ==\",\"CAc\"],\"keybindPublicKeys\":[\"BAU\"],\"futureField\":{\"x\":1}}",
        ]
        let restored = await BbsHolderStateVault(keystore: store).get(credentialId: "cred-1")
        XCTAssertEqual(sampleState, restored)
    }

    // MARK: - Behaviour

    func testHolderStateRoundTrips() async throws {
        let store = InMemoryExtensionStore()
        let vault = BbsHolderStateVault(keystore: store)
        try await vault.put(credentialId: "cred-1", state: sampleState)
        let restored = await vault.get(credentialId: "cred-1")
        XCTAssertEqual(sampleState, restored)
    }

    /// Two credentials' state must not overwrite each other.
    ///
    /// This is why the entry key names a credential rather than the
    /// subsystem: an aggregate `"bbs"` entry would make the second write
    /// discard the first, and resolution is last-write-wins per entry.
    func testEachCredentialGetsItsOwnEntry() async throws {
        let store = InMemoryExtensionStore()
        let vault = BbsHolderStateVault(keystore: store)
        let a = BbsHolderState(issuerPublicKey: [1], secretProverBlind: [UInt8](repeating: 0, count: 32), committedMessages: [[0xA]], keybindPublicKeys: [])
        let b = BbsHolderState(issuerPublicKey: [2], secretProverBlind: [UInt8](repeating: 1, count: 32), committedMessages: [[0xB]], keybindPublicKeys: [])

        try await vault.put(credentialId: "cred-a", state: a)
        try await vault.put(credentialId: "cred-b", state: b)

        let restoredA = await vault.get(credentialId: "cred-a")
        let restoredB = await vault.get(credentialId: "cred-b")
        let ids = await vault.credentialIds()
        XCTAssertEqual(a, restoredA)
        XCTAssertEqual(b, restoredB)
        XCTAssertEqual(["cred-a", "cred-b"], ids)
        XCTAssertEqual(2, store.entries["org.siros.bbs"]?.count)
    }

    /// Missing state means "cannot present", and the caller must be able to
    /// tell that apart from a successful lookup - never presented unbound.
    func testAbsentHolderStateIsNil() async {
        let restored = await BbsHolderStateVault(keystore: InMemoryExtensionStore()).get(credentialId: "never-stored")
        XCTAssertNil(restored)
    }

    func testRemovingHolderStateDeletesTheEntry() async throws {
        let store = InMemoryExtensionStore()
        let vault = BbsHolderStateVault(keystore: store)
        try await vault.put(credentialId: "cred-1", state: sampleState)
        try await vault.remove(credentialId: "cred-1")
        let restored = await vault.get(credentialId: "cred-1")
        let ids = await vault.credentialIds()
        XCTAssertNil(restored)
        XCTAssertEqual([], ids)
        XCTAssertNil(store.entries["org.siros.bbs"], "an emptied namespace leaves nothing behind")
    }

    /// A corrupt entry reads as absent rather than throwing.
    ///
    /// The caller's contract is already "nil means this cannot be
    /// presented"; surfacing a decode failure as an error from a lookup
    /// would give it a second way to fail with the same meaning.
    func testAnUndecodableEntryReadsAsAbsent() async {
        let store = InMemoryExtensionStore()
        store.entries["org.siros.bbs"] = [
            "not-json": "not json at all",
            "not-an-object": "[1,2,3]",
            "missing-field": "{\"issuerPublicKey\":\"AQID\",\"secretProverBlind\":\"AA\",\"committedMessages\":[]}",
            "wrong-type": "{\"issuerPublicKey\":\"AQID\",\"secretProverBlind\":7,\"committedMessages\":[],\"keybindPublicKeys\":[]}",
            "bad-base64": "{\"issuerPublicKey\":\"@@@\",\"secretProverBlind\":\"AA\",\"committedMessages\":[],\"keybindPublicKeys\":[]}",
            "non-string-list-item": "{\"issuerPublicKey\":\"AQID\",\"secretProverBlind\":\"AA\",\"committedMessages\":[1],\"keybindPublicKeys\":[]}",
        ]
        let vault = BbsHolderStateVault(keystore: store)
        for key in store.entries["org.siros.bbs"]!.keys {
            let restored = await vault.get(credentialId: key)
            XCTAssertNil(restored, "entry \(key) must read as absent")
        }
    }

    /// The vault does not soften the store's locked-state contract: a write
    /// that cannot land fails, and the BBS secret is not silently lost.
    func testPutOnALockedStoreThrows() async throws {
        let store = InMemoryExtensionStore()
        store.locked = true
        do {
            try await BbsHolderStateVault(keystore: store).put(credentialId: "cred-1", state: sampleState)
            XCTFail("put on a locked store must throw")
        } catch KeystoreError.locked {
            // expected
        }
    }
}

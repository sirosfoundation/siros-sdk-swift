// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosAuth
import SirosCredentials
import SirosKeystore
@testable import SirosWallet
@preconcurrency import SwiftCBOR

/// `credentialStatus(of:)` writes to `credentialStatusCache` only after
/// `await`ing the (potentially slow, real-network) evaluator - a session
/// boundary or this credential's own deletion can complete WHILE that
/// `await` is still suspended. Uses a stub `KeystoreManager` (like
/// `SirosWalletLifecycleTests`) so it runs identically on Linux and Apple
/// platforms, without CryptoKit.
private final class StubAuthProvider: AuthProvider, @unchecked Sendable {
    struct NotImplemented: Error {}
    func register(options: RegisterOptions) async throws -> RegisterResult { throw NotImplemented() }
    func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw NotImplemented() }
    func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw NotImplemented() }
}

private final class StubKeystoreManager: KeystoreManager, @unchecked Sendable {
    var isUnlocked: Bool { true }
    func unlock(prfOutput: Data, encryptedContainer: Data, hkdfSalt: Data, hkdfInfo: Data) async throws {}
    func lock() {}
    func generateKey(algorithm: String) async throws -> String { "key-1" }
    func sign(keyId: String, payload: Data, algorithm: String) async throws -> Data { Data() }
    func generateProof(audience: String, nonce: String, freshKey: Bool) async throws -> String { "" }
    func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String { "" }
    func signVpToken(credential: String, disclosedClaims: [String]?, nonce: String, audience: String, kid: String?) async throws -> String { "" }
    func exportEncryptedContainer() async throws -> Data { Data() }
    func listKeys() -> [KeyInfo] { [] }
    func exportWscdCredentials() async -> [String: String] { [:] }
    func setWscdCredentials(pluginId: String, state: String) async {}
    func extensionEntries(namespace: String) async -> [String: String] { [:] }
    func setExtensionEntry(namespace: String, key: String, value: String) async throws {}
    func removeExtensionEntry(namespace: String, key: String) async throws {}
    func exportCredentialRefreshTokens() async -> [Int64: CredentialRefreshTokenEntry] { [:] }
    func setCredentialRefreshToken(batchId: Int64, entry: CredentialRefreshTokenEntry) async {}
    func removeCredentialRefreshToken(batchId: Int64) async {}
    func saveCredential(id: Int64, json: String) async throws {}
    func getCredential(id: Int64) async throws -> String? { nil }
    func getAllCredentials() async throws -> [Int64: String] { [:] }
    func deleteCredential(id: Int64) async throws {}
    func clearCredentials() async throws {}
    func savePresentationRecord(id: Int64, json: String) async throws {}
    func getAllPresentationRecords() async throws -> [Int64: String] { [:] }
    func clearPresentationRecords() async throws {}
    func generateKeypairs(count: Int) async throws -> [KeypairInfo] { [] }
    func generateKeyAttestation(nonce: String, count: Int) async throws -> String { "" }
}

final class SirosWalletCredentialStatusRaceTests: XCTestCase {

    private func makeWallet(credentialStore: CredentialStore) -> SirosWallet {
        var config = WalletConfig(backendUrl: "https://wallet.example.invalid")
        config.credentialStore = credentialStore
        let wallet = SirosWallet(
            config: config,
            authProvider: StubAuthProvider(),
            keystore: StubKeystoreManager()
        )
        XCTAssertNotNil(wallet)
        return wallet!
    }

    /// A credential whose `validUntil` is long past - `evaluate()` short-
    /// circuits on the validity window before ever consulting the network
    /// (see `CredentialStatusTests.testTheValidityWindowShortCircuitsTheStatusList`),
    /// so this resolves to `.expired` (never `.valid`) quickly and
    /// deterministically - exactly what makes the cache-write assertion
    /// below meaningful: `.valid` is `cachedCredentialStatus`'s own default
    /// for an id with NO entry, so only a status that is provably NOT
    /// `.valid` can distinguish "no entry was written" from "one was".
    private func expiredCredential(id: Int64) -> StoredCredential {
        func b64(_ object: [String: Any]) -> String {
            Data(try! JSONSerialization.data(withJSONObject: object)).base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        let payload: [String: Any] = ["iss": "https://issuer.example", "validUntil": "2020-01-01T00:00:00Z"]
        let raw = "\(b64(["alg": "ES256", "typ": "dc+sd-jwt"])).\(b64(payload)).sig~"
        return StoredCredential(id: id, format: "dc+sd-jwt", raw: raw, batchId: id, instanceId: 0)
    }

    /// An mdoc whose MSO declares NEITHER `validityInfo` NOR `status` at
    /// all - the one shape `CredentialUtils.parseValidityClaims` returns
    /// nil claims for (every other shape either throws or returns a
    /// non-nil, possibly-empty, dictionary).
    private func claimsFreeMdocCredential(id: Int64) -> StoredCredential {
        let mso: CBOR = .map([.utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL")])
        let msoBytes = CBOR.tagged(.encodedCBORDataItem, .byteString(mso.encode()))
        let issuerSigned: CBOR = .map([
            .utf8String("nameSpaces"): .map([:]),
            .utf8String("issuerAuth"): .array([
                .byteString([]), .map([:]), .byteString(msoBytes.encode()), .byteString([]),
            ]),
        ])
        return StoredCredential(
            id: id,
            format: "mso_mdoc",
            raw: Data(issuerSigned.encode()).base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: ""),
            batchId: id,
            instanceId: 0
        )
    }

    /// Regression (review finding): `deleteCredential(_:)` removes a
    /// credential without bumping the session generation at all (that's a
    /// session-boundary concept, not a per-credential one) - evaluating a
    /// credential that has ALREADY been deleted by the time the (here,
    /// instant) evaluation completes must not resurrect a cache entry for
    /// the freed id.
    func testCredentialStatusDoesNotCacheAResultForACredentialDeletedDuringEvaluation() async {
        let store = InMemoryCredentialStore()
        let credential = expiredCredential(id: 42)
        await store.save(credential)
        let wallet = makeWallet(credentialStore: store)

        // Deleted BEFORE credentialStatus(of:) is even called - simulating
        // the moment a concurrent deletion would have completed while a
        // slower, real evaluation was still in flight. The caller's own
        // `credential` value is still the one from before the deletion,
        // exactly as it would be for an evaluation already under way.
        await wallet.deleteCredential(42)

        let status = await wallet.credentialStatus(of: credential)
        XCTAssertEqual(status, .expired, "the evaluation itself still completes and returns a real result")
        XCTAssertEqual(
            wallet.cachedCredentialStatus(of: 42), .valid,
            "must stay at cachedCredentialStatus's default for an unknown id - .expired must NOT have been cached"
        )
    }

    /// Regression (review finding): a bare `credentialStore.getById` check
    /// before writing to the cache is not atomic WITH a concurrent
    /// `remove(_:)` - deletion can complete in the gap between that check
    /// and the write itself, which a separate async lookup cannot ever
    /// close no matter how late it runs. `CredentialStatusCache` now refuses
    /// a `set` for any id `remove` has tombstoned, checked under the SAME
    /// lock as the write - this exercises that guarantee directly, without
    /// needing to reproduce the exact thread interleaving.
    func testCacheRefusesASetForATombstonedIdEvenWithNoInterveningCheck() {
        let cache = CredentialStatusCache()
        let generation = cache.currentGeneration()
        cache.set(7, .valid, generation: generation)
        XCTAssertEqual(cache.get(7), .valid)

        cache.remove(7) // simulates deleteCredential(_:) completing concurrently
        // simulates the in-flight evaluation's write landing after it, still
        // carrying the generation it captured BEFORE the remove above:
        cache.set(7, .revoked, generation: generation)
        XCTAssertEqual(
            cache.get(7), .valid,
            "a set for a tombstoned id must be refused outright, not merely overwritten by a later remove"
        )
    }

    /// A reused id (the credential store assigning a deleted id to a new,
    /// unrelated credential) must not be refused forever - `retain(_:)` is
    /// what `refreshCredentialStatuses()` calls with every currently-held id,
    /// and an id back in that set must un-tombstone.
    func testCacheAcceptsWritesAgainOnceRetainSeesTheIdReturn() {
        let cache = CredentialStatusCache()
        cache.remove(9)
        cache.set(9, .revoked, generation: cache.currentGeneration())
        XCTAssertEqual(cache.get(9), .valid, "still tombstoned - the reused credential has not been seen yet")

        cache.retain([9])
        cache.set(9, .revoked, generation: cache.currentGeneration())
        XCTAssertEqual(cache.get(9), .revoked, "un-tombstoned once retain saw id 9 as currently held again")
    }

    /// Regression (review finding): a caller capturing "is this still the
    /// same session" via a check made SEPARATELY from (before) the cache
    /// write it guards cannot be atomic with that write, for the exact same
    /// reason a separate existence check before `set` could not be (see the
    /// tombstone test above) - a concurrent `clear()` (session boundary) can
    /// land in the gap between that check and the write. Folding the
    /// generation check into `set` itself, under its own lock, closes it.
    func testCacheRefusesASetFromAnOlderGenerationEvenWithNoInterveningCheck() {
        let cache = CredentialStatusCache()
        let staleGeneration = cache.currentGeneration()

        cache.clear() // simulates endSessionLocally() completing concurrently

        // simulates the in-flight evaluation's write landing after it, still
        // carrying the generation it captured BEFORE the clear above:
        cache.set(7, .revoked, generation: staleGeneration)
        XCTAssertEqual(
            cache.get(7), .valid,
            "a set from a superseded generation must be refused, not resurrect a cleared session's entry"
        )

        // A write using the CURRENT generation must still succeed - this
        // isn't a permanently broken cache, only a stale write is refused.
        cache.set(7, .revoked, generation: cache.currentGeneration())
        XCTAssertEqual(cache.get(7), .revoked)
    }

    /// Regression (review finding, "previously missed" - in code unchanged
    /// since an earlier round): `credentialStatus(of:)`'s "claims parsed to
    /// nil" path returned `.valid` WITHOUT writing it to the cache. An id
    /// SQLite reuses for a later, unrelated credential (the same id-
    /// collision concern `CredentialStatusCache.tombstoned` exists for) can
    /// go from one credential that cached a real unusable status to a new
    /// one with no validity/status claims at all - and without this write,
    /// `cachedCredentialStatus` kept answering with the PREVIOUS occupant's
    /// stale `.revoked`/`.expired`/etc indefinitely, since nothing else ever
    /// overwrites a claims-free credential's entry.
    func testCredentialStatusCachesValidForAClaimsFreeCredentialEvenOverAStaleEntry() async {
        let store = InMemoryCredentialStore()
        let credential = claimsFreeMdocCredential(id: 77)
        await store.save(credential)
        let wallet = makeWallet(credentialStore: store)

        // Simulates id 77's PREVIOUS occupant having cached a real, usable
        // result before being deleted and this id reused.
        wallet.credentialStatusCache.set(77, .revoked, generation: wallet.credentialStatusCache.currentGeneration())
        XCTAssertEqual(wallet.cachedCredentialStatus(of: 77), .revoked, "sanity: the stale entry is actually there")

        let status = await wallet.credentialStatus(of: credential)
        XCTAssertEqual(status, .valid, "a claims-free credential has nothing to mark it anything but valid")
        XCTAssertEqual(
            wallet.cachedCredentialStatus(of: 77), .valid,
            "must overwrite the stale entry, not leave the previous occupant's status in place forever"
        )
    }
}

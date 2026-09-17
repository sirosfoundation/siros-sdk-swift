// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosWallet

final class SessionStoreTests: XCTestCase {

    func testInMemoryStoreBasics() {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        XCTAssertNil(store.appToken)
        XCTAssertFalse(store.hasSession)

        store.appToken = "token-1"
        store.userId = "user-1"
        XCTAssertEqual(store.appToken, "token-1")
        XCTAssertEqual(store.userId, "user-1")
        XCTAssertTrue(store.hasSession)
    }

    func testClearRemovesAll() {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        store.appToken = "tok"
        store.userId = "uid"
        store.refreshToken = "ref"
        store.displayName = "Alice"
        store.tenantId = "t1"
        store.hkdfSalt = "salt"
        store.hkdfInfo = "info"
        store.prfSalt = "prf"
        store.credentialId = "cid"
        store.privateDataJwe = "jwe"
        XCTAssertTrue(store.hasSession)

        store.clear()

        XCTAssertNil(store.appToken)
        XCTAssertNil(store.userId)
        XCTAssertNil(store.refreshToken)
        XCTAssertNil(store.displayName)
        XCTAssertNil(store.tenantId)
        XCTAssertNil(store.hkdfSalt)
        XCTAssertNil(store.hkdfInfo)
        XCTAssertNil(store.prfSalt)
        XCTAssertNil(store.credentialId)
        XCTAssertNil(store.privateDataJwe)
        XCTAssertFalse(store.hasSession)
    }

    func testHasSessionRequiresBothTokenAndUserId() {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        store.appToken = "tok"
        XCTAssertFalse(store.hasSession) // userId nil

        store.appToken = nil
        store.userId = "uid"
        XCTAssertTrue(store.hasSession) // userId set → has session

        store.appToken = "tok"
        XCTAssertTrue(store.hasSession) // both set
    }

    func testOverwriteValue() {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        store.appToken = "first"
        XCTAssertEqual(store.appToken, "first")
        store.appToken = "second"
        XCTAssertEqual(store.appToken, "second")
    }

    func testSetNilRemovesValue() {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        store.appToken = "tok"
        XCTAssertEqual(store.appToken, "tok")
        store.appToken = nil
        XCTAssertNil(store.appToken)
    }

    /// Real Copilot-review finding: appAttestKeyId must be genuinely
    /// install-scoped, NOT account-scoped like every other property here -
    /// App Attest keys are generated once per install and reused forever,
    /// so switching the active account must not affect it at all (unlike
    /// account-scoped properties, which read back nil for a different account).
    func testAppAttestKeyIdIsSharedAcrossAccountsNotAccountScoped() {
        let store = InMemorySessionStore()
        store.activeAccountId = "account-a"
        store.appAttestKeyId = "app-attest-key-1"
        XCTAssertEqual(store.appAttestKeyId, "app-attest-key-1")

        store.activeAccountId = "account-b"
        XCTAssertEqual(store.appAttestKeyId, "app-attest-key-1", "must be visible under a different account too")

        // Contrast with an account-scoped property, which does NOT survive an account switch.
        store.instanceKeyId = "instance-key-b"
        store.activeAccountId = "account-a"
        XCTAssertNil(store.instanceKeyId, "instanceKeyId is account-scoped, unlike appAttestKeyId")
    }

    /// Real Copilot-review finding: clearAccount() (logout/account switch)
    /// must NOT delete appAttestKeyId - only clearAll() (factory reset)
    /// should. Deleting it on logout would force a fresh App Attest key +
    /// attestation on next login, defeating its one-per-install purpose.
    func testAppAttestKeyIdSurvivesClearAccountButNotClearAll() {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        store.appAttestKeyId = "app-attest-key-1"
        store.userId = "user-1"

        store.clearAccount()
        XCTAssertEqual(store.appAttestKeyId, "app-attest-key-1", "clearAccount() must not delete appAttestKeyId")
        XCTAssertNil(store.userId, "clearAccount() must still clear account-scoped data")

        store.clearAll()
        XCTAssertNil(store.appAttestKeyId, "clearAll() (factory reset) must delete appAttestKeyId")
    }

    /// `wscdTofuMappingJson` is a single JSON string blob (matching
    /// `privateDataJwe`'s as-string-blob precedent), account-scoped like
    /// most other properties - unlike `appAttestKeyId`, it must NOT survive
    /// an account switch or `clearAccount()`.
    func testWscdTofuMappingJsonIsAccountScoped() {
        let store = InMemorySessionStore()
        store.activeAccountId = "account-a"
        store.wscdTofuMappingJson = "{\"issuer|type\":\"fido2\"}"
        XCTAssertEqual(store.wscdTofuMappingJson, "{\"issuer|type\":\"fido2\"}")

        store.activeAccountId = "account-b"
        XCTAssertNil(store.wscdTofuMappingJson, "must be account-scoped, unlike appAttestKeyId")

        store.activeAccountId = "account-a"
        XCTAssertEqual(store.wscdTofuMappingJson, "{\"issuer|type\":\"fido2\"}")

        store.clearAccount()
        XCTAssertNil(store.wscdTofuMappingJson, "clearAccount() must clear the TOFU mapping like other account-scoped data")
    }

    /// `wscdUserOverrideMappingJson`/`wscdGlobalOverridePluginId` are new
    /// properties for `WscdSelectionPolicy`'s explicit user-preference
    /// feature - same account-scoping behavior as `wscdTofuMappingJson`
    /// above (a deliberate per-account preference, not an install-wide one
    /// like `appAttestKeyId`).
    func testWscdUserOverridePropertiesAreAccountScoped() {
        let store = InMemorySessionStore()
        store.activeAccountId = "account-a"
        store.wscdUserOverrideMappingJson = "{\"issuer|type\":\"fido2\"}"
        store.wscdGlobalOverridePluginId = "r2ps"
        XCTAssertEqual(store.wscdUserOverrideMappingJson, "{\"issuer|type\":\"fido2\"}")
        XCTAssertEqual(store.wscdGlobalOverridePluginId, "r2ps")

        store.activeAccountId = "account-b"
        XCTAssertNil(store.wscdUserOverrideMappingJson, "must be account-scoped")
        XCTAssertNil(store.wscdGlobalOverridePluginId, "must be account-scoped")

        store.activeAccountId = "account-a"
        XCTAssertEqual(store.wscdUserOverrideMappingJson, "{\"issuer|type\":\"fido2\"}")
        XCTAssertEqual(store.wscdGlobalOverridePluginId, "r2ps")

        store.clearAccount()
        XCTAssertNil(store.wscdUserOverrideMappingJson, "clearAccount() must clear the per-issuer override mapping")
        XCTAssertNil(store.wscdGlobalOverridePluginId, "clearAccount() must clear the global override")
    }

    /// The instance key is what identifies this installation to the backend's
    /// wallet instance lifecycle (SID-AUTH-06). Clearing it on logout would
    /// mint a new key - and therefore a new, unblocked backend instance - at
    /// the next login, letting a suspended or revoked installation walk away
    /// from its block by logging out and back in.
    func testClearAccountKeepsTheInstanceKey() {
        let store = InMemorySessionStore()
        store.activeAccountId = "default:user-1"
        store.instanceKeyId = "instance-key-1"
        store.userId = "user-1"

        store.clearAccount()

        XCTAssertNil(store.userId, "the session itself is cleared")
        XCTAssertEqual(store.instanceKeyId, "instance-key-1", "the instance key survives a logout")
    }

    /// A factory reset is the one thing that does drop it.
    func testClearAllRemovesTheInstanceKey() {
        let store = InMemorySessionStore()
        store.activeAccountId = "default:user-1"
        store.instanceKeyId = "instance-key-1"

        store.clearAll()

        store.activeAccountId = "default:user-1"
        XCTAssertNil(store.instanceKeyId)
    }

    /// Each account keeps its own instance key across the other's logout.
    func testInstanceKeysAreScopedPerAccount() {
        let store = InMemorySessionStore()
        store.activeAccountId = "default:user-1"
        store.instanceKeyId = "key-1"
        store.activeAccountId = "default:user-2"
        store.instanceKeyId = "key-2"

        store.clearAccount()

        XCTAssertEqual(store.instanceKeyId, "key-2")
        store.activeAccountId = "default:user-1"
        XCTAssertEqual(store.instanceKeyId, "key-1")
    }
}

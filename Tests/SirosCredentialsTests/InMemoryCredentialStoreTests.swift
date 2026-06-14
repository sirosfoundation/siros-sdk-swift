// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

final class InMemoryCredentialStoreTests: XCTestCase {

    func testSaveAndGetById() async {
        let store = InMemoryCredentialStore()
        let cred = StoredCredential(id: "c1", format: "dc+sd-jwt", raw: "raw-1",
                                    metadata: CredentialMetadata(name: "Test"))

        await store.save(cred)
        let retrieved = await store.getById("c1")

        XCTAssertNotNil(retrieved)
        XCTAssertEqual(retrieved?.id, "c1")
        XCTAssertEqual(retrieved?.metadata?.name, "Test")
    }

    func testGetAllReturnsAllSavedCredentials() async {
        let store = InMemoryCredentialStore()
        await store.save(StoredCredential(id: "a", format: "dc+sd-jwt", raw: "r"))
        await store.save(StoredCredential(id: "b", format: "mso_mdoc", raw: "r"))
        await store.save(StoredCredential(id: "c", format: "dc+sd-jwt", raw: "r"))

        let all = await store.getAll()
        XCTAssertEqual(all.count, 3)
        XCTAssertEqual(Set(all.map(\.id)), ["a", "b", "c"])
    }

    func testUpdateReplacesExistingCredential() async {
        let store = InMemoryCredentialStore()
        let original = StoredCredential(id: "upd", format: "dc+sd-jwt", raw: "old",
                                        metadata: CredentialMetadata(name: "Old"))
        await store.save(original)

        let updated = StoredCredential(id: "upd", format: "dc+sd-jwt", raw: "new",
                                       metadata: CredentialMetadata(name: "New"))
        await store.update(updated)

        let retrieved = await store.getById("upd")
        XCTAssertEqual(retrieved?.raw, "new")
        XCTAssertEqual(retrieved?.metadata?.name, "New")
    }

    func testDeleteRemovesCredential() async {
        let store = InMemoryCredentialStore()
        await store.save(StoredCredential(id: "del", format: "dc+sd-jwt", raw: "r"))

        await store.delete("del")
        let retrieved = await store.getById("del")
        XCTAssertNil(retrieved)
    }

    func testClearRemovesAllCredentials() async {
        let store = InMemoryCredentialStore()
        await store.save(StoredCredential(id: "x", format: "dc+sd-jwt", raw: "r"))
        await store.save(StoredCredential(id: "y", format: "dc+sd-jwt", raw: "r"))

        await store.clear()
        let all = await store.getAll()
        XCTAssertTrue(all.isEmpty)
    }
}

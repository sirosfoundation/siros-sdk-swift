// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

final class InMemoryCredentialStoreTests: XCTestCase {

    /// StoredCredential now requires batchId/instanceId - defaults batchId
    /// to id (matching wallet-frontend: every issuance response is its own
    /// batch of at least one, so a standalone test credential is simplest
    /// modeled as a batch of one).
    private func storedCredential(
        id: Int64,
        format: String,
        raw: String,
        metadata: CredentialMetadata? = nil,
        notificationId: String? = nil
    ) -> StoredCredential {
        StoredCredential(
            id: id,
            format: format,
            raw: raw,
            metadata: metadata,
            notificationId: notificationId,
            batchId: id,
            instanceId: 0
        )
    }

    func testSaveAndGetById() async {
        let store = InMemoryCredentialStore()
        let cred = storedCredential(id: 1, format: "dc+sd-jwt", raw: "raw-1", metadata: CredentialMetadata(name: "Test"))

        await store.save(cred)
        let retrieved = await store.getById(1)

        XCTAssertNotNil(retrieved)
        XCTAssertEqual(retrieved?.id, 1)
        XCTAssertEqual(retrieved?.metadata?.name, "Test")
    }

    func testGetAllReturnsAllSavedCredentials() async {
        let store = InMemoryCredentialStore()
        await store.save(storedCredential(id: 1, format: "dc+sd-jwt", raw: "r"))
        await store.save(storedCredential(id: 2, format: "mso_mdoc", raw: "r"))
        await store.save(storedCredential(id: 3, format: "dc+sd-jwt", raw: "r"))

        let all = await store.getAll()
        XCTAssertEqual(all.count, 3)
        XCTAssertEqual(Set(all.map(\.id)), [1, 2, 3])
    }

    func testUpdateReplacesExistingCredential() async {
        let store = InMemoryCredentialStore()
        let original = storedCredential(id: 4, format: "dc+sd-jwt", raw: "old", metadata: CredentialMetadata(name: "Old"))
        await store.save(original)

        let updated = storedCredential(id: 4, format: "dc+sd-jwt", raw: "new", metadata: CredentialMetadata(name: "New"))
        await store.update(updated)

        let retrieved = await store.getById(4)
        XCTAssertEqual(retrieved?.raw, "new")
        XCTAssertEqual(retrieved?.metadata?.name, "New")
    }

    func testDeleteRemovesCredential() async {
        let store = InMemoryCredentialStore()
        await store.save(storedCredential(id: 5, format: "dc+sd-jwt", raw: "r"))

        await store.delete(5)
        let retrieved = await store.getById(5)
        XCTAssertNil(retrieved)
    }

    func testClearRemovesAllCredentials() async {
        let store = InMemoryCredentialStore()
        await store.save(storedCredential(id: 6, format: "dc+sd-jwt", raw: "r"))
        await store.save(storedCredential(id: 7, format: "dc+sd-jwt", raw: "r"))

        await store.clear()
        let all = await store.getAll()
        XCTAssertTrue(all.isEmpty)
    }

    func testNotificationIdPersistsThroughStore() async {
        let store = InMemoryCredentialStore()
        let cred = storedCredential(id: 8, format: "dc+sd-jwt", raw: "raw-1", notificationId: "notif-123")
        await store.save(cred)

        let retrieved = await store.getById(8)
        XCTAssertEqual(retrieved?.notificationId, "notif-123")
    }

    func testNotificationIdCodableRoundtrip() throws {
        let cred = storedCredential(id: 9, format: "dc+sd-jwt", raw: "raw-2", notificationId: "notif-456")
        let data = try JSONEncoder().encode(cred)
        let text = String(data: data, encoding: .utf8)!
        XCTAssertTrue(text.contains("\"notification_id\":\"notif-456\""))

        let decoded = try JSONDecoder().decode(StoredCredential.self, from: data)
        XCTAssertEqual(decoded.notificationId, "notif-456")
    }

    func testNotificationIdDefaultsToNil() throws {
        let cred = storedCredential(id: 10, format: "dc+sd-jwt", raw: "raw-3")
        XCTAssertNil(cred.notificationId)

        let data = try JSONEncoder().encode(cred)
        let text = String(data: data, encoding: .utf8)!
        XCTAssertFalse(text.contains("notification_id"))
    }
}

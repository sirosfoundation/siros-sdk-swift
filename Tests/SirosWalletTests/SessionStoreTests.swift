// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosWallet

final class SessionStoreTests: XCTestCase {

    func testInMemoryStoreBasics() {
        let store = InMemorySessionStore()
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
        store.appToken = "tok"
        XCTAssertFalse(store.hasSession) // userId nil

        store.appToken = nil
        store.userId = "uid"
        XCTAssertFalse(store.hasSession) // appToken nil

        store.appToken = "tok"
        XCTAssertTrue(store.hasSession) // both set
    }

    func testOverwriteValue() {
        let store = InMemorySessionStore()
        store.appToken = "first"
        XCTAssertEqual(store.appToken, "first")
        store.appToken = "second"
        XCTAssertEqual(store.appToken, "second")
    }

    func testSetNilRemovesValue() {
        let store = InMemorySessionStore()
        store.appToken = "tok"
        XCTAssertEqual(store.appToken, "tok")
        store.appToken = nil
        XCTAssertNil(store.appToken)
    }
}

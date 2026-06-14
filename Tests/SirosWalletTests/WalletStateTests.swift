// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosWallet
import SirosCredentials

final class WalletStateTests: XCTestCase {

    func testDisconnectedEquality() {
        XCTAssertEqual(WalletState.disconnected, WalletState.disconnected)
    }

    func testReadyEquality() {
        let cred = StoredCredential(id: "c1", format: "dc+sd-jwt", raw: "raw")
        let s1 = WalletState.ready(userId: "u1", displayName: "Alice", credentials: [cred])
        let s2 = WalletState.ready(userId: "u1", displayName: "Alice", credentials: [cred])
        XCTAssertEqual(s1, s2)
    }

    func testReadyInequalityUserId() {
        let s1 = WalletState.ready(userId: "u1", displayName: "Alice", credentials: [])
        let s2 = WalletState.ready(userId: "u2", displayName: "Alice", credentials: [])
        XCTAssertNotEqual(s1, s2)
    }

    func testKeystoreLockedEquality() {
        let s1 = WalletState.keystoreLocked(userId: "u1", displayName: "Alice")
        let s2 = WalletState.keystoreLocked(userId: "u1", displayName: "Alice")
        XCTAssertEqual(s1, s2)
    }

    func testFlowActiveEquality() {
        let s1 = WalletState.flowActive(
            userId: "u1", displayName: "Alice", flowId: "f1",
            flowType: "issuance", status: "in_progress", credentials: []
        )
        let s2 = WalletState.flowActive(
            userId: "u1", displayName: "Alice", flowId: "f1",
            flowType: "issuance", status: "in_progress", credentials: []
        )
        XCTAssertEqual(s1, s2)
    }

    func testErrorEquality() {
        XCTAssertEqual(
            WalletState.error(message: "fail"),
            WalletState.error(message: "fail")
        )
        XCTAssertNotEqual(
            WalletState.error(message: "fail"),
            WalletState.error(message: "other")
        )
    }

    func testConnectingEquality() {
        XCTAssertEqual(WalletState.connecting, WalletState.connecting)
    }

    func testDifferentCasesNotEqual() {
        XCTAssertNotEqual(WalletState.disconnected, WalletState.connecting)
        XCTAssertNotEqual(
            WalletState.disconnected,
            WalletState.error(message: "err")
        )
    }
}

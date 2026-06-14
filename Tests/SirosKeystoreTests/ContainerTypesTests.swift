// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore

final class ContainerTypesTests: XCTestCase {

    func testContainerDataInit() {
        let container = ContainerData(jwe: "test-jwe", mainKey: nil, prfKeys: [])
        XCTAssertEqual(container.jwe, "test-jwe")
        XCTAssertNil(container.mainKey)
        XCTAssertTrue(container.prfKeys.isEmpty)
    }

    func testKeyInfoEquality() {
        let a = KeyInfo(keyId: "k1", algorithm: "ES256", createdAt: 100)
        let b = KeyInfo(keyId: "k1", algorithm: "ES256", createdAt: 100)
        let c = KeyInfo(keyId: "k2", algorithm: "ES256", createdAt: 100)
        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, c)
    }

    func testKeystoreErrorCases() {
        let e1 = KeystoreError.locked
        let e2 = KeystoreError.keyNotFound("test-key")
        let e3 = KeystoreError.containerMissing("no container")
        let e4 = KeystoreError.cryptoError("bad crypto")
        let e5 = KeystoreError.invalidContainer("bad format")
        // Just verify they're valid errors
        XCTAssertNotNil(e1.localizedDescription)
        XCTAssertNotNil(e2.localizedDescription)
        XCTAssertNotNil(e3.localizedDescription)
        XCTAssertNotNil(e4.localizedDescription)
        XCTAssertNotNil(e5.localizedDescription)
    }
}

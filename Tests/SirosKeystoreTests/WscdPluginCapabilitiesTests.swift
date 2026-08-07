// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore

final class WscdPluginCapabilitiesTests: XCTestCase {

    func testKnownPluginTiers() {
        XCTAssertEqual(WscdPluginCapabilities.tier(forPluginId: "softkey"), "iso_18045_basic")
        XCTAssertEqual(WscdPluginCapabilities.tier(forPluginId: "fido2"), "iso_18045_high")
        XCTAssertEqual(WscdPluginCapabilities.tier(forPluginId: "r2ps"), "iso_18045_high")
    }

    func testUnknownPluginHasNoTier() {
        XCTAssertNil(WscdPluginCapabilities.tier(forPluginId: "some-future-plugin"))
    }

    func testMeetsIsReflexive() {
        for tier in WscdPluginCapabilities.tierOrder {
            XCTAssertTrue(WscdPluginCapabilities.meets(actual: tier, required: tier))
        }
    }

    func testMeetsAscendingOrder() {
        XCTAssertTrue(WscdPluginCapabilities.meets(actual: "iso_18045_high", required: "iso_18045_basic"))
        XCTAssertTrue(WscdPluginCapabilities.meets(actual: "iso_18045_moderate", required: "iso_18045_basic"))
        XCTAssertFalse(WscdPluginCapabilities.meets(actual: "iso_18045_basic", required: "iso_18045_moderate"))
        XCTAssertFalse(WscdPluginCapabilities.meets(actual: "iso_18045_basic", required: "iso_18045_high"))
        XCTAssertFalse(WscdPluginCapabilities.meets(actual: "iso_18045_moderate", required: "iso_18045_high"))
    }

    func testMeetsIsFalseForUnrecognizedTierStrings() {
        XCTAssertFalse(WscdPluginCapabilities.meets(actual: "not_a_tier", required: "iso_18045_basic"))
        XCTAssertFalse(WscdPluginCapabilities.meets(actual: "iso_18045_high", required: "not_a_tier"))
    }
}

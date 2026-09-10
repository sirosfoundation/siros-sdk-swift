// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosTransport

/// The descriptor is the wire contract between a wrapper app and the page
/// (its Kotlin and TypeScript twins are generated from the same spec), so
/// these pin the JSON shape rather than the Swift API: the page only ever
/// sees the JSON.
final class BridgeDescriptorTests: XCTestCase {

    private let host = BridgeHost(name: "org.siros.wwwallet", version: "3.1.0", sdkVersion: "0.9.0")

    private func json(_ text: String) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any])
    }

    func testDescriptorCarriesVersionsHostAndOnlyOfferedCapabilities() throws {
        let text = try BridgeDescriptorBuilder(platform: "ios", host: host)
            .zk(ZkCapability(systems: ["longfellow-libzk-v1"], circuitCache: true))
            .proximitySession(ProximitySessionCapability(transports: ["ble_peripheral"], nfcStaticHandover: true))
            .oidc()
            .encode()
        let root = try json(text)

        XCTAssertEqual((root["bridge"] as? [String: Any])?["version"] as? Int, BridgeVocabulary.descriptorVersion)
        XCTAssertEqual(root["vocabulary"] as? Int, BridgeVocabulary.version)
        XCTAssertEqual(root["platform"] as? String, "ios")
        XCTAssertEqual((root["host"] as? [String: Any])?["sdk_version"] as? String, "0.9.0")

        let caps = try XCTUnwrap(root["capabilities"] as? [String: Any])
        XCTAssertEqual(Set(caps.keys), ["zk", "proximity.session", "oidc"])
        XCTAssertEqual((caps["zk"] as? [String: Any])?["systems"] as? [String], ["longfellow-libzk-v1"])
        XCTAssertEqual((caps["proximity.session"] as? [String: Any])?["nfc_static_handover"] as? Bool, true)
        // No parameters is an empty object, not null - presence is the signal.
        XCTAssertEqual((caps["oidc"] as? [String: Any])?.isEmpty, true)
        // Unset parameters are omitted, never null.
        XCTAssertNil((caps["proximity.session"] as? [String: Any])?["reader_auth"])
    }

    func testIdsAreStableAndDeprecatedNamesOnlyRetiredOnes() {
        XCTAssertEqual(BridgeCapabilityId.idvPhysicalId, "idv.physical_id")
        XCTAssertEqual(BridgeCapabilityId.all.count, Set(BridgeCapabilityId.all).count)
        XCTAssertTrue(BridgeCapabilityId.deprecated.keys.allSatisfy { BridgeCapabilityId.all.contains($0) })
        XCTAssertNotNil(BridgeCapabilityId.deprecated[BridgeCapabilityId.proximityBytePipe])
        XCTAssertNil(BridgeCapabilityId.deprecated[BridgeCapabilityId.proximitySession])
    }

    func testDescriptorRoundTripsThroughCodable() throws {
        let built = try BridgeDescriptorBuilder(platform: "ios", host: host)
            .webauthn(WebauthnCapability(prf: true, securityKeyTransports: ["nfc", "usb"]))
            .build()
        let data = try JSONEncoder().encode(built)
        let decoded = try JSONDecoder().decode(BridgeDescriptor.self, from: data)
        XCTAssertEqual(decoded.capabilities, built.capabilities)
        XCTAssertEqual(decoded.host.sdkVersion, "0.9.0")
        let webauthn = try JSONDecoder().decode(
            WebauthnCapability.self,
            from: JSONEncoder().encode(try XCTUnwrap(decoded.capabilities["webauthn"]))
        )
        XCTAssertEqual(webauthn.securityKeyTransports, ["nfc", "usb"])
    }
}

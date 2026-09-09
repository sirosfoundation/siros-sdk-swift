// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosWallet

final class HostAppRequirementsTests: XCTestCase {

    private func fullyDeclared() -> [String: Any] {
        [
            "CFBundleURLTypes": [["CFBundleURLSchemes": DeepLinkClassifier.handledSchemes + ["my-app"]]],
            "NSCameraUsageDescription": "camera",
            "NSBluetoothAlwaysUsageDescription": "ble",
            "NFCReaderUsageDescription": "nfc",
            "NSFaceIDUsageDescription": "face",
        ]
    }

    func testAFullyDeclaredBundleHasNoFindings() {
        XCTAssertEqual(HostAppRequirements.audit(infoDictionary: fullyDeclared(), callbackScheme: "my-app"), [])
    }

    func testEveryMissingDeclarationIsReportedOnce() {
        let findings = HostAppRequirements.audit(infoDictionary: [:], callbackScheme: "my-app")
        let kinds = findings.map(\.requirement.kind)
        // Every handled scheme, the callback scheme, and every usage
        // description - the camera one is needed by two features but is one
        // key, reported once per feature that needs it so the reason is
        // specific.
        for scheme in DeepLinkClassifier.handledSchemes {
            XCTAssertTrue(kinds.contains(.urlScheme(scheme)), "\(scheme) not reported")
        }
        XCTAssertTrue(kinds.contains(.urlScheme("my-app")))
        XCTAssertTrue(kinds.contains(.infoPlistKey("NSBluetoothAlwaysUsageDescription")))
        XCTAssertTrue(kinds.contains(.infoPlistKey("NFCReaderUsageDescription")))
        XCTAssertTrue(kinds.contains(.infoPlistKey("NSFaceIDUsageDescription")))
        XCTAssertEqual(kinds.filter { $0 == .infoPlistKey("NSCameraUsageDescription") }.count, 2)
        // Entitlements are documented, never flagged.
        XCTAssertFalse(kinds.contains { if case .entitlement = $0 { return true } else { return false } })
    }

    func testFeaturesScopeWhatIsChecked() {
        let findings = HostAppRequirements.audit(infoDictionary: [:], features: [.bleProximity])
        XCTAssertEqual(findings.map(\.requirement.kind), [.infoPlistKey("NSBluetoothAlwaysUsageDescription")])
    }

    func testAnEmptyUsageDescriptionCountsAsMissing() {
        var info = fullyDeclared()
        info["NSCameraUsageDescription"] = ""
        let findings = HostAppRequirements.audit(infoDictionary: info, features: [.qrScanning])
        XCTAssertEqual(findings.count, 1)
        XCTAssertTrue(findings[0].description.contains("NSCameraUsageDescription"))
    }

    func testSchemeMatchingIsCaseInsensitive() {
        var info = fullyDeclared()
        info["CFBundleURLTypes"] = [["CFBundleURLSchemes": DeepLinkClassifier.handledSchemes.map { $0.uppercased() }]]
        XCTAssertEqual(HostAppRequirements.audit(infoDictionary: info, features: [.deepLinks]), [])
    }

    func testTheRequirementListDocumentsEntitlementsToo() {
        let entitlements = HostAppRequirements.requirements().compactMap { r -> String? in
            if case .entitlement(let e) = r.kind { return e } else { return nil }
        }
        XCTAssertEqual(Set(entitlements), ["com.apple.developer.associated-domains", "com.apple.developer.nfc.readersession.formats"])
    }
}

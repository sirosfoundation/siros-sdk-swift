// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosSampleApp

/// How the wallet's screens are organised: the bottom bar and the menu lead
/// to destinations, and History, Add Credentials, Scan Photo ID and the
/// scanner stack over whichever destination is current.
@MainActor
final class WalletNavigationTests: XCTestCase {

    func testHomeIsTheStartingDestination() {
        let vm = WalletViewModel()
        XCTAssertEqual(vm.destination, .home)
        XCTAssertNil(vm.currentMenuItem)
    }

    /// The three tabs `selectedTab` has always named keep their numbers.
    func testDestinationsAreSelectedTabsValues() {
        let vm = WalletViewModel()
        vm.selectedTab = 0
        XCTAssertEqual(vm.destination, .credentials)
        vm.selectedTab = 2
        XCTAssertEqual(vm.destination, .settings)
        vm.destination = .share
        XCTAssertEqual(vm.selectedTab, WalletDestination.share.rawValue)
        vm.selectedTab = 99
        XCTAssertEqual(vm.destination, .home)
    }

    func testGoingToADestinationLeavesEveryStackedScreen() {
        let vm = WalletViewModel()
        vm.showHistory = true
        vm.showAddCredential = true
        vm.showIDVPreparation = true
        vm.openActivate()

        vm.go(.share)

        XCTAssertEqual(vm.destination, .share)
        XCTAssertFalse(vm.showHistory)
        XCTAssertFalse(vm.showAddCredential)
        XCTAssertFalse(vm.showIDVPreparation)
        XCTAssertFalse(vm.showActivate)
    }

    func testScanQrOpensTheScannerOverTheCurrentDestination() {
        let vm = WalletViewModel()
        vm.go(.credentials)
        vm.showHistory = true
        vm.openActivate(mode: .proximity)

        vm.scanQr()

        XCTAssertTrue(vm.showActivate)
        XCTAssertEqual(vm.activateMode, .qr)
        XCTAssertFalse(vm.showHistory)
        XCTAssertEqual(vm.destination, .credentials)
    }

    func testTheMenuHighlightsTheScreenItWasOpenedFrom() {
        let vm = WalletViewModel()
        vm.go(.settings)
        vm.openMenu()
        XCTAssertEqual(vm.destination, .menu)
        XCTAssertEqual(vm.menuOrigin, .settings)

        // Opening it again from the menu itself keeps the highlight.
        vm.openMenu()
        XCTAssertEqual(vm.menuOrigin, .settings)

        // From a stacked screen, that screen is the origin.
        vm.go(.credentials)
        vm.showHistory = true
        vm.openMenu()
        XCTAssertEqual(vm.menuOrigin, .history)
        XCTAssertFalse(vm.showHistory)

        // From Home there is nothing to highlight.
        vm.go(.home)
        vm.openMenu()
        XCTAssertNil(vm.menuOrigin)
    }

    func testManageCredentialsOpensOnTheRequestedFilter() {
        let vm = WalletViewModel()
        vm.openManageCredentials(needsAttentionOnly: true)
        XCTAssertEqual(vm.destination, .credentials)
        XCTAssertTrue(vm.needsAttentionOnly)
        XCTAssertEqual(vm.currentMenuItem, .manageCredentials)

        vm.go(.home)
        vm.openManageCredentials(needsAttentionOnly: false)
        XCTAssertFalse(vm.needsAttentionOnly)
    }

    /// The appearance setting: a stored choice is read back, anything else
    /// follows the device, and only an explicit choice overrides it.
    func testTheAppearanceChoice() {
        for mode in ThemeMode.allCases {
            XCTAssertEqual(ThemeMode.fromStored(mode.rawValue), mode)
        }
        XCTAssertEqual(ThemeMode.fromStored(nil), .system)
        XCTAssertEqual(ThemeMode.fromStored("sepia"), .system)
        XCTAssertNil(ThemeMode.system.colorScheme)
        XCTAssertEqual(ThemeMode.light.colorScheme, .light)
        XCTAssertEqual(ThemeMode.dark.colorScheme, .dark)
    }

    /// Every string the designed screens look up is in both language tables
    /// (read from the source tree, as `FlowStepLabelTests` does).
    func testTheDesignedScreensStringsAreInBothLanguageTables() throws {
        let keys = [
            "chrome.title", "chrome.myWallet", "chrome.walletOf", "nav.home", "nav.scanQr", "nav.menu", "nav.back",
            "home.welcomeBack", "home.welcomeBackName", "home.attentionOne", "home.attentionOther",
            "home.manageCredentials", "home.shareInPerson", "home.promptBegin", "home.promptGetStarted",
            "home.addCredentialsText", "menu.history", "menu.about", "menu.verify", "menu.logout", "menu.poweredBy",
            "share.title", "share.intro", "share.showQrTitle", "share.showQrSubtitle", "share.scanQrTitle",
            "share.scanQrSubtitle", "share.showQrCaption", "share.showQrDescription",
            "manage.title", "manage.search", "manage.filterAll", "manage.filterAttention",
            "manage.noneNeedAttention", "manage.noMatch", "about.text", "about.version", "about.license",
            "history.today", "history.yesterday", "history.search", "qr.caption",
            "credentials.scanQrTitle", "credentials.scanQrSubtitle", "credentials.addAvailable", "idv.stepNumber",
            "settings.appearanceSection", "settings.appearanceSystem", "settings.appearanceLight",
            "settings.appearanceDark",
        ]
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        for name in ["en", "sv"] {
            let data = try Data(contentsOf: root.appendingPathComponent("Resources/i18n/\(name).json"))
            let table = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
            for key in keys {
                var current: Any? = table
                for segment in key.split(separator: ".") {
                    current = (current as? [String: Any])?[String(segment)]
                }
                XCTAssertNotNil(current as? String, "\(key) is missing from \(name).json")
            }
        }
    }
}

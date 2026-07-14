// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosWallet

final class WalletConfigTests: XCTestCase {

    func testDefaultConfig() {
        let config = WalletConfig(backendUrl: "https://wallet.example.com")
        XCTAssertEqual(config.backendUrl, "https://wallet.example.com")
        XCTAssertEqual(config.tenantId, "default")
        XCTAssertEqual(config.redirectUri, "")
        XCTAssertNil(config.credentialStore)
        XCTAssertNil(config.urlRewriter)
        XCTAssertTrue(config.requireUserAuth)
        XCTAssertFalse(config.useWmpProtocol)
    }

    func testCustomConfig() {
        let config = WalletConfig(
            backendUrl: "https://api.example.com",
            tenantId: "tenant-42",
            redirectUri: "myapp://callback",
            requireUserAuth: false
        )
        XCTAssertEqual(config.backendUrl, "https://api.example.com")
        XCTAssertEqual(config.tenantId, "tenant-42")
        XCTAssertEqual(config.redirectUri, "myapp://callback")
        XCTAssertFalse(config.requireUserAuth)
    }

    func testUrlRewriter() {
        var config = WalletConfig(backendUrl: "https://wallet.example.com")
        config.urlRewriter = { url in
            url.replacingOccurrences(of: "internal", with: "external")
        }
        let rewritten = config.urlRewriter?("https://internal.example.com")
        XCTAssertEqual(rewritten, "https://external.example.com")
    }

    func testUseWmpProtocol() {
        let legacyConfig = WalletConfig(backendUrl: "https://wallet.example.com")
        XCTAssertFalse(legacyConfig.useWmpProtocol, "legacy mode is the default")

        let wmpConfig = WalletConfig(backendUrl: "https://wallet.example.com", useWmpProtocol: true)
        XCTAssertTrue(wmpConfig.useWmpProtocol)
    }
}

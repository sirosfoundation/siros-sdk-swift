// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosTransport

/// The discovery base and well-known URL rules of WMP Core 7.5.1.
final class WmpDiscoveryBaseTests: XCTestCase {
    private let wk = "/.well-known/wmp-configuration"

    func testTheWellKnownURLInsertsTheSegmentBeforeTheTenantPath() {
        // The rows of the well-known URL table of the specification.
        let rows = [
            ("x509:san:dns:example.com", "https://example.com\(wk)"),
            ("https://example.com", "https://example.com\(wk)"),
            ("https://example.com/", "https://example.com\(wk)"),
            ("https://example.com/tenant1", "https://example.com\(wk)/tenant1"),
            ("https://example.com:8443/tenants/acme/", "https://example.com:8443\(wk)/tenants/acme"),
            ("x509:san:uri:https://example.com/tenant1", "https://example.com\(wk)/tenant1"),
            ("did:web:example.com", "https://example.com\(wk)"),
            ("did:web:example.com%3A8443", "https://example.com:8443\(wk)"),
            ("https://[::1]:8443/t", "https://[::1]:8443\(wk)/t"),
        ]
        for (identifier, url) in rows {
            XCTAssertEqual(WmpDiscoveryBase(identifier: identifier)?.wellKnownURL, url, identifier)
        }
    }

    func testIdentifiersWithoutADiscoveryBase() {
        let none = [
            "did:web:example.com:tenant1",
            "did:key:z6Mkf5rGMoatrSj1f3JWKc",
            "https://example.com/tenant1?x=1",
            "https://example.com/tenant1?",
            "https://example.com/tenant1#frag",
            "https://user@example.com/tenant1",
            "https://example.com/a/../b",
            "https://example.com/a/./b",
            "https://example.com/a/%2e%2e/b",
            "https://example.com/a/%zz/b",
            "https://example.com\\@evil.example/",
            "https://-example.com/t",
            "https://example..com/t",
            "x509:san:uri:https://example.com/t?x=1",
            "x509:san:uri:http://example.com/t",
            "x509:san:dns:example.com/path",
            "http://example.com/tenant1",
            "opaque",
        ]
        for identifier in none {
            XCTAssertNil(WmpDiscoveryBase(identifier: identifier), identifier)
        }
    }

    func testATenantDocumentMustNameTheTenant() throws {
        let tenant = try XCTUnwrap(WmpDiscoveryBase(identifier: "https://example.com/tenants/acme"))
        XCTAssertTrue(tenant.isDescribed(by: "https://example.com/tenants/acme"))
        XCTAssertTrue(tenant.isDescribed(by: "HTTPS://EXAMPLE.com/tenants/acme"))
        XCTAssertFalse(tenant.isDescribed(by: "https://example.com/tenants/acme/"), "trailing slash")
        XCTAssertFalse(tenant.isDescribed(by: nil), "absent")
        XCTAssertFalse(tenant.isDescribed(by: ""), "empty")
        XCTAssertFalse(tenant.isDescribed(by: "https://example.com"), "the host's")
        XCTAssertFalse(tenant.isDescribed(by: "https://example.com/tenants/other"), "another tenant's")
        XCTAssertFalse(tenant.isDescribed(by: "https://evil.example/tenants/acme"), "another host's")
        XCTAssertFalse(tenant.isDescribed(by: "https://example.com:8443/tenants/acme"), "another port's")
        XCTAssertFalse(tenant.isDescribed(by: "https://example.com/tenants/ACME"), "path case")
    }

    func testAHostDocumentMayLeaveTheBaseOutButNotNameAnother() throws {
        let host = try XCTUnwrap(WmpDiscoveryBase(identifier: "x509:san:dns:example.com"))
        XCTAssertTrue(host.isDescribed(by: nil))
        XCTAssertTrue(host.isDescribed(by: "https://example.com"))
        XCTAssertFalse(host.isDescribed(by: "https://example.com/"), "trailing slash")
        XCTAssertFalse(host.isDescribed(by: "https://example.com/tenant1"))
        XCTAssertFalse(host.isDescribed(by: "https://evil.example"))
    }
}

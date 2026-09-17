// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosCredentials
@testable import SirosWallet

/// A configured per-issuer interop override must apply to that issuer and to
/// nothing that merely looks like it.
///
/// A raw string prefix matches `https://issuer.example.evil` (a different
/// domain) and `https://issuer.example@evil.com/x` (where the familiar-looking
/// part is only userinfo), either of which hands one issuer's configuration to
/// somebody else.
final class IssuerOverrideMatchingTests: XCTestCase {

    private func matches(_ issuer: String, _ configured: String) -> Bool {
        guard let url = URL(string: issuer) else { return false }
        return SirosWallet.sameIssuer(url, configured)
    }

    func testTheConfiguredIssuerAndPathsUnderItMatch() {
        XCTAssertTrue(matches("https://issuer.example", "https://issuer.example"))
        XCTAssertTrue(matches("https://issuer.example/", "https://issuer.example"))
        XCTAssertTrue(matches("https://issuer.example/oid4vci", "https://issuer.example"))
        XCTAssertTrue(matches("https://issuer.example/a/b", "https://issuer.example/a"))
    }

    func testADifferentDomainDoesNotMatch() {
        XCTAssertFalse(matches("https://issuer.example.evil", "https://issuer.example"))
        XCTAssertFalse(matches("https://issuer.example.co/x", "https://issuer.example"))
    }

    func testUserinfoNeverMatches() {
        // The part that looks like the configured issuer is userinfo; the real
        // host is evil.com. A legitimate credential_issuer carries none.
        XCTAssertFalse(matches("https://issuer.example@evil.com/x", "https://issuer.example"))
        XCTAssertFalse(matches("https://issuer.example", "https://user@issuer.example"))
    }

    func testASiblingPathDoesNotMatch() {
        XCTAssertFalse(matches("https://issuer.example/abc", "https://issuer.example/a"))
    }

    func testADifferentSchemeDoesNotMatch() {
        XCTAssertFalse(matches("http://issuer.example", "https://issuer.example"))
    }

    func testAnExplicitDefaultPortIsTheSameIssuer() {
        // `URL.port` is nil for the implicit form, which is a detail of the
        // parser and not a different host - comparing it directly would
        // silently drop the override.
        XCTAssertTrue(matches("https://issuer.example:443/oid4vci", "https://issuer.example"))
        XCTAssertTrue(matches("https://issuer.example", "https://issuer.example:443"))
        XCTAssertTrue(matches("http://issuer.example:80", "http://issuer.example"))
    }

    func testANonDefaultPortIsADifferentIssuer() {
        XCTAssertFalse(matches("https://issuer.example:8443", "https://issuer.example"))
    }
}

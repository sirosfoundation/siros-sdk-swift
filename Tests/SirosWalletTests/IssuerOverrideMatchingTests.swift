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

    // MARK: - sameAdvertisedIssuer (holderBinding's offer/proof-issuer match)
    //
    // Same policy as sameIssuer above, applied to the active offer's
    // credential_issuer against the issuer a proof is being signed for -
    // negotiated binding methods from the WRONG offer must never apply.

    func testSameAdvertisedIssuerMatchesThroughNormalIssuerComparison() {
        XCTAssertTrue(SirosWallet.sameAdvertisedIssuer("https://issuer.example", "https://issuer.example"))
        // The offer's issuer is the "configured" side sameIssuer checks a
        // path against, so a MORE specific issuer being proved for is still
        // the same issuer the offer advertised.
        XCTAssertTrue(SirosWallet.sameAdvertisedIssuer("https://issuer.example", "https://issuer.example:443"))
        XCTAssertTrue(SirosWallet.sameAdvertisedIssuer("https://issuer.example", "https://issuer.example/oid4vci"))
    }

    func testSameAdvertisedIssuerNilIssuerMeansTheOnlyInFlightOfferApplies() {
        XCTAssertTrue(SirosWallet.sameAdvertisedIssuer("https://issuer.example", nil))
        XCTAssertFalse(SirosWallet.sameAdvertisedIssuer(nil, "https://issuer.example"))
    }

    /// Regression (review finding): a raw `==` fast path let two copies of
    /// the SAME confusing string - a URL carrying userinfo - match each
    /// other here while `sameIssuer` (the policy this function exists to
    /// apply consistently) rejects exactly that shape. There must be no
    /// shortcut around it.
    func testSameAdvertisedIssuerNeverShortcutsAroundUserinfoRejection() {
        let confusing = "https://issuer.example@evil.example"
        XCTAssertFalse(
            SirosWallet.sameAdvertisedIssuer(confusing, confusing),
            "identical strings must not bypass sameIssuer's userinfo rejection"
        )
    }

}

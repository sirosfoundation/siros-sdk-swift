// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

final class CredentialStatusTests: XCTestCase {

    private let now = Date(timeIntervalSince1970: 1_780_315_200) // 2026-06-01T12:00:00Z

    private func claims(_ json: String) -> [String: Any] {
        (try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]) ?? [:]
    }

    // MARK: - the validity window

    func testVcdmPropertiesArePreferredOverTheJwtClaims() {
        // A VCDM credential's own validFrom/validUntil are authoritative; the
        // enveloping JWT's exp may be shorter and is not the credential's.
        let window = CredentialValidity.extract(from: claims("""
        {"validFrom":"2026-01-01T00:00:00Z","validUntil":"2027-01-01T00:00:00Z","nbf":1,"exp":2}
        """))
        XCTAssertEqual(window.validFrom, ISO8601DateFormatter().date(from: "2026-01-01T00:00:00Z"))
        XCTAssertEqual(window.validUntil, ISO8601DateFormatter().date(from: "2027-01-01T00:00:00Z"))
    }

    func testNbfAndExpStandInWhenTheVcdmPropertiesAreAbsent() {
        let window = CredentialValidity.extract(
            from: claims(#"{"nbf":1700000000,"exp":1800000000,"iat":1700000000}"#)
        )
        XCTAssertEqual(window.validFrom, Date(timeIntervalSince1970: 1_700_000_000))
        XCTAssertEqual(window.validUntil, Date(timeIntervalSince1970: 1_800_000_000))
        XCTAssertEqual(window.signed, Date(timeIntervalSince1970: 1_700_000_000))
    }

    func testATimestampWithAnOffsetRatherThanZStillParses() {
        let window = CredentialValidity.extract(from: claims(#"{"validUntil":"2027-01-01T00:00:00+02:00"}"#))
        XCTAssertEqual(window.validUntil, ISO8601DateFormatter().date(from: "2026-12-31T22:00:00Z"))
    }

    func testAnUnparseableTimestampIsIgnoredRatherThanFailingTheCredential() {
        XCTAssertNil(CredentialValidity.extract(from: claims(#"{"validUntil":"whenever"}"#)).validUntil)
    }

    func testNoBoundsMeansValidIndefinitely() {
        XCTAssertEqual(
            CredentialValidity.check(CredentialValidity.extract(from: claims("{}")), now: now),
            .valid
        )
    }

    func testACredentialPastValidUntilIsExpired() {
        let window = CredentialValidity.extract(from: claims(#"{"validUntil":"2026-05-01T00:00:00Z"}"#))
        XCTAssertEqual(CredentialValidity.check(window, now: now), .expired)
    }

    func testACredentialBeforeValidFromIsNotYetValid() {
        let window = CredentialValidity.extract(from: claims(#"{"validFrom":"2026-07-01T00:00:00Z"}"#))
        XCTAssertEqual(CredentialValidity.check(window, now: now), .notYetValid)
    }

    func testClockToleranceCoversSkewAtBothEdgesOfTheWindow() {
        let justExpired = CredentialValidity.extract(from: claims(#"{"validUntil":"2026-06-01T11:59:30Z"}"#))
        XCTAssertEqual(CredentialValidity.check(justExpired, clockTolerance: 0, now: now), .expired)
        XCTAssertEqual(CredentialValidity.check(justExpired, clockTolerance: 60, now: now), .valid)

        let justStarted = CredentialValidity.extract(from: claims(#"{"validFrom":"2026-06-01T12:00:30Z"}"#))
        XCTAssertEqual(CredentialValidity.check(justStarted, clockTolerance: 0, now: now), .notYetValid)
        XCTAssertEqual(CredentialValidity.check(justStarted, clockTolerance: 60, now: now), .valid)
    }

    func testExpiryIsReportedAheadOfNotYetValidWhenAWindowIsInverted() {
        // A malformed window should still name one reason, deterministically.
        let window = ValidityWindow(
            validFrom: ISO8601DateFormatter().date(from: "2027-01-01T00:00:00Z"),
            validUntil: ISO8601DateFormatter().date(from: "2026-01-01T00:00:00Z")
        )
        XCTAssertEqual(CredentialValidity.check(window, now: now), .expired)
    }

    // MARK: - the whole algorithm

    func testTheValidityWindowShortCircuitsTheStatusList() async {
        // An expired credential is expired whether or not the issuer's status
        // endpoint answers, and saying so needs no network.
        let evaluator = CredentialStatusEvaluator(
            statusListClient: TokenStatusListClient(
                httpGet: { _, _ in
                    XCTFail("the status list must not be fetched")
                    return nil
                }
            ),
            now: { self.now }
        )
        let status = await evaluator.evaluate(claims: claims("""
        {"validUntil":"2026-01-01T00:00:00Z","status":{"status_list":{"idx":1,"uri":"https://x.example"}}}
        """))
        XCTAssertEqual(status, .expired)
    }

    func testACredentialWithNoStatusReferenceIsValid() async {
        let evaluator = CredentialStatusEvaluator(now: { self.now })
        let status = await evaluator.evaluate(claims: claims(#"{"iss":"https://issuer.example"}"#))
        XCTAssertEqual(status, .valid)
    }

    func testAnUnreachableStatusListLeavesTheCredentialUsable() async {
        // Hiding a credential because the issuer's status endpoint is down
        // would make the wallet unusable offline. This is deliberate.
        let evaluator = CredentialStatusEvaluator(
            statusListClient: TokenStatusListClient(httpGet: { _, _ in nil }),
            now: { self.now }
        )
        let status = await evaluator.evaluate(claims: claims("""
        {"iss":"https://issuer.example","status":{"status_list":{"idx":1,"uri":"https://x.example"}}}
        """))
        XCTAssertEqual(status, .valid)
    }

    func testAStatusListThatIsNotATypedStatusListTokenIsNotTrusted() async {
        let evaluator = CredentialStatusEvaluator(
            statusListClient: TokenStatusListClient(httpGet: { _, _ in Data("not-a-jws".utf8) }),
            now: { self.now }
        )
        let status = await evaluator.evaluate(claims: claims("""
        {"iss":"https://issuer.example","status":{"status_list":{"idx":1,"uri":"https://x.example"}}}
        """))
        XCTAssertEqual(status, .valid)
    }

    func testOnlyValidIsUsable() {
        XCTAssertTrue(CredentialStatus.valid.isUsable)
        for status in CredentialStatus.allCases where status != .valid {
            XCTAssertFalse(status.isUsable, "\(status)")
        }
    }

    func testTheIssuerOfAVcdmCredentialIsItsIssuerProperty() {
        XCTAssertEqual(
            CredentialStatusEvaluator.issuer(of: claims(#"{"iss":"https://a.example"}"#)),
            "https://a.example"
        )
        XCTAssertEqual(
            CredentialStatusEvaluator.issuer(of: claims(#"{"issuer":"https://b.example"}"#)),
            "https://b.example"
        )
        XCTAssertEqual(
            CredentialStatusEvaluator.issuer(of: claims(#"{"issuer":{"id":"https://c.example"}}"#)),
            "https://c.example"
        )
        XCTAssertNil(CredentialStatusEvaluator.issuer(of: claims("{}")))
    }
}

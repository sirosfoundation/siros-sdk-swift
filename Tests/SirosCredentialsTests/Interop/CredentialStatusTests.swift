// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

final class CredentialStatusTests: XCTestCase {

    private let now = Date(timeIntervalSince1970: 1_780_315_200) // 2026-06-01T12:00:00Z

    private func claims(_ json: String) -> [String: Any] {
        (try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]) ?? [:]
    }

    // MARK: - selectively disclosed validity/status claims
    //
    // Mirrors SharedDcqlMatcherTests' sdJwt/digest helpers - building a real
    // SD-JWT whose validity/status claim is hidden behind an `_sd` digest,
    // the same shape an Issuer actually produces.

    private func b64url(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func digest(of disclosure: String) -> String {
        b64url(Data(SHA256.hash(data: Data(disclosure.utf8))))
    }

    /// Build a real SD-JWT VC: a JWT whose payload hides `hidden` behind an
    /// `_sd` digest, followed by the disclosure that opens it.
    private func sdJwt(plain: [String: Any], hidden: (String, Any)) -> String {
        let disclosureJson = try! JSONSerialization.data(withJSONObject: ["c2FsdA", hidden.0, hidden.1])
        let disclosure = b64url(disclosureJson)

        var payload = plain
        payload["_sd"] = [digest(of: disclosure)]
        payload["_sd_alg"] = "sha-256"
        let body = b64url(try! JSONSerialization.data(withJSONObject: payload))
        return "eyJhbGciOiJFUzI1NiJ9.\(body).sig~\(disclosure)~"
    }

    private func sdJwtCredential(raw: String) -> StoredCredential {
        StoredCredential(id: 1, format: "dc+sd-jwt", raw: raw, batchId: 1, instanceId: 0)
    }

    /// Regression (review finding): `parseValidityClaims` only ever read the
    /// JWT body, so a selectively disclosed `validUntil` was simply absent -
    /// `CredentialValidity.extract` then saw no bound at all and reported the
    /// credential valid indefinitely, regardless of what the disclosed claim
    /// actually said.
    func testADisclosedValidUntilIsFoundNotReportedAsNoBound() throws {
        let credential = sdJwtCredential(
            raw: sdJwt(plain: ["vct": "urn:eu.europa.ec.eudi:pid:1"], hidden: ("validUntil", "2026-05-01T00:00:00Z"))
        )
        let parsed = try XCTUnwrap(CredentialUtils.parseValidityClaims(credential))
        XCTAssertEqual(parsed["validUntil"] as? String, "2026-05-01T00:00:00Z")
        let window = CredentialValidity.extract(from: parsed)
        XCTAssertEqual(CredentialValidity.check(window, now: now), .expired)
    }

    /// Same regression, for the Token Status List reference rather than the
    /// validity window - a disclosed `status` must be visible to
    /// `CredentialStatusEvaluator` too.
    func testADisclosedStatusReferenceIsFoundNotReportedAsAbsent() throws {
        let statusClaim: [String: Any] = ["status_list": ["idx": 1, "uri": "https://status.example"]]
        let credential = sdJwtCredential(
            raw: sdJwt(plain: ["vct": "urn:eu.europa.ec.eudi:pid:1"], hidden: ("status", statusClaim))
        )
        let parsed = try XCTUnwrap(CredentialUtils.parseValidityClaims(credential))
        let status = try XCTUnwrap(parsed["status"] as? [String: Any])
        let statusList = try XCTUnwrap(status["status_list"] as? [String: Any])
        XCTAssertEqual(statusList["uri"] as? String, "https://status.example")
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

    /// Regression (review finding): `clearCache()` must exist and be callable
    /// at a session boundary (logout) regardless of whether revocation
    /// checking is even configured - a no-op `statusListClient` must not
    /// crash.
    func testClearCacheIsSafeWhenRevocationCheckingIsDisabled() async {
        let evaluator = CredentialStatusEvaluator(now: { self.now })
        await evaluator.clearCache()
    }

    func testACredentialWithNoStatusReferenceIsValid() async {
        let evaluator = CredentialStatusEvaluator(now: { self.now })
        let status = await evaluator.evaluate(claims: claims(#"{"iss":"https://issuer.example"}"#))
        XCTAssertEqual(status, .valid)
    }

    /// Regression (review finding): a status_list claim present but
    /// unreadable (here, a `uri` with no `idx` at all - mdocValidityClaims
    /// preserves exactly this shape when the real idx overflows Int) must
    /// not be conflated with "no status claim", which evaluates to `.valid`
    /// for free. A statusListClient that would fail the test if consulted
    /// confirms this is caught before ever reaching the network, the same
    /// way the validity-window short-circuit above is.
    func testAStatusReferenceMissingItsIdxIsUnknownNotValid() async {
        let evaluator = CredentialStatusEvaluator(
            statusListClient: TokenStatusListClient(
                httpGet: { _, _ in
                    XCTFail("a malformed reference must never reach the network")
                    return nil
                }
            ),
            now: { self.now }
        )
        let status = await evaluator.evaluate(claims: claims(#"{"status":{"status_list":{"uri":"https://x.example"}}}"#))
        XCTAssertEqual(status, .unknown)
    }

    /// Regression (review finding): with no known issuer to check the Status
    /// List Token's `iss` against - neither the credential's own claims nor
    /// `credentialIssuer` name one - resolve's issuer binding check would
    /// have been skipped entirely (expectedIssuer: nil), accepting a validly
    /// signed token from ANY issuer, including one an attacker controls and
    /// self-signs, for a credential this wallet cannot even name the issuer
    /// of. No issuer to bind to must refuse, not skip the check.
    func testNoKnownIssuerRefusesRatherThanSkippingTheBindingCheck() async {
        let evaluator = CredentialStatusEvaluator(
            statusListClient: TokenStatusListClient(
                httpGet: { _, _ in
                    XCTFail("with no issuer to bind to, this must never reach the network")
                    return nil
                }
            ),
            now: { self.now }
        )
        // No "iss"/"issuer" claim, and no credentialIssuer argument either.
        let status = await evaluator.evaluate(
            claims: claims(#"{"status":{"status_list":{"idx":0,"uri":"https://x.example"}}}"#)
        )
        XCTAssertEqual(status, .unknown)
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

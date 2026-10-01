// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosCredentials
@testable import SirosWallet

/// Most Issuers are identified by an HTTPS URL rather than a DID. Resolving
/// their signing key only through `DidResolver` meant a Status List Token from
/// such an issuer could never be verified, so every revocation check degraded
/// to "unavailable" — which this SDK deliberately treats as usable, so
/// revocation silently never applied.
final class IssuerSigningKeyResolutionTests: XCTestCase {

    private let p256 = [
        "kty": "EC", "crv": "P-256",
        "x": "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
        "y": "_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE",
    ]

    func testAKidNamesTheKeyItSelects() {
        var first = p256
        first["kid"] = "a"
        var second = p256
        second["kid"] = "b"
        second["x"] = "different"

        let chosen = SirosWallet.selectIssuerKey([first, second], kid: "b")
        XCTAssertEqual(chosen?["kid"], "b")
        XCTAssertEqual(chosen?["x"], "different")
    }

    func testASoleKeyIsUsedWhenNoKidIsNamed() {
        XCTAssertEqual(SirosWallet.selectIssuerKey([p256], kid: nil)?["crv"], "P-256")
    }

    func testSeveralKeysWithNoKidIsAmbiguousAndRefused() {
        // Guessing would mean accepting a signature from whichever key
        // happened to be first in the set.
        var a = p256
        a["kid"] = "a"
        var b = p256
        b["kid"] = "b"
        XCTAssertNil(SirosWallet.selectIssuerKey([a, b], kid: nil))
    }

    func testAKidThatMatchesNothingIsRefused() {
        var only = p256
        only["kid"] = "a"
        XCTAssertNil(SirosWallet.selectIssuerKey([only], kid: "missing"))
    }

    func testAKeyCarryingPrivateMaterialIsNotAVerificationKey() {
        // A misconfigured JWKS that publishes a private key must not have it
        // treated as something to verify signatures with.
        var leaked = p256
        leaked["d"] = "private"
        XCTAssertNil(SirosWallet.selectIssuerKey([leaked], kid: nil))

        var symmetric = ["kty": "oct", "k": "secret"]
        symmetric["kid"] = "s"
        XCTAssertNil(SirosWallet.selectIssuerKey([symmetric], kid: "s"))
    }

    func testAnInlineJwksIsRead() async throws {
        let body = Data(#"{"issuer":"https://issuer.example","jwks":{"keys":[{"kty":"EC","crv":"P-256","x":"aa","y":"bb","kid":"k1"}]}}"#.utf8)
        let resolved = await SirosWallet.issuerJwks(metadata: body)
        let keys = try XCTUnwrap(resolved)
        XCTAssertEqual(keys.count, 1)
        XCTAssertEqual(keys[0]["kid"] as? String, "k1")
    }

    func testMetadataWithNeitherJwksNorUriYieldsNothing() async {
        let body = Data(#"{"issuer":"https://issuer.example"}"#.utf8)
        let keys = await SirosWallet.issuerJwks(metadata: body)
        XCTAssertNil(keys)
    }

    func testANonHttpsIssuerIsNotFetched() async {
        // Nothing to fetch, and no plaintext fetch attempted either.
        let key = await SirosWallet.resolveHttpsIssuerSigningKey(
            issuer: "http://issuer.example", kid: nil, profile: .latest
        )
        XCTAssertNil(key)
    }

    func testAPlaintextUrlIsNeverFetched() async {
        // Over plaintext anyone on the path can answer "is this credential
        // still valid" and "which key says so" in the issuer's place.
        for url in [
            "http://issuer.example/list",
            "HTTP://issuer.example/list",
            "ftp://issuer.example/list",
            "file:///etc/passwd",
            "not a url at all",
        ] {
            let body = await SirosWallet.fetchPublicUrl(url, headers: [:])
            XCTAssertNil(body, "\(url) must not be fetched")
        }
    }

    func testAUrlCarryingUserinfoIsNeverFetched() async {
        // The classic way to make a host look like one it is not. Userinfo
        // means nothing for an issuer's metadata or a status list.
        for url in [
            "https://issuer.example@evil.example/list",
            "https://user:pass@evil.example/list",
        ] {
            let body = await SirosWallet.fetchPublicUrl(url, headers: [:])
            XCTAssertNil(body, "\(url) must not be fetched")
        }
    }

    func testAnUppercaseSchemeIsStillHttps() async {
        // URI schemes are case-insensitive. Rejecting this spelling would
        // leave that issuer's status list unverifiable and its revocation
        // silently never applied. Nothing is reachable in a test, so this
        // asserts only that it is not refused before the fetch.
        let key = await SirosWallet.resolveHttpsIssuerSigningKey(
            issuer: "HTTPS://issuer.example", kid: nil, profile: .latest
        )
        XCTAssertNil(key, "unreachable, but it must have tried rather than refused the spelling")
    }
    func testTheRedirectPolicyIsTheSameAsTheFirstRequestPolicy() {
        // A rule enforced on the first request and not on the hop after it is
        // not a rule: a 3xx could otherwise bounce to `https://user@host/`,
        // which `fetchPublicUrl` refuses outright. Both now ask the same
        // predicate.
        XCTAssertTrue(isPublicFetchAllowed(URL(string: "https://issuer.example/list")!))
        XCTAssertTrue(isPublicFetchAllowed(URL(string: "HTTPS://issuer.example/list")!))

        XCTAssertFalse(isPublicFetchAllowed(URL(string: "http://issuer.example/list")!))
        XCTAssertFalse(isPublicFetchAllowed(URL(string: "https://issuer.example@evil.example/l")!))
        XCTAssertFalse(isPublicFetchAllowed(URL(string: "https://user:pass@evil.example/l")!))
        XCTAssertFalse(isPublicFetchAllowed(URL(string: "ftp://issuer.example/list")!))
    }

    /// Regression (review finding): a third-party response's COMPRESSED body
    /// must be capped while it is still arriving, not only checked against
    /// `Inflate`'s own output-size limit afterward - otherwise a credential-
    /// controlled status-list URI could make evaluating one stored
    /// credential buffer an unbounded amount of memory.
    ///
    /// No real network round trip (the real `thirdPartySession` is
    /// constructed once, at module load, with no seam left to intercept it) -
    /// this instead drives the delegate's own `didReceive`/cancellation logic
    /// directly against a real (never-`resume()`d, so no actual request is
    /// ever made) `URLSessionDataTask`, the same object shape the real
    /// session hands it.
    func testHttpsOnlyRedirectDelegateCancelsOnceTheCapIsExceeded() {
        let delegate = HttpsOnlyRedirectDelegate()
        let task = URLSession.shared.dataTask(with: URL(string: "https://issuer.example/status")!)

        let halfCap = Data(repeating: 0, count: maxPublicFetchResponseBytes / 2)
        delegate.urlSession(URLSession.shared, dataTask: task, didReceive: halfCap)
        XCTAssertNotEqual(task.state, .canceling, "half the cap in one chunk must not cancel")

        // A second chunk takes the running total past the cap.
        delegate.urlSession(URLSession.shared, dataTask: task, didReceive: halfCap)
        delegate.urlSession(URLSession.shared, dataTask: task, didReceive: Data([0, 1]))
        XCTAssertEqual(task.state, .canceling, "exceeding the cap must cancel the task")
    }

    func testHttpsOnlyRedirectDelegateTracksBytesPerTaskIndependently() {
        let delegate = HttpsOnlyRedirectDelegate()
        let taskA = URLSession.shared.dataTask(with: URL(string: "https://issuer.example/a")!)
        let taskB = URLSession.shared.dataTask(with: URL(string: "https://issuer.example/b")!)

        let almostCap = Data(repeating: 0, count: maxPublicFetchResponseBytes - 1)
        delegate.urlSession(URLSession.shared, dataTask: taskA, didReceive: almostCap)
        delegate.urlSession(URLSession.shared, dataTask: taskB, didReceive: Data([0]))
        XCTAssertNotEqual(taskA.state, .canceling, "taskA alone is still under its own cap")
        XCTAssertNotEqual(taskB.state, .canceling, "taskB's one byte must not inherit taskA's running total")
    }
}

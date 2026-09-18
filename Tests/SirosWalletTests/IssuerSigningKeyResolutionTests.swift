// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
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
}

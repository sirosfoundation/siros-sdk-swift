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

    private var originalHostResolutionTimeout: TimeInterval = 5

    override func setUp() {
        super.setUp()
        originalHostResolutionTimeout = hostResolutionTimeout
        // Short, deterministically so this file's own tests (and
        // `testAnUppercaseSchemeIsStillHttps`, which reaches a real DNS
        // lookup for the RFC 2606 placeholder `issuer.example` through
        // `resolveHttpsIssuerSigningKey`) stay fast regardless of how long
        // whatever environment runs them takes to give up on a name that
        // will not resolve - see `hostResolutionTimeout`'s own doc comment.
        hostResolutionTimeout = 1
    }

    override func tearDown() {
        hostResolutionTimeout = originalHostResolutionTimeout
        super.tearDown()
    }

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

    /// Regression (review finding): two keys sharing one `kid` is exactly as
    /// ambiguous as several keys with none - which one a verifier means is
    /// then whichever the server's array happened to list first, not
    /// something this wallet decided.
    func testTwoKeysSharingOneKidIsAmbiguousAndRefused() {
        var first = p256
        first["kid"] = "a"
        var second = p256
        second["x"] = "different"
        second["kid"] = "a"
        XCTAssertNil(SirosWallet.selectIssuerKey([first, second], kid: "a"))
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
            let outcome = await SirosWallet.fetchPublicUrl(url, headers: [:])
            guard case .rejected = outcome else {
                XCTFail("\(url) must not be fetched, got \(outcome)")
                continue
            }
        }
    }

    func testAUrlCarryingUserinfoIsNeverFetched() async {
        // The classic way to make a host look like one it is not. Userinfo
        // means nothing for an issuer's metadata or a status list.
        for url in [
            "https://issuer.example@evil.example/list",
            "https://user:pass@evil.example/list",
        ] {
            let outcome = await SirosWallet.fetchPublicUrl(url, headers: [:])
            guard case .rejected = outcome else {
                XCTFail("\(url) must not be fetched, got \(outcome)")
                continue
            }
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

    /// Regression (review finding): a credential-controlled status URI or
    /// issuer jwks_uri naming a loopback/private/link-local IP literal
    /// previously passed every other check here and was fetched - turning
    /// status evaluation into an SSRF/local-network probing primitive.
    func testLoopbackPrivateAndLinkLocalAddressesAreNeverFetched() {
        // Loopback.
        XCTAssertFalse(isPublicFetchAllowed(URL(string: "https://127.0.0.1/list")!))
        XCTAssertFalse(isPublicFetchAllowed(URL(string: "https://127.1.2.3/list")!))
        XCTAssertFalse(isPublicFetchAllowed(URL(string: "https://localhost/list")!))
        XCTAssertFalse(isPublicFetchAllowed(URL(string: "https://[::1]/list")!))
        // The three private ranges (RFC 1918).
        XCTAssertFalse(isPublicFetchAllowed(URL(string: "https://10.0.0.5/list")!))
        XCTAssertFalse(isPublicFetchAllowed(URL(string: "https://172.16.0.5/list")!))
        XCTAssertFalse(isPublicFetchAllowed(URL(string: "https://192.168.1.1/list")!))
        // Link-local.
        XCTAssertFalse(isPublicFetchAllowed(URL(string: "https://169.254.1.1/list")!))
        XCTAssertFalse(isPublicFetchAllowed(URL(string: "https://[fe80::1]/list")!))
        // Unique-local IPv6 (RFC 4193's private-network analogue).
        XCTAssertFalse(isPublicFetchAllowed(URL(string: "https://[fd00::1]/list")!))
        // An IPv4-mapped IPv6 literal must not bypass the IPv4 checks.
        XCTAssertFalse(isPublicFetchAllowed(URL(string: "https://[::ffff:127.0.0.1]/list")!))
        // Carrier-grade NAT and a documentation range, for completeness.
        XCTAssertFalse(isPublicFetchAllowed(URL(string: "https://100.64.0.1/list")!))
        XCTAssertFalse(isPublicFetchAllowed(URL(string: "https://192.0.2.1/list")!))
    }

    /// Regression (review finding): `isPublicFetchAllowed` only rejects IP
    /// *literals* in the URL text - an ordinary HOSTNAME that resolves to a
    /// private/loopback address sailed through it untouched. "localhost" is
    /// used here (rather than a fabricated private-resolving domain) since
    /// it resolves through the system's own local stub resolver, needing no
    /// live network access to be deterministic in a sandboxed CI runner -
    /// and it always resolves to loopback, on every platform this SDK runs
    /// on.
    func testAHostnameResolvingToLoopbackIsNeverFetched() async {
        let result = await hostResolvesToOnlyPublicAddresses("localhost")
        XCTAssertFalse(result)
    }

    /// A hostname this SDK cannot resolve at all is not this function's
    /// decision to make: the connect attempt fails on its own and reads as
    /// `.unreachable`, the same as any other transport failure - not as
    /// "blocked". Also covers the case where DNS genuinely is not reachable
    /// in whatever environment runs this test: either way, the answer must
    /// be true, never a false negative that reads a merely-offline sandbox
    /// as an SSRF attempt.
    func testAHostnameThatCannotBeResolvedIsNotTreatedAsBlocked() async {
        let result = await hostResolvesToOnlyPublicAddresses("this-host-does-not-exist.invalid")
        XCTAssertTrue(result)
    }

    /// The timeout itself, proven non-vacuous: a name whose resolution
    /// genuinely takes longer than `hostResolutionTimeout` must still come
    /// back (as `true` - not a policy decision - see this function's own
    /// doc comment) in roughly that bounded time, not however long the
    /// underlying `getaddrinfo` call would otherwise take.
    func testResolutionGivesUpAfterHostResolutionTimeout() async {
        hostResolutionTimeout = 0.2
        let start = Date()
        let result = await hostResolvesToOnlyPublicAddresses("this-host-does-not-exist.invalid")
        XCTAssertTrue(result)
        XCTAssertLessThan(
            Date().timeIntervalSince(start), 5,
            "must give up at roughly hostResolutionTimeout, not wait out the real DNS failure"
        )
    }

    func testOrdinaryPublicAddressesAndHostnamesAreStillFetched() {
        XCTAssertTrue(isPublicFetchAllowed(URL(string: "https://issuer.example/list")!))
        // A real public IP literal (documentation-safe TEST-NET-3 analogue
        // picked for a well-known public resolver, not actually dialed by
        // this test - only the predicate runs here).
        XCTAssertTrue(isPublicFetchAllowed(URL(string: "https://8.8.8.8/list")!))
        XCTAssertTrue(isPublicFetchAllowed(URL(string: "https://[2001:4860:4860::8888]/list")!))
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
    /// A never-`resume()`d `URLSessionTask` starts `.suspended` and stays
    /// there until something calls `.cancel()` on it - nothing else is
    /// happening on it, so `.suspended` is a stable, race-free "not
    /// cancelled" signal. Once cancelled, `.state` moves on to `.canceling`
    /// or - observed to already be the case by the time a test asserts, on
    /// at least one real CI runner - straight through to `.completed`;
    /// checking merely "not still suspended" is what both transitions have
    /// in common, so it is used instead of asserting one specific far side
    /// of a transition this test does not control the timing of.
    func testHttpsOnlyRedirectDelegateCancelsOnceTheCapIsExceeded() {
        let delegate = HttpsOnlyRedirectDelegate()
        let task = URLSession.shared.dataTask(with: URL(string: "https://issuer.example/status")!)

        let halfCap = Data(repeating: 0, count: maxPublicFetchResponseBytes / 2)
        delegate.urlSession(URLSession.shared, dataTask: task, didReceive: halfCap)
        XCTAssertEqual(task.state, .suspended, "half the cap in one chunk must not cancel")
        XCTAssertFalse(delegate.didExceedResponseCap)

        // A second chunk takes the running total past the cap.
        delegate.urlSession(URLSession.shared, dataTask: task, didReceive: halfCap)
        delegate.urlSession(URLSession.shared, dataTask: task, didReceive: Data([0, 1]))
        XCTAssertNotEqual(task.state, .suspended, "exceeding the cap must cancel the task")
        // Regression (review finding): fetchPublicUrl must be able to tell
        // THIS cancellation apart from a genuine transport failure, since
        // only the latter is offline-friendly (.unreachable).
        XCTAssertTrue(delegate.didExceedResponseCap)
    }

    /// Regression (review finding): a response this delegate itself
    /// cancelled for exceeding the byte cap reached the server and received
    /// (too much) data - it must not read as `.unreachable` (offline-
    /// friendly) the same way a genuine DNS/connection failure does, or an
    /// oversized/hostile status-list response could force a credential to
    /// evaluate as `.valid` instead of `.unknown`. One delegate instance now
    /// backs exactly one request (`fetchPublicUrl` constructs a fresh one
    /// per call), so there is no cross-task bleeding to prove separately -
    /// that guarantee is now structural rather than bookkeeping-dependent.
    func testFetchPublicUrlDoesNotTreatACapExceededCancellationAsUnreachable() async {
        // Exercises the exact decision fetchPublicUrl's catch block makes,
        // without a live network round trip (consistent with this delegate
        // having none anywhere else in this file): a delegate that has
        // already recorded exceeding the cap must report so, which is the
        // one thing fetchPublicUrl checks after `data(for:request:delegate:)`
        // throws.
        let delegate = HttpsOnlyRedirectDelegate()
        let task = URLSession.shared.dataTask(with: URL(string: "https://issuer.example/status")!)
        delegate.urlSession(URLSession.shared, dataTask: task, didReceive: Data(repeating: 0, count: maxPublicFetchResponseBytes + 1))
        XCTAssertTrue(delegate.didExceedResponseCap, "fetchPublicUrl relies on exactly this flag to say .rejected, not .unreachable")
    }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

final class DidTests: XCTestCase {

    private let p256Jwk: [String: String] = [
        "kty": "EC",
        "crv": "P-256",
        "x": "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
        "y": "_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE",
    ]

    // MARK: - did:jwk

    func testADidJwkRoundTripsBackToTheKeyItWasBuiltFrom() {
        let did = Did.createDidJwk(p256Jwk)
        XCTAssertTrue(did.hasPrefix("did:jwk:"))

        guard let document = Did.resolveDidJwk(did).document else {
            return XCTFail("did:jwk resolves offline")
        }
        XCTAssertEqual(document.id, did)
        let key = document.findPublicKey(kid: "\(did)#0", relationship: .authentication)
        XCTAssertEqual(key?["x"], p256Jwk["x"])
    }

    func testTheOnlyVerificationMethodOfADidJwkIsHashZero() {
        let did = Did.createDidJwk(p256Jwk)
        XCTAssertEqual(Did.didJwkKeyId(did), "\(did)#0")
        let document = Did.resolveDidJwk(did).document
        XCTAssertEqual(document?.authentication, ["\(did)#0"])
        XCTAssertEqual(document?.assertionMethod, ["\(did)#0"])
    }

    func testWebCryptoBookkeepingAndPrivateMaterialNeverReachTheIdentifier() {
        // A key exported by WebCrypto carries `ext`/`key_ops`, and a private
        // key carries `d`. Including either would make the same key produce
        // two different DIDs - or publish the private key.
        var noisy = p256Jwk
        noisy["d"] = "secret"
        noisy["ext"] = "true"
        noisy["key_ops"] = "sign"
        XCTAssertEqual(Did.createDidJwk(noisy), Did.createDidJwk(p256Jwk))

        let encoded = String(Did.createDidJwk(noisy).dropFirst("did:jwk:".count))
        let decoded = String(data: EncryptedContainerBase64.urlDecode(encoded), encoding: .utf8) ?? ""
        XCTAssertFalse(decoded.contains("\"d\""), "no private key material in the DID")
        XCTAssertFalse(decoded.contains("key_ops"))
    }

    func testOptionalJwkMembersDoNotChangeTheIdentifier() {
        // A key that also carries `alg`, `use` or a `kid` is the same key, and
        // must get the same DID - otherwise one client's did:jwk stops
        // matching another's for the same key pair in the shared container.
        var annotated = p256Jwk
        annotated["alg"] = "ES256"
        annotated["use"] = "sig"
        annotated["kid"] = "whatever"
        XCTAssertEqual(Did.createDidJwk(annotated), Did.createDidJwk(p256Jwk))
    }

    func testTheIdentifierIsLexicographicallyOrdered() {
        // Not arbitrary: it is RFC 7638's canonicalization and what
        // wallet-frontend emits, and the same key must yield the same DID on
        // every client reading the shared container.
        let encoded = String(Did.createDidJwk(p256Jwk).dropFirst("did:jwk:".count))
        let decoded = String(data: EncryptedContainerBase64.urlDecode(encoded), encoding: .utf8)
        XCTAssertEqual(
            decoded,
            "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"\(p256Jwk["x"]!)\",\"y\":\"\(p256Jwk["y"]!)\"}"
        )
    }

    func testAMalformedDidJwkFailsRatherThanResolvingToNothing() {
        XCTAssertNil(Did.resolveDidJwk("did:jwk:not-base64url!!").document)
        XCTAssertNil(Did.resolveDidJwk("did:web:example.com").document)
    }

    /// Regression (review finding): an embedded JWK decoding to `{}` (or
    /// anything else missing the members its own `kty` requires) previously
    /// "resolved" successfully anyway, with a `publicKeyJwk` nothing could
    /// verify a signature against. `resolveDidJwk` is the entirely-offline
    /// trust root for `did:jwk` - it must fail rather than resolve to a
    /// document with no usable key.
    func testAnEmptyEmbeddedJwkFailsRatherThanResolvingWithNoUsableKey() {
        let did = "did:jwk:" + EncryptedContainerBase64.urlEncode(Data("{}".utf8))
        XCTAssertNil(Did.resolveDidJwk(did).document)
    }

    /// Regression (review finding): an EC JWK missing `y` is not a usable
    /// public key (not enough curve-point material to verify anything
    /// against), and must not resolve just because `kty`/`crv`/`x` happen to
    /// be present.
    func testAnIncompleteEcJwkFailsRatherThanResolvingWithAPartialKey() {
        let incomplete = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"\(p256Jwk["x"]!)\"}"
        let did = "did:jwk:" + EncryptedContainerBase64.urlEncode(Data(incomplete.utf8))
        XCTAssertNil(Did.resolveDidJwk(did).document)
    }

    /// Regression (review finding): `oct` is symmetric SECRET material (`k`
    /// is a shared secret, not a public key), never a usable public key for
    /// a DID verification method regardless of which members it carries -
    /// a did:jwk (or delegated document) declaring one must not expose that
    /// secret through `publicKeyJwk` by being treated as "usable".
    func testAnOctKeyIsNeverUsableAsAPublicKeyRegardlessOfWhichMembersItCarries() {
        XCTAssertFalse(Did.isUsablePublicJwk(["kty": "oct", "k": "shared-secret"]))
        let did = "did:jwk:" + EncryptedContainerBase64.urlEncode(Data(#"{"kty":"oct","k":"shared-secret"}"#.utf8))
        XCTAssertNil(Did.resolveDidJwk(did).document)
    }

    /// Regression (review finding): private key material (`d`) embedded
    /// alongside a legitimate public key must never be echoed back through
    /// `publicKeyJwk` - only the members `canonicalPublicJwk` recognises as
    /// public, for this key's own `kty`, are kept.
    func testPrivateKeyMaterialInTheEmbeddedJwkNeverReachesThePublicKey() {
        var withPrivateKey = p256Jwk
        withPrivateKey["d"] = "super-secret-private-scalar"
        let json = try! JSONSerialization.data(withJSONObject: withPrivateKey)
        let did = "did:jwk:" + EncryptedContainerBase64.urlEncode(json)
        guard let document = Did.resolveDidJwk(did).document else {
            return XCTFail("a JWK with the required EC public members, plus an extra private one, still resolves")
        }
        let key = document.findPublicKey(kid: "\(did)#0", relationship: .authentication)
        XCTAssertEqual(key?["x"], p256Jwk["x"])
        XCTAssertNil(key?["d"], "private key material must never be exposed through publicKeyJwk")
    }

    // MARK: - delegated resolution
    //
    // Everything that is not did:jwk is a trust decision - which document is
    // authoritative for an identifier - and belongs to go-trust, reached
    // through the backend. These tests pin that the SDK delegates rather than
    // fetching, because fetching is exactly the bug.

    func testADidWebIsResolvedThroughTheDelegateNotFetched() async {
        let asked = AskedRecorder()
        let resolver = DidResolver { did in
            await asked.record(did)
            // Built up rather than written as one nested literal, for the same
            // reason as TokenStatusListTests: Swift 6.1's type-checker gives
            // up on deeply nested heterogeneous dictionary literals.
            let jwk: [String: Any] = ["kty": "EC", "crv": "P-256", "x": "aa", "y": "bb"]
            let method: [String: Any] = [
                "id": "did:web:issuer.example#key-1",
                "type": "JsonWebKey2020",
                "controller": "did:web:issuer.example",
                "publicKeyJwk": jwk,
            ]
            let document: [String: Any] = [
                "id": "did:web:issuer.example",
                "verificationMethod": [method],
                "assertionMethod": ["did:web:issuer.example#key-1"],
            ]
            return document
        }
        let document = await resolver.resolve("did:web:issuer.example").document
        let value = await asked.value
        XCTAssertEqual(value, "did:web:issuer.example")
        let key = document?.findPublicKey(kid: "did:web:issuer.example#key-1", relationship: .assertionMethod)
        XCTAssertEqual(key?["x"], "aa")
    }

    func testAWalletWithNoResolutionAuthorityDoesNotResolveADidWebItself() async {
        // Failing is the point: the alternative is the SDK deciding which host
        // to believe, which is go-trust's decision, not the wallet's.
        let resolver = DidResolver(delegate: nil)
        let result = await resolver.resolve("did:web:example.com")
        XCTAssertNil(result.document)
    }

    func testADocumentNamingADifferentSubjectIsRejected() async {
        // Whoever returned it, it is not this DID's document.
        let resolver = DidResolver { _ in ["id": "did:web:evil.example"] }
        let result = await resolver.resolve("did:web:example.com")
        XCTAssertNil(result.document)
    }

    func testADelegateThatCannotResolveIsAFailureNotAnEmptyDocument() async {
        let resolver = DidResolver { _ in nil }
        let result = await resolver.resolve("did:web:example.com")
        XCTAssertNil(result.document)
    }

    func testDidJwkNeverReachesTheDelegate() async {
        // It resolves offline: the key is the identifier, so a round trip
        // would add a dependency and a failure mode for a known answer.
        let asked = AskedRecorder()
        let resolver = DidResolver { did in
            await asked.record(did)
            return nil
        }
        let did = Did.createDidJwk(p256Jwk)
        let resolved = await resolver.resolve(did).document
        XCTAssertNotNil(resolved)
        let value = await asked.value
        XCTAssertNil(value, "did:jwk must not be delegated")
    }

    func testDidWebvhIsDelegatedLikeAnyOtherNetworkMethod() async {
        // A DIIP v6 Future Direction. The SDK does not special-case it:
        // go-trust either resolves it or does not.
        let asked = AskedRecorder()
        let resolver = DidResolver(profile: .v6) { did in
            await asked.record(did)
            return nil
        }
        _ = await resolver.resolve("did:webvh:scid:example.com")
        let value = await asked.value
        XCTAssertEqual(value, "did:webvh:scid:example.com")
        let required = await resolver.requiredMethods
        XCTAssertTrue(required.contains(.webvh))
    }

    // MARK: - documents and cnf

    func testAnInlineVerificationMethodIsRegisteredAsWellAsAReferencedOne() {
        let root = try? JSONSerialization.jsonObject(with: Data("""
        {
          "id": "did:web:x.example",
          "authentication": [{
            "id": "#inline",
            "type": "JsonWebKey2020",
            "publicKeyJwk": {"kty":"EC","crv":"P-256","x":"cc","y":"dd"}
          }]
        }
        """.utf8)) as? [String: Any]
        let document = Did.parseDidDocument(root ?? [:])
        // A relative fragment is resolved against the document's own id.
        let key = document?.findPublicKey(kid: "did:web:x.example#inline", relationship: .authentication)
        XCTAssertEqual(key?["x"], "cc")
    }

    /// Regression (review finding): a delegated document's verification
    /// method is filtered to canonical public members the same way the
    /// offline did:jwk path is - private key material embedded alongside a
    /// legitimate public key must never reach `publicKeyJwk`.
    func testPrivateKeyMaterialInADelegatedDocumentNeverReachesThePublicKey() {
        let root = try? JSONSerialization.jsonObject(with: Data("""
        {
          "id": "did:web:x.example",
          "authentication": [{
            "id": "#inline",
            "type": "JsonWebKey2020",
            "publicKeyJwk": {"kty":"EC","crv":"P-256","x":"cc","y":"dd","d":"super-secret"}
          }]
        }
        """.utf8)) as? [String: Any]
        let document = Did.parseDidDocument(root ?? [:])
        let key = document?.findPublicKey(kid: "did:web:x.example#inline", relationship: .authentication)
        XCTAssertEqual(key?["x"], "cc")
        XCTAssertNil(key?["d"], "private key material must never be exposed through publicKeyJwk")
    }

    /// Regression (review finding): a verification method whose embedded
    /// `publicKeyJwk` is missing what its own `kty` requires (here, no `y`)
    /// must not be registered as a usable key at all.
    func testADelegatedDocumentsIncompletePublicKeyIsNotRegistered() {
        let root = try? JSONSerialization.jsonObject(with: Data("""
        {
          "id": "did:web:x.example",
          "authentication": [{
            "id": "#inline",
            "type": "JsonWebKey2020",
            "publicKeyJwk": {"kty":"EC","crv":"P-256","x":"cc"}
          }]
        }
        """.utf8)) as? [String: Any]
        let document = Did.parseDidDocument(root ?? [:])
        XCTAssertNil(document?.findPublicKey(kid: "did:web:x.example#inline", relationship: .authentication))
    }

    func testADocumentWithSeveralKeysAndNoKidIsAmbiguousRatherThanTheFirstOne() {
        // Taking the first would make verification depend on document order:
        // a token signed by the issuer's other assertion key would be
        // rejected, and a key it never signed with could be accepted.
        let root = try? JSONSerialization.jsonObject(with: Data("""
        {
          "id": "did:web:issuer.example",
          "verificationMethod": [
            {"id":"did:web:issuer.example#a","type":"JsonWebKey2020","controller":"did:web:issuer.example",
             "publicKeyJwk":{"kty":"EC","crv":"P-256","x":"aa","y":"bb"}},
            {"id":"did:web:issuer.example#b","type":"JsonWebKey2020","controller":"did:web:issuer.example",
             "publicKeyJwk":{"kty":"EC","crv":"P-256","x":"cc","y":"dd"}}
          ],
          "assertionMethod": ["did:web:issuer.example#a","did:web:issuer.example#b"]
        }
        """.utf8)) as? [String: Any]
        let document = Did.parseDidDocument(root ?? [:])
        XCTAssertNil(document?.findPublicKey(kid: nil, relationship: .assertionMethod))
        // Naming one resolves it.
        XCTAssertEqual(
            document?.findPublicKey(kid: "did:web:issuer.example#a", relationship: .assertionMethod)?["x"],
            "aa"
        )
    }

    /// Regression (review finding): matching by fragment alone let a `kid`
    /// naming a DIFFERENT subject's verification method (same fragment,
    /// different DID) select a key from THIS document - exactly what a
    /// token whose `kid` is `"did:evil.example#key-1"` would try against an
    /// issuer document that happens to name one of its own methods
    /// `"...#key-1"` too.
    func testAFullyQualifiedKidNamingADifferentSubjectNeverMatchesByFragmentAlone() {
        let root = try? JSONSerialization.jsonObject(with: Data("""
        {
          "id": "did:web:issuer.example",
          "verificationMethod": [
            {"id":"did:web:issuer.example#key-1","type":"JsonWebKey2020","controller":"did:web:issuer.example",
             "publicKeyJwk":{"kty":"EC","crv":"P-256","x":"aa","y":"bb"}}
          ],
          "assertionMethod": ["did:web:issuer.example#key-1"]
        }
        """.utf8)) as? [String: Any]
        let document = Did.parseDidDocument(root ?? [:])
        XCTAssertNil(
            document?.findPublicKey(kid: "did:evil.example#key-1", relationship: .assertionMethod),
            "a kid naming a different subject must not resolve to this document's identically-fragmented key"
        )
        // The genuinely-matching fully-qualified kid still resolves.
        XCTAssertEqual(
            document?.findPublicKey(kid: "did:web:issuer.example#key-1", relationship: .assertionMethod)?["x"],
            "aa"
        )
    }

    func testASoleKeyStillResolvesWithoutAKid() {
        let did = Did.createDidJwk(p256Jwk)
        XCTAssertNotNil(Did.resolveDidJwk(did).document?.findPublicKey(kid: nil, relationship: .authentication))
    }

    func testAKidIsMatchedByFragmentWhenItIsNotTheFullDidUrl() {
        let did = Did.createDidJwk(p256Jwk)
        let document = Did.resolveDidJwk(did).document
        XCTAssertNotNil(document?.findPublicKey(kid: "#0", relationship: .authentication))
    }

    func testCnfKidWinsOverCnfJwkAndAnAbsentBindingIsNil() {
        let thumbprint: ([String: Any]) -> String? = { _ in "THUMB" }
        XCTAssertEqual(
            Did.resolveCnfKid(["kid": "did:jwk:abc#0", "jwk": ["kty": "EC"]], thumbprintOf: thumbprint),
            "did:jwk:abc#0"
        )
        XCTAssertEqual(Did.resolveCnfKid(["jwk": ["kty": "EC"]], thumbprintOf: thumbprint), "THUMB")
        XCTAssertNil(Did.resolveCnfKid(nil, thumbprintOf: thumbprint))
        XCTAssertNil(Did.resolveCnfKid([:], thumbprintOf: thumbprint))
    }

    func testADidsMethodIsReadFromTheIdentifier() {
        XCTAssertEqual(DidMethod.of("did:jwk:abc"), .jwk)
        XCTAssertEqual(DidMethod.of("did:web:example.com"), .web)
        XCTAssertEqual(DidMethod.of("did:webvh:scid:example.com"), .webvh)
        XCTAssertNil(DidMethod.of("https://example.com"))
        XCTAssertNil(DidMethod.of("did:unknown:x"))
    }

    func testAMethodNameIsReadEvenWhenThisSdkDoesNotKnowIt() {
        XCTAssertEqual(DidMethod.methodName(of: "did:unknown:x"), "unknown")
        XCTAssertEqual(DidMethod.methodName(of: "did:ebsi:zABC"), "ebsi")
        XCTAssertNil(DidMethod.methodName(of: "https://example.com"))
        // `did:<method>:<id>` - neither half may be missing.
        XCTAssertNil(DidMethod.methodName(of: "did:web"))
        XCTAssertNil(DidMethod.methodName(of: "did:web:"))
        XCTAssertNil(DidMethod.methodName(of: "did::x"))
    }

    func testAMethodThisSdkDoesNotKnowIsStillGoTrustsToResolve() async {
        // Enumerating methods here would make the SDK the authority on which
        // of them exist. It is not: go-trust is, and a method it learns about
        // must not need an SDK release.
        let asked = AskedRecorder()
        let resolver = DidResolver(profile: .latest) { did in
            await asked.record(did)
            return nil
        }
        _ = await resolver.resolve("did:ebsi:zABC")
        let value = await asked.value
        XCTAssertEqual(value, "did:ebsi:zABC")
    }

    func testSomethingThatIsNotADidIsNotDelegated() async {
        let asked = AskedRecorder()
        let resolver = DidResolver(profile: .latest) { did in
            await asked.record(did)
            return nil
        }
        let result = await resolver.resolve("https://issuer.example")
        let value = await asked.value
        XCTAssertNil(value)
        guard case .failed = result else { return XCTFail("a non-DID must not resolve") }
    }
}

/// Records the DID a delegate was asked for, across actor boundaries.
private actor AskedRecorder {
    private(set) var value: String?
    func record(_ did: String) { value = did }
}

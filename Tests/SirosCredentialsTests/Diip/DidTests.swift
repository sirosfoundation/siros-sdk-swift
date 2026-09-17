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

    // MARK: - did:web

    func testABareDidWebResolvesToTheWellKnownPath() {
        XCTAssertEqual(
            Did.didWebToUrl("did:web:example.com"),
            "https://example.com/.well-known/did.json"
        )
    }

    func testPathSegmentsOfADidWebBecomeUrlPathSegments() {
        XCTAssertEqual(
            Did.didWebToUrl("did:web:example.com:issuers:1"),
            "https://example.com/issuers/1/did.json"
        )
    }

    func testAPercentEncodedPortIsDecodedBackIntoTheHost() {
        XCTAssertEqual(
            Did.didWebToUrl("did:web:example.com%3A8443"),
            "https://example.com:8443/.well-known/did.json"
        )
    }

    func testADocumentServedForADifferentSubjectIsRejected() async {
        // Otherwise any domain could serve a document for any DID.
        let resolver = DidResolver { _ in Data(#"{"id":"did:web:evil.example"}"#.utf8) }
        let result = await resolver.resolve("did:web:example.com")
        XCTAssertNil(result.document)
    }

    func testADidWebDocumentResolvesItsAssertionMethodKey() async {
        let body = """
        {
          "id": "did:web:issuer.example",
          "verificationMethod": [{
            "id": "did:web:issuer.example#key-1",
            "type": "JsonWebKey2020",
            "controller": "did:web:issuer.example",
            "publicKeyJwk": {"kty":"EC","crv":"P-256","x":"aa","y":"bb"}
          }],
          "assertionMethod": ["did:web:issuer.example#key-1"]
        }
        """
        let resolver = DidResolver { _ in Data(body.utf8) }
        let document = await resolver.resolve("did:web:issuer.example").document
        let key = document?.findPublicKey(kid: "did:web:issuer.example#key-1", relationship: .assertionMethod)
        XCTAssertEqual(key?["x"], "aa")
    }

    func testAnUnreachableDidWebIsAFailureNotAnEmptyDocument() async {
        let resolver = DidResolver { _ in nil }
        let result = await resolver.resolve("did:web:example.com")
        XCTAssertNil(result.document)
    }

    // MARK: - did:webvh

    func testDidWebvhFailsClosedRatherThanServingAnUnverifiedDocument() async {
        // Its whole value over did:web is the verifiable log; a resolver that
        // skipped the proof chain would offer did:web trust while looking
        // like more.
        let resolver = DidResolver(profile: .v6) { _ in Data("{}".utf8) }
        let result = await resolver.resolve("did:webvh:scid:example.com")
        XCTAssertNil(result.document)
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
}

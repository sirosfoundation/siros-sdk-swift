// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@preconcurrency import SwiftCBOR
@testable import SirosCredentials
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// The SDK's half of the shared DCQL engine.
///
/// The engine itself is a native library in an iOS-only XCFramework, so the one
/// function that *calls* it is `#if os(iOS)` and cannot run here. Its matching
/// behaviour is covered in `siros-dc-matcher` against the specification's own
/// examples, which is the point of sharing it.
///
/// What is left is the translation layer, and it is deliberately
/// platform-neutral so that it can be tested where the engine cannot run:
/// ``SharedDcqlMatcher/matchingClaims(_:)`` (which claims the engine is told
/// about), ``SharedDcqlMatcher/splitClaimKey(format:key:)`` (mdoc path
/// splitting), and — in `CredentialMatcherNarrowingTests` below —
/// `CredentialMatcher.narrow(parsed:with:)`, which is where the §6.4 rule
/// lives. Those three are where a mistake silently removes a credential from
/// what a user is offered.
final class SharedDcqlMatcherTests: XCTestCase {

    /// ISO namespaces keep their dots; only the element identifier splits off.
    ///
    /// Splitting on the *first* dot yields namespace `org`, which matches
    /// nothing while looking entirely reasonable in a debugger.
    func testMdocClaimKeysSplitOnTheLastDot() {
        XCTAssertEqual(
            SharedDcqlMatcher.splitClaimKey(format: "mso_mdoc", key: "org.iso.18013.5.1.family_name"),
            ["org.iso.18013.5.1", "family_name"]
        )
    }

    /// JSON-based credentials keep the key whole - theirs are not dotted paths,
    /// so a dot in one is part of the name.
    func testNonMdocKeysAreNotSplit() {
        XCTAssertEqual(
            SharedDcqlMatcher.splitClaimKey(format: "dc+sd-jwt", key: "given_name"),
            ["given_name"]
        )
        XCTAssertEqual(
            SharedDcqlMatcher.splitClaimKey(format: "dc+sd-jwt", key: "address.locality"),
            ["address.locality"]
        )
    }

    /// An mdoc key with no dot is an element with no namespace, not an error.
    func testAnMdocKeyWithoutADotStaysWhole() {
        XCTAssertEqual(
            SharedDcqlMatcher.splitClaimKey(format: "mso_mdoc", key: "family_name"),
            ["family_name"]
        )
    }

    /// Format comparison is case-insensitive, matching the Kotlin SDK.
    func testFormatMatchIsCaseInsensitive() {
        XCTAssertEqual(
            SharedDcqlMatcher.splitClaimKey(format: "MSO_MDOC", key: "org.iso.18013.5.1.age_over_18"),
            ["org.iso.18013.5.1", "age_over_18"]
        )
    }

    /// `satisfiable` is carried, not derived.
    ///
    /// A request can ask for two credentials and get one: the answerable query
    /// has candidates while the request as a whole must offer nothing (§6.4).
    /// Any caller reconstructing the flag from the map alone gets exactly that
    /// case wrong, which is why ``SharedDcqlMatcher/Outcome`` holds both.
    func testAnOutcomeCanBeUnsatisfiableWithCandidatesPresent() {
        let outcome = SharedDcqlMatcher.Outcome(
            satisfiable: false,
            candidatesByQuery: ["answerable": [1], "unanswerable": []]
        )
        XCTAssertFalse(outcome.satisfiable)
        XCTAssertEqual(outcome.candidatesByQuery["answerable"], [1])
    }

    // MARK: - Claims the engine is given

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
        let disclosureJson = try! JSONSerialization.data(
            withJSONObject: ["c2FsdA", hidden.0, hidden.1]
        )
        let disclosure = b64url(disclosureJson)

        var payload = plain
        payload["_sd"] = [digest(of: disclosure)]
        payload["_sd_alg"] = "sha-256"
        let body = b64url(try! JSONSerialization.data(withJSONObject: payload))
        return "eyJhbGciOiJFUzI1NiJ9.\(body).sig~\(disclosure)~"
    }

    private func sdJwtCredential(raw: String) -> StoredCredential {
        StoredCredential(id: 1, format: "dc+sd-jwt", raw: raw, metadata: nil, batchId: 1, instanceId: 0)
    }

    /// The regression this extractor exists for.
    ///
    /// `CredentialUtils.extractClaims` reads only the JWT body, so a
    /// selectively disclosed claim is simply absent. The engine would then
    /// apply §6.4.1 and decline a credential that can disclose exactly what the
    /// verifier asked for - a credential silently missing from the picker.
    func testASelectivelyDisclosedClaimIsFound() {
        let credential = sdJwtCredential(raw: sdJwt(plain: ["vct": "urn:eu.europa.ec.eudi:pid:1"],
                                                    hidden: ("given_name", "Erika")))

        let display = CredentialUtils.extractClaims(credential).map(\.key)
        XCTAssertFalse(display.contains("given_name"), "precondition: the display extractor cannot see it")

        let matching = SharedDcqlMatcher.matchingClaims(credential)
        XCTAssertTrue(matching.contains { $0.path == ["given_name"] && $0.value == "Erika" })
    }

    /// A claim that was never hidden is still there - resolving disclosures
    /// must not replace the payload, only add to it.
    func testPlainClaimsSurviveDisclosureResolution() {
        let credential = sdJwtCredential(raw: sdJwt(plain: ["vct": "x", "iss": "https://issuer.example"],
                                                    hidden: ("given_name", "Erika")))
        let paths = SharedDcqlMatcher.matchingClaims(credential).map(\.path)
        XCTAssertTrue(paths.contains(["iss"]))
        XCTAssertTrue(paths.contains(["given_name"]))
    }

    /// Nested claims get real DCQL paths, not one dotted string.
    ///
    /// `["address", "locality"]` is what a claims path pointer looks like
    /// (OpenID4VP 1.0 §7); `["address.locality"]` matches nothing.
    func testNestedClaimsBecomePathsNotDottedKeys() {
        let credential = sdJwtCredential(
            raw: sdJwt(plain: ["address": ["locality": "Stockholm"]], hidden: ("given_name", "Erika"))
        )
        let paths = SharedDcqlMatcher.matchingClaims(credential).map(\.path)
        XCTAssertTrue(paths.contains(["address", "locality"]))
        XCTAssertTrue(paths.contains(["address"]), "an object is addressable too")
        XCTAssertFalse(paths.contains(["address.locality"]))
    }

    /// A digest with no matching disclosure invents nothing.
    ///
    /// The holder was not given that claim. Offering the credential for it
    /// would be the opposite error to the one above, and just as wrong.
    func testAnUndisclosedDigestDoesNotBecomeAClaim() {
        var payload: [String: Any] = ["vct": "x"]
        payload["_sd"] = ["ZG9lcy1ub3QtcmVzb2x2ZQ"]
        let body = b64url(try! JSONSerialization.data(withJSONObject: payload))
        let credential = sdJwtCredential(raw: "eyJhbGciOiJFUzI1NiJ9.\(body).sig~")

        let claims = SharedDcqlMatcher.matchingClaims(credential)
        XCTAssertEqual(claims.map(\.path), [["vct"]])
    }

    /// A JSON boolean reaches the engine as "true", not "1".
    ///
    /// `JSONSerialization` bridges it to `__NSCFBoolean`, which is an
    /// `NSNumber`, so a formatter that tests `NSNumber` first renders it "1".
    /// DCQL compares a requested `values` entry against this string, so
    /// `age_over_18: true` would then fail to match and the credential would
    /// not be offered.
    func testBooleanClaimsAreNotRenderedAsNumbers() {
        let credential = sdJwtCredential(
            raw: sdJwt(plain: ["age_over_18": true, "age": 42], hidden: ("given_name", "Erika"))
        )
        let claims = SharedDcqlMatcher.matchingClaims(credential)
        XCTAssertEqual(claims.first { $0.path == ["age_over_18"] }?.value, "true")
        XCTAssertEqual(claims.first { $0.path == ["age"] }?.value, "42", "a real number is still a number")
    }

    /// A disclosure whose value hides further claims is resolved too.
    ///
    /// `address` is disclosed, and the object it reveals carries its own `_sd`
    /// pointing at `locality`. One pass cannot reach the inner digest, because
    /// the array holding it does not exist in the payload until the outer
    /// disclosure has been planted - which is why resolution runs to a fixed
    /// point, and why it walks the payload as it is being rebuilt rather than
    /// as it arrived.
    func testDisclosuresNestedInsideDisclosuresAreResolved() {
        let inner = b64url(try! JSONSerialization.data(withJSONObject: ["s1", "locality", "Stockholm"]))
        let outer = b64url(try! JSONSerialization.data(
            withJSONObject: ["s2", "address", ["_sd": [digest(of: inner)]]]
        ))
        let payload: [String: Any] = ["vct": "x", "_sd": [digest(of: outer)], "_sd_alg": "sha-256"]
        let body = b64url(try! JSONSerialization.data(withJSONObject: payload))
        let credential = sdJwtCredential(raw: "eyJhbGciOiJFUzI1NiJ9.\(body).sig~\(outer)~\(inner)~")

        let claims = SharedDcqlMatcher.matchingClaims(credential)
        XCTAssertTrue(
            claims.contains { $0.path == ["address", "locality"] && $0.value == "Stockholm" },
            "got \(claims.map(\.path))"
        )
    }

    /// SD-JWT bookkeeping is not a claim - no verifier requests `_sd_alg`.
    func testStructuralKeysAreNotOfferedAsClaims() {
        let credential = sdJwtCredential(raw: sdJwt(plain: ["vct": "x"], hidden: ("given_name", "Erika")))
        let paths = SharedDcqlMatcher.matchingClaims(credential).map(\.path)
        XCTAssertFalse(paths.contains(["_sd"]))
        XCTAssertFalse(paths.contains(["_sd_alg"]))
    }

    // MARK: - docType(for:)

    /// An mdoc's docType comes from its own MSO, with no metadata at all.
    ///
    /// Issuer metadata only carries a doctype when the issuer exposes a
    /// SIROS-internal schema endpoint; a standards-conformant third-party
    /// issuer has no reason to, and its credentials would otherwise be
    /// unmatchable while looking perfectly valid.
    func testAnMdocResolvesItsDocTypeFromItsOwnMsoWithNoMetadata() {
        let credential = StoredCredential(
            id: 1, format: "mso_mdoc", raw: mdocRaw(docType: "org.iso.18013.5.1.mDL"),
            metadata: nil, batchId: 1, instanceId: 0
        )
        XCTAssertEqual(SharedDcqlMatcher.docType(for: credential), "org.iso.18013.5.1.mDL")
    }

    /// The declared format decides, not the bytes.
    ///
    /// The raw value here would parse perfectly well as an mdoc. It must still
    /// not produce an mdoc docType, because the credential says it is an
    /// SD-JWT. Parsing unconditionally let the content of `raw` answer a
    /// question only `format` may answer - the regression this guards.
    func testAnSdJwtCredentialTakesItsDocTypeFromItsFormatNotItsBytes() {
        let credential = StoredCredential(
            id: 2, format: "dc+sd-jwt", raw: mdocRaw(docType: "org.iso.18013.5.1.mDL"),
            metadata: nil, batchId: 2, instanceId: 0
        )
        XCTAssertNil(SharedDcqlMatcher.docType(for: credential))
    }

    /// The case actually reported (siros-sdk-kotlin#204).
    ///
    /// A real compact serialization is not base64url, so on this platform the
    /// unguarded parse failed silently rather than throwing as it did on
    /// Android - meaning this assertion held before the guard too. It pins the
    /// reported behaviour; the test above is the one that proves the fix.
    func testARealSdJwtSerializationIsNeverParsedAsAnMdoc() {
        let credential = StoredCredential(
            id: 3, format: "vc+sd-jwt",
            raw: "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJodHRwczovL2lzc3Vlci5leGFtcGxlL3BpZCJ9.sig~WQ~",
            metadata: nil, batchId: 3, instanceId: 0
        )
        XCTAssertNil(SharedDcqlMatcher.docType(for: credential))
    }

    /// A genuine mdoc the parser cannot read still falls back to metadata.
    ///
    /// The guard must not turn an mdoc into a metadata-only path, nor swallow
    /// the fallback that keeps such a credential matchable.
    func testAnUnparseableMdocFallsBackToMetadata() {
        let credential = StoredCredential(
            id: 4, format: "mso_mdoc", raw: "not base64url at all!",
            metadata: CredentialMetadata(doctype: "org.iso.18013.5.1.mDL"),
            batchId: 4, instanceId: 0
        )
        XCTAssertEqual(SharedDcqlMatcher.docType(for: credential), "org.iso.18013.5.1.mDL")
    }

    /// A DeviceResponse-shaped mdoc envelope, base64url encoded the way
    /// `StoredCredential.raw` holds it. The MSO carries the docType the way the
    /// wire format does (ISO 18013-5 9.1.2.4): a byteString whose content
    /// decodes to a tag-24 byteString, which itself decodes to the MSO map.
    private func mdocRaw(docType: String) -> String {
        let mso: CBOR = .map([.utf8String("docType"): .utf8String(docType)])
        let taggedMso: CBOR = .tagged(.encodedCBORDataItem, .byteString(mso.encode()))
        let issuerAuth: CBOR = .array([
            .byteString([]),
            .map([:]),
            .byteString(taggedMso.encode()),
            .byteString([UInt8](repeating: 0, count: 64)),
        ])
        let item: CBOR = .map([
            .utf8String("digestID"): .unsignedInt(0),
            .utf8String("random"): .byteString([UInt8](repeating: 0, count: 16)),
            .utf8String("elementIdentifier"): .utf8String("family_name"),
            .utf8String("elementValue"): .utf8String("Doe"),
        ])
        let issuerSigned: CBOR = .map([
            .utf8String("nameSpaces"): .map([
                .utf8String("org.iso.18013.5.1"): .array([
                    .tagged(.encodedCBORDataItem, .byteString(item.encode())),
                ]),
            ]),
            .utf8String("issuerAuth"): issuerAuth,
        ])
        let envelope: CBOR = .map([
            .utf8String("documents"): .array([
                .map([
                    .utf8String("docType"): .utf8String(docType),
                    .utf8String("issuerSigned"): issuerSigned,
                ]),
            ]),
            .utf8String("status"): .unsignedInt(0),
        ])
        return Data(envelope.encode()).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

/// The §6.4 rule, tested where the engine cannot run.
///
/// `CredentialMatcher.narrow(parsed:with:)` is deliberately platform-neutral:
/// calling the engine needs the native library, deciding what its answer means
/// does not. These run on every platform this package builds for.
final class CredentialMatcherNarrowingTests: XCTestCase {

    private func credential(_ id: Int64) -> StoredCredential {
        StoredCredential(id: id, format: "mso_mdoc", raw: "", metadata: nil, batchId: id, instanceId: 0)
    }

    private func result(_ queryId: String, _ ids: [Int64]) -> CredentialMatcher.MatchResult {
        CredentialMatcher.MatchResult(
            queryId: queryId,
            format: "mso_mdoc",
            candidates: ids.map(credential),
            requestedClaims: [["org.iso.18013.5.1", "age_over_18"]],
            ppidContext: "https://rp.example/ctx"
        )
    }

    /// §6.4: when part of a request cannot be answered, none of it may be
    /// offered - not even the part that could.
    ///
    /// The engine reports per-query candidates regardless, so `answerable` has
    /// one here. Offering it would let a user consent to a presentation that
    /// cannot satisfy the verifier.
    func testAnUnsatisfiableRequestWithholdsTheAnswerableQueryToo() {
        let narrowed = CredentialMatcher.narrow(
            parsed: [result("answerable", [1]), result("unanswerable", [])],
            with: SharedDcqlMatcher.Outcome(
                satisfiable: false,
                candidatesByQuery: ["answerable": [1], "unanswerable": []]
            )
        )
        XCTAssertTrue(narrowed.allSatisfy { $0.candidates.isEmpty })
    }

    /// Narrowing filters candidates; it does not touch what the wallet reads at
    /// presentation time. Those are parsed from the query, not decided by the
    /// engine.
    func testPresentationMetadataSurvivesNarrowing() {
        let narrowed = CredentialMatcher.narrow(
            parsed: [result("q", [1, 2])],
            with: SharedDcqlMatcher.Outcome(satisfiable: true, candidatesByQuery: ["q": [2]])
        )
        XCTAssertEqual(narrowed.single().candidates.map(\.id), [2])
        XCTAssertEqual(narrowed.single().requestedClaims, [["org.iso.18013.5.1", "age_over_18"]])
        XCTAssertEqual(narrowed.single().ppidContext, "https://rp.example/ctx")
        XCTAssertEqual(narrowed.single().format, "mso_mdoc")
    }

    /// A query the engine says nothing about offers nothing.
    ///
    /// The engine names every query it was given, so an absent one means it
    /// found no candidates - not that it had no opinion. Reading it the other
    /// way would offer credentials the engine had already declined.
    func testAQueryAbsentFromTheOutcomeOffersNothing() {
        let narrowed = CredentialMatcher.narrow(
            parsed: [result("q", [1])],
            with: SharedDcqlMatcher.Outcome(satisfiable: true, candidatesByQuery: [:])
        )
        XCTAssertTrue(narrowed.single().candidates.isEmpty)
    }
}

private extension Array {
    func single() -> Element {
        precondition(count == 1, "expected exactly one element, got \(count)")
        return self[0]
    }
}

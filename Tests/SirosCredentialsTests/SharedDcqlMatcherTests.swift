// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

/// The shared DCQL engine.
///
/// Only ``SharedDcqlMatcher/splitClaimKey(format:key:)`` is testable off-iOS:
/// the engine is a native library shipped as an iOS-only XCFramework, so
/// everything that calls it is `#if os(iOS)` and would not even compile in this
/// package's macOS and Linux test runs. The engine's own matching behaviour is
/// covered in `siros-dc-matcher` against the specification's examples, which is
/// the point of sharing it; what is left to test here is the SDK's translation
/// layer.
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
}

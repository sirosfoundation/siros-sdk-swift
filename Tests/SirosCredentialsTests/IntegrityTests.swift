// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Subresource-integrity digests as SD-JWT VC Type Metadata uses them.
///
/// The failure that matters here is a false pass: a digest that cannot be
/// parsed, or is computed with an algorithm we do not implement, must not be
/// reported as matching.
final class IntegrityTests: XCTestCase {

    private let content = Data(#"{"vct":"urn:eudi:pid:1"}"#.utf8)

    private func sri256() -> String {
        "sha256-" + Data(SHA256.hash(data: content)).base64EncodedString()
    }

    func testMatchesACorrectSha256Digest() {
        XCTAssertTrue(Integrity.matches(content, sri256()))
    }

    func testMatchesSha384AndSha512() {
        XCTAssertTrue(Integrity.matches(content, "sha384-" + Data(SHA384.hash(data: content)).base64EncodedString()))
        XCTAssertTrue(Integrity.matches(content, "sha512-" + Data(SHA512.hash(data: content)).base64EncodedString()))
    }

    func testRejectsADigestOfDifferentContent() {
        XCTAssertFalse(Integrity.matches(Data("something else".utf8), sri256()))
    }

    func testRejectsAnAlgorithmItCannotCompute() {
        // Not "true because we could not check": an unknown algorithm is a
        // digest that did not pass.
        XCTAssertFalse(Integrity.matches(content, "md5-" + content.base64EncodedString()))
    }

    func testRejectsMalformedValues() {
        XCTAssertFalse(Integrity.matches(content, ""))
        XCTAssertFalse(Integrity.matches(content, "sha256"))
        XCTAssertFalse(Integrity.matches(content, "sha256-not!base64"))
        XCTAssertFalse(Integrity.matches(content, "-" + content.base64EncodedString()))
    }

    func testAcceptsAnyOfSeveralSpaceSeparatedDigests() {
        // SRI permits a list, strongest first; any one matching is a match.
        XCTAssertTrue(Integrity.matches(content, "sha512-AAAA " + sri256()))
    }

    func testToleratesTheUrlSafeAlphabet() {
        // Standard base64 is what the spec says, but a digest that is correct
        // and merely spelled with -_ should not be reported as a mismatch.
        let urlSafe = Data(SHA256.hash(data: content))
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        XCTAssertTrue(Integrity.matches(content, "sha256-\(urlSafe)"))
    }
}

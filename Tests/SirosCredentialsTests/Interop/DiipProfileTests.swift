// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

final class DiipProfileTests: XCTestCase {

    func testTheDefaultProfileIsTheNewestThisSdkImplements() {
        XCTAssertEqual(DiipProfile.latest, .v6)
    }

    func testAVersionIsParsedHoweverItIsSpelledInConfiguration() {
        XCTAssertEqual(DiipProfile.from(version: "v5"), .v5)
        XCTAssertEqual(DiipProfile.from(version: "V5"), .v5)
        XCTAssertEqual(DiipProfile.from(version: "5"), .v5)
        XCTAssertEqual(DiipProfile.from(version: "  v5 "), .v5)
    }

    func testAnUnrecognisedVersionIsReportedRatherThanGuessedAt() {
        XCTAssertNil(DiipProfile.from(version: "v99"))
        XCTAssertNil(DiipProfile.from(version: ""))
        XCTAssertNil(DiipProfile.from(version: nil))
    }

    func testEveryVersionIdentifiesHoldersByDidJwk() {
        for profile in DiipProfile.allCases {
            XCTAssertEqual(profile.holderDidMethod, .jwk, "\(profile.version)")
        }
    }

    func testV6AddsDidWebvhToTheMethodsAWalletResolves() {
        XCTAssertEqual(DiipProfile.v5.resolvableDidMethods, [.jwk, .web])
        XCTAssertTrue(DiipProfile.v6.resolvableDidMethods.contains(.webvh))
        // Additive: nothing v5 required is dropped.
        XCTAssertTrue(DiipProfile.v5.resolvableDidMethods.isSubset(of: DiipProfile.v6.resolvableDidMethods))
    }

    func testSdJwtVcRenamedTheIssuerMetadataPathBetweenV4AndV5() {
        XCTAssertEqual(DiipProfile.v4.sdJwtVcIssuerMetadataPath, "/.well-known/jwt-vc-issuer")
        XCTAssertEqual(DiipProfile.v5.sdJwtVcIssuerMetadataPath, "/.well-known/vc-issuer")
        XCTAssertEqual(DiipProfile.v6.sdJwtVcIssuerMetadataPath, "/.well-known/vc-issuer")
    }

    func testOid4vpWentFromABareSchemeToClientIdentifierPrefixesAtV5() {
        XCTAssertEqual(DiipProfile.v4.clientIdStyle, .bareScheme)
        XCTAssertEqual(DiipProfile.v5.clientIdStyle, .prefixed)
        XCTAssertEqual(DiipProfile.v6.clientIdStyle, .prefixed)
    }

    func testTheDcApiAndWalletFederationAreV6FutureDirections() {
        XCTAssertFalse(DiipProfile.v5.requiresDigitalCredentialsApi)
        XCTAssertTrue(DiipProfile.v6.requiresDigitalCredentialsApi)
        XCTAssertFalse(DiipProfile.v5.requiresWalletFederation)
        XCTAssertTrue(DiipProfile.v6.requiresWalletFederation)
    }

    func testTheTokenStatusListDraftMovesWithTheProfile() {
        XCTAssertEqual(DiipProfile.v4.tokenStatusListDraft, 10)
        XCTAssertEqual(DiipProfile.v5.tokenStatusListDraft, 15)
    }

    func testProfilesOrderByRelease() {
        XCTAssertTrue(DiipProfile.v4 < DiipProfile.v5)
        XCTAssertTrue(DiipProfile.v5 < DiipProfile.v6)
    }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SwiftCBOR
@testable import SirosCredentials

/// An mdoc's validity window and Token Status List reference come out of the
/// MSO, which is credential content: attacker-supplied until it has been
/// verified, and read here before that.
final class MdocValidityClaimsTests: XCTestCase {

    /// A bare `IssuerSigned` whose MSO carries `validityInfo` and the given
    /// `status.status_list`. Not signed - nothing on this path verifies the
    /// signature, which is the point: these bytes are read first.
    private func credential(statusListIdx: CBOR) -> StoredCredential {
        let mso: CBOR = .map([
            .utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL"),
            .utf8String("validityInfo"): .map([
                .utf8String("validFrom"): .tagged(.standardDateTimeString, .utf8String("2026-01-01T00:00:00Z")),
                .utf8String("validUntil"): .tagged(.standardDateTimeString, .utf8String("2027-01-01T00:00:00Z")),
            ]),
            .utf8String("status"): .map([
                .utf8String("status_list"): .map([
                    .utf8String("idx"): statusListIdx,
                    .utf8String("uri"): .utf8String("https://issuer.example/statuslists/1"),
                ]),
            ]),
        ])
        let msoBytes = CBOR.tagged(.encodedCBORDataItem, .byteString(mso.encode()))
        let issuerSigned: CBOR = .map([
            .utf8String("nameSpaces"): .map([:]),
            .utf8String("issuerAuth"): .array([
                .byteString([]), .map([:]), .byteString(msoBytes.encode()), .byteString([]),
            ]),
        ])
        return StoredCredential(
            id: 1,
            format: "mso_mdoc",
            raw: Data(issuerSigned.encode()).base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: ""),
            batchId: 1,
            instanceId: 0
        )
    }

    func testAStatusListReferenceIsReadFromTheMso() throws {
        let claims = try XCTUnwrap(CredentialUtils.validityClaims(credential(statusListIdx: .unsignedInt(7))))
        XCTAssertEqual(claims["validFrom"] as? String, "2026-01-01T00:00:00Z")
        let statusList = try XCTUnwrap(
            (claims["status"] as? [String: Any])?["status_list"] as? [String: Any]
        )
        XCTAssertEqual(statusList["idx"] as? Int, 7)
        XCTAssertEqual(statusList["uri"] as? String, "https://issuer.example/statuslists/1")
    }

    func testAnIndexPastIntMaxIsNotReadRatherThanTrapping() throws {
        // `Int(idx)` traps on this, and a trap is not a parse failure - it
        // takes the process down on a credential someone else wrote. A status
        // list with 2^64 entries does not exist; the index is simply not read,
        // which leaves the reference incomplete and the status unavailable.
        let claims = try XCTUnwrap(
            CredentialUtils.validityClaims(credential(statusListIdx: .unsignedInt(UInt64.max)))
        )
        XCTAssertEqual(claims["validFrom"] as? String, "2026-01-01T00:00:00Z")
        let statusList = try XCTUnwrap(
            (claims["status"] as? [String: Any])?["status_list"] as? [String: Any]
        )
        XCTAssertNil(statusList["idx"])
        XCTAssertNil(TokenStatusList.extractReference(from: claims))
        // Regression (review finding): extractReference's nil alone reads
        // the same as "no status claim at all" - hasStatusReference is what
        // lets CredentialStatusEvaluator tell a malformed one (must not pass
        // as valid) from a genuinely absent one (ordinarily valid) apart.
        XCTAssertTrue(
            TokenStatusList.hasStatusReference(claims),
            "a status_list claim IS present, just unreadable - must not look like no claim at all"
        )
    }

    /// Regression (review finding): when NEITHER `idx` nor `uri` comes
    /// through usably, the reference built from them is entirely empty -
    /// `!reference.isEmpty` previously gated recording the claim at all, so
    /// this most-malformed case was the one most completely indistinguishable
    /// from "no status claim", the opposite of what fail-closed requires.
    func testAStatusListWithNeitherIdxNorUriUsableIsStillRecordedAsPresent() throws {
        let mso: CBOR = .map([
            .utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL"),
            .utf8String("status"): .map([
                .utf8String("status_list"): .map([
                    .utf8String("idx"): .unsignedInt(UInt64.max),
                    .utf8String("uri"): .unsignedInt(123), // not a string
                ]),
            ]),
        ])
        let msoBytes = CBOR.tagged(.encodedCBORDataItem, .byteString(mso.encode()))
        let issuerSigned: CBOR = .map([
            .utf8String("nameSpaces"): .map([:]),
            .utf8String("issuerAuth"): .array([
                .byteString([]), .map([:]), .byteString(msoBytes.encode()), .byteString([]),
            ]),
        ])
        let credential = StoredCredential(
            id: 1,
            format: "mso_mdoc",
            raw: Data(issuerSigned.encode()).base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: ""),
            batchId: 1,
            instanceId: 0
        )
        let claims = try XCTUnwrap(CredentialUtils.validityClaims(credential))
        XCTAssertNil(TokenStatusList.extractReference(from: claims))
        XCTAssertTrue(
            TokenStatusList.hasStatusReference(claims),
            "status_list WAS declared, with nothing usable in it - still not the same as no claim at all"
        )
    }

    /// Regression (review finding): when `validityInfo` is present but
    /// NEITHER `validFrom` nor `validUntil` untags to a readable string
    /// (here, both are bare integers rather than tagged date strings), the
    /// claims dictionary previously came back empty for this block -
    /// indistinguishable from a credential declaring no validity window at
    /// all (an ordinary credential, correctly valid indefinitely), rather
    /// than one whose window this SDK could not read.
    func testAValidityInfoWithNeitherDateReadableIsStillRecordedAsPresent() throws {
        let mso: CBOR = .map([
            .utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL"),
            .utf8String("validityInfo"): .map([
                .utf8String("validFrom"): .unsignedInt(1),
                .utf8String("validUntil"): .unsignedInt(2),
            ]),
        ])
        let msoBytes = CBOR.tagged(.encodedCBORDataItem, .byteString(mso.encode()))
        let issuerSigned: CBOR = .map([
            .utf8String("nameSpaces"): .map([:]),
            .utf8String("issuerAuth"): .array([
                .byteString([]), .map([:]), .byteString(msoBytes.encode()), .byteString([]),
            ]),
        ])
        let credential = StoredCredential(
            id: 1,
            format: "mso_mdoc",
            raw: Data(issuerSigned.encode()).base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: ""),
            batchId: 1,
            instanceId: 0
        )
        let claims = try XCTUnwrap(CredentialUtils.validityClaims(credential))
        XCTAssertNil(claims["validFrom"])
        XCTAssertNil(claims["validUntil"])
        XCTAssertTrue(
            CredentialUtils.hasDeclaredValidityWindow(claims),
            "validityInfo WAS declared, with neither date readable - still not the same as no window at all"
        )
    }

    /// End-to-end regression (review finding): the credential above must
    /// evaluate to `.unknown`, not `.valid` - a credential whose declared
    /// validity window this SDK could not read is not the same thing as one
    /// that declared no window at all.
    func testAMdocWithAnUnreadableValidityWindowEvaluatesAsUnknown() async throws {
        let mso: CBOR = .map([
            .utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL"),
            .utf8String("validityInfo"): .map([
                .utf8String("validFrom"): .unsignedInt(1),
                .utf8String("validUntil"): .unsignedInt(2),
            ]),
        ])
        let msoBytes = CBOR.tagged(.encodedCBORDataItem, .byteString(mso.encode()))
        let issuerSigned: CBOR = .map([
            .utf8String("nameSpaces"): .map([:]),
            .utf8String("issuerAuth"): .array([
                .byteString([]), .map([:]), .byteString(msoBytes.encode()), .byteString([]),
            ]),
        ])
        let credential = StoredCredential(
            id: 1,
            format: "mso_mdoc",
            raw: Data(issuerSigned.encode()).base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: ""),
            batchId: 1,
            instanceId: 0
        )
        let claims = try XCTUnwrap(CredentialUtils.validityClaims(credential))
        let evaluator = CredentialStatusEvaluator()
        let status = await evaluator.evaluate(claims: claims, credentialIssuer: "https://issuer.example")
        XCTAssertEqual(status, .unknown)
    }

    /// Regression (review finding): a GENUINELY readable `validFrom`
    /// alongside a malformed `validUntil` (an integer, not a tagged date
    /// string) previously evaluated to `.valid` - the "both bounds nil"
    /// check this credential doesn't match, since `validFrom` parsed fine,
    /// left the malformed `validUntil` silently reading as "no upper bound
    /// at all" instead of unreadable.
    func testAMdocWithOneReadableBoundAndOneMalformedBoundEvaluatesAsUnknown() async throws {
        let mso: CBOR = .map([
            .utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL"),
            .utf8String("validityInfo"): .map([
                .utf8String("validFrom"): .tagged(.standardDateTimeString, .utf8String("2020-01-01T00:00:00Z")),
                .utf8String("validUntil"): .unsignedInt(2),
            ]),
        ])
        let msoBytes = CBOR.tagged(.encodedCBORDataItem, .byteString(mso.encode()))
        let issuerSigned: CBOR = .map([
            .utf8String("nameSpaces"): .map([:]),
            .utf8String("issuerAuth"): .array([
                .byteString([]), .map([:]), .byteString(msoBytes.encode()), .byteString([]),
            ]),
        ])
        let credential = StoredCredential(
            id: 1,
            format: "mso_mdoc",
            raw: Data(issuerSigned.encode()).base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: ""),
            batchId: 1,
            instanceId: 0
        )
        let claims = try XCTUnwrap(CredentialUtils.validityClaims(credential))
        XCTAssertEqual(claims["validFrom"] as? String, "2020-01-01T00:00:00Z", "sanity: validFrom DID parse")
        XCTAssertTrue(CredentialUtils.hasUnreadableValidUntil(claims))
        XCTAssertFalse(CredentialUtils.hasUnreadableValidFrom(claims))
        let evaluator = CredentialStatusEvaluator()
        let status = await evaluator.evaluate(claims: claims, credentialIssuer: "https://issuer.example")
        XCTAssertEqual(status, .unknown)
    }

    /// Regression (review finding): a `status` member that is not even a
    /// map (here, a bare scalar) previously failed the whole
    /// `if let status = ..., let statusList = status[...]` as one unit, so
    /// `claims["status"]` was never set at all - indistinguishable from no
    /// status claim, and reported `.valid` instead of `.unknown`.
    func testAScalarStatusMemberIsStillRecordedAsPresent() throws {
        let mso: CBOR = .map([
            .utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL"),
            .utf8String("status"): .unsignedInt(7), // not a map at all
        ])
        let msoBytes = CBOR.tagged(.encodedCBORDataItem, .byteString(mso.encode()))
        let issuerSigned: CBOR = .map([
            .utf8String("nameSpaces"): .map([:]),
            .utf8String("issuerAuth"): .array([
                .byteString([]), .map([:]), .byteString(msoBytes.encode()), .byteString([]),
            ]),
        ])
        let credential = StoredCredential(
            id: 1,
            format: "mso_mdoc",
            raw: Data(issuerSigned.encode()).base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: ""),
            batchId: 1,
            instanceId: 0
        )
        let claims = try XCTUnwrap(CredentialUtils.validityClaims(credential))
        XCTAssertNil(TokenStatusList.extractReference(from: claims))
        XCTAssertTrue(
            TokenStatusList.hasStatusReference(claims),
            "status WAS declared, even though it isn't a map at all - still not the same as no claim"
        )
    }
}

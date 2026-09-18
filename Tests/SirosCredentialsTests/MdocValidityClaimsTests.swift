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
    }
}

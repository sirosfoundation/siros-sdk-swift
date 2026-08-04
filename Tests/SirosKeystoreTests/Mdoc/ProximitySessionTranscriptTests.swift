// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@preconcurrency import SwiftCBOR
@testable import SirosKeystore

#if canImport(CryptoKit)

/// Ported from `org.siros.sdk.keystore.mdoc.ProximitySessionTranscriptTest`
/// (Kotlin). Gated on `canImport(CryptoKit)` only because it uses
/// `DeviceEngagement.create()` to build fixture data -
/// `ProximitySessionTranscript.build` itself has no crypto dependency.
final class ProximitySessionTranscriptTests: XCTestCase {

    /// Reuse DeviceEngagement's own COSE_Key encoding as a stand-in "reader" key for this test's purposes.
    private func fakeEReaderKeyBytes(_ engagement: DeviceEngagement.Engagement) throws -> [UInt8] {
        let decoded = try CBOR.decode(engagement.deviceEngagementBytes)
        guard case .array(let security)? = decoded?[CBOR.unsignedInt(1)] else {
            throw XCTSkip("malformed fixture")
        }
        return security[1].encode()
    }

    func testBuild_qrHandover_producesNullHandoverSlot() throws {
        let engagement = try DeviceEngagement.create()
        let eReaderKeyBytes = try fakeEReaderKeyBytes(engagement)

        let transcript = try ProximitySessionTranscript.build(
            deviceEngagementBytes: engagement.deviceEngagementBytes,
            eReaderKeyBytes: eReaderKeyBytes,
            handoverSelectMessageBytes: nil
        )

        let decoded = try CBOR.decode(transcript)
        guard case .array(let elements)? = decoded else {
            return XCTFail("transcript not an array")
        }
        XCTAssertEqual(elements.count, 3)
        guard case .tagged(let tag0, let content0) = elements[0], tag0 == .encodedCBORDataItem,
              case .byteString(let deBytes) = content0 else {
            return XCTFail("element 0 not tag-24-wrapped")
        }
        XCTAssertEqual(deBytes, engagement.deviceEngagementBytes)
        guard case .tagged(let tag1, _) = elements[1], tag1 == .encodedCBORDataItem else {
            return XCTFail("element 1 not tag-24-wrapped")
        }
        guard case .null = elements[2] else {
            return XCTFail("element 2 not null")
        }
    }

    func testBuild_nfcStaticHandover_producesTwoElementArrayWithNullSecondSlot() throws {
        let engagement = try DeviceEngagement.create()
        let eReaderKeyBytes = try fakeEReaderKeyBytes(engagement)
        let handoverSelect = try NfcHandoverSelect.build(engagement)

        let transcript = try ProximitySessionTranscript.build(
            deviceEngagementBytes: engagement.deviceEngagementBytes,
            eReaderKeyBytes: eReaderKeyBytes,
            handoverSelectMessageBytes: handoverSelect
        )

        let decoded = try CBOR.decode(transcript)
        guard case .array(let elements)? = decoded else {
            return XCTFail("transcript not an array")
        }
        guard case .array(let handover) = elements[2] else {
            return XCTFail("handover not an array")
        }
        XCTAssertEqual(handover.count, 2)
        guard case .byteString(let hs) = handover[0] else {
            return XCTFail("handover[0] not a byte string")
        }
        XCTAssertEqual(hs, handoverSelect)
        guard case .null = handover[1] else {
            return XCTFail("handover[1] not null")
        }
    }

    func testBuild_eReaderKeyBytes_reusedVerbatim_notRebuilt() throws {
        let engagement = try DeviceEngagement.create()
        let eReaderKeyBytes = try fakeEReaderKeyBytes(engagement)

        let transcript = try ProximitySessionTranscript.build(
            deviceEngagementBytes: engagement.deviceEngagementBytes,
            eReaderKeyBytes: eReaderKeyBytes,
            handoverSelectMessageBytes: nil
        )

        let decoded = try CBOR.decode(transcript)
        guard case .array(let elements)? = decoded else {
            return XCTFail("transcript not an array")
        }
        XCTAssertEqual(elements[1].encode(), eReaderKeyBytes)
    }
}

#endif

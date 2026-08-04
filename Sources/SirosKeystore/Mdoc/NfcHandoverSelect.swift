// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// ISO 18013-5 §9.2/§11.1.2 NFC Static Handover: builds the Handover Select
/// NDEF message an mdoc (acting as an NFC Forum Type 4 Tag, per §9.2.1) would
/// serve to an mdoc reader, wrapping a `DeviceEngagement.Engagement` for BLE
/// data retrieval.
///
/// Byte layout verified by hand against the official worked example in Annex
/// D.3.3 of the ISO/IEC 18013-5 second-edition CD ballot-resolution draft
/// (`91020f487315d10209...`), which decodes to exactly the three-record NDEF
/// message this builder produces: an "Hs" (Handover Select) record wrapping a
/// single "ac" (Alternative Carrier) record, a MIME carrier-configuration
/// record (`application/vnd.bluetooth.le.oob`), and an external-type
/// auxiliary record (`iso.org:18013:deviceengagement`) carrying the
/// `DeviceEngagement` CBOR bytes verbatim.
///
/// This message-BUILDING logic is pure, portable CBOR/NDEF construction and
/// is ported here as testable business logic even though, unlike Android's
/// `HostApduService`, iOS gives third-party apps no way to actually SERVE
/// this as an NFC Type 4 Tag / HCE host (that capability is restricted to
/// specific system frameworks - transit/ID passes via PassKit - not general
/// app code). There is no `MdocHostApduService` iOS equivalent, and none is
/// planned; this class exists so the SessionTranscript's NFCHandover path can
/// still be exercised/tested independent of a live HCE host.
public enum NfcHandoverSelect {

    // NDEF record header bit positions (NFC Forum NDEF Technical
    // Specification 1.0 §3.2).
    private static let ndefMB: UInt8 = 0x80
    private static let ndefME: UInt8 = 0x40
    private static let ndefSR: UInt8 = 0x10
    private static let ndefIL: UInt8 = 0x08
    private static let tnfWellKnown: UInt8 = 0x01
    private static let tnfMime: UInt8 = 0x02
    private static let tnfExternal: UInt8 = 0x04

    /// Connection Handover (CH) Technical Specification version 1.5, per §9.2.1.
    private static let handoverVersion15: UInt8 = 0x15

    /// Carrier Power State "active", per NFC Forum CH 1.5 §5.1 (ac record).
    private static let cpsActive: UInt8 = 0x01

    private static let carrierDataReference = "0"
    private static let auxDataReference = "mdoc"
    private static let bleOobMimeType = "application/vnd.bluetooth.le.oob"
    private static let deviceEngagementExternalType = "iso.org:18013:deviceengagement"

    // Bluetooth Supplement to the Core Specification AD types (§11.1.2).
    private static let adTypeLeRole: UInt8 = 0x1C

    /// Bluetooth Supplement to the Core Specification LE Role AD (0x1C) values.
    public enum LeRole: UInt8, CaseIterable, Sendable {
        case peripheralOnly = 0x00
        case centralOnly = 0x01
        /// Both roles supported, peripheral preferred for connection establishment.
        case bothPeripheralPreferred = 0x02
        /// Both roles supported, central preferred - matches §11.1.3.1's guidance that a
        /// reader "should select the mdoc central client mode" when both are offered.
        case bothCentralPreferred = 0x03
    }

    /// Build the Handover Select NDEF message for `engagement`.
    ///
    /// The LE Role advertised is derived from which BLE modes `engagement`
    /// offers - matching the mandatory LE Role (0x1C) AD type (§11.1.2). LE
    /// Device Address (0x1B) is omitted: it's merely "recommended", and
    /// there's no public API to read the local BLE MAC address on either
    /// platform this SDK targets, so the reader is expected to connect using
    /// the UUID(s) embedded in the `DeviceEngagement` CBOR itself.
    public static func build(_ engagement: DeviceEngagement.Engagement) throws -> [UInt8] {
        let leRole: LeRole
        if engagement.centralClientModeUuid != nil && engagement.peripheralServerModeUuid != nil {
            leRole = .bothCentralPreferred
        } else if engagement.centralClientModeUuid != nil {
            leRole = .centralOnly
        } else if engagement.peripheralServerModeUuid != nil {
            leRole = .peripheralOnly
        } else {
            throw KeystoreError.invalidParameter("engagement offers no BLE retrieval method")
        }
        return build(deviceEngagementBytes: engagement.deviceEngagementBytes, leRole: leRole)
    }

    /// Lower-level overload taking the LE Role explicitly - used by tests.
    public static func build(deviceEngagementBytes: [UInt8], leRole: LeRole) -> [UInt8] {
        let acMessage = ndefRecord(
            tnf: tnfWellKnown,
            type: Array("ac".utf8),
            id: nil,
            payload: alternativeCarrierPayload(),
            messageBegin: true,
            messageEnd: true
        )
        let hsPayload: [UInt8] = [handoverVersion15] + acMessage

        let hsRecord = ndefRecord(
            tnf: tnfWellKnown,
            type: Array("Hs".utf8),
            id: nil,
            payload: hsPayload,
            messageBegin: true,
            messageEnd: false
        )
        let carrierConfigRecord = ndefRecord(
            tnf: tnfMime,
            type: Array(bleOobMimeType.utf8),
            id: Array(carrierDataReference.utf8),
            payload: bleOobPayload(leRole),
            messageBegin: false,
            messageEnd: false
        )
        let deviceEngagementRecord = ndefRecord(
            tnf: tnfExternal,
            type: Array(deviceEngagementExternalType.utf8),
            id: Array(auxDataReference.utf8),
            payload: deviceEngagementBytes,
            messageBegin: false,
            messageEnd: true
        )

        return hsRecord + carrierConfigRecord + deviceEngagementRecord
    }

    /// `ac` (Alternative Carrier) record payload, per NFC Forum CH 1.5 §5.1:
    /// CPS (1 byte) + Carrier Data Reference (length-prefixed) + Auxiliary
    /// Data Reference Count (1 byte) + Auxiliary Data Reference(s)
    /// (length-prefixed), referencing the carrier-configuration record by
    /// `carrierDataReference` and the device-engagement record by
    /// `auxDataReference`, matching Annex D.3.3's worked example exactly.
    private static func alternativeCarrierPayload() -> [UInt8] {
        let cdr = Array(carrierDataReference.utf8)
        let aux = Array(auxDataReference.utf8)
        var out: [UInt8] = [cpsActive]
        out.append(UInt8(cdr.count))
        out.append(contentsOf: cdr)
        out.append(1) // Auxiliary Data Reference Count
        out.append(UInt8(aux.count))
        out.append(contentsOf: aux)
        return out
    }

    /// Bluetooth OOB data block (Supplement to the Bluetooth Core
    /// Specification, referenced by §11.1.2): a sequence of AD structures,
    /// each `length(1) + type(1) + data(length-1)`. Only LE Role is included -
    /// see `build`'s doc comment for why LE Device Address is omitted.
    private static func bleOobPayload(_ leRole: LeRole) -> [UInt8] {
        [2, adTypeLeRole, leRole.rawValue] // AD length = type(1) + data(1)
    }

    private static func ndefRecord(
        tnf: UInt8,
        type: [UInt8],
        id: [UInt8]?,
        payload: [UInt8],
        messageBegin: Bool,
        messageEnd: Bool
    ) -> [UInt8] {
        precondition(payload.count < 256, "NDEF short record payload must be < 256 bytes")
        var header = tnf
        if messageBegin { header |= ndefMB }
        if messageEnd { header |= ndefME }
        header |= ndefSR
        if id != nil { header |= ndefIL }

        var out: [UInt8] = [header, UInt8(type.count), UInt8(payload.count)]
        if let id { out.append(UInt8(id.count)) }
        out.append(contentsOf: type)
        if let id { out.append(contentsOf: id) }
        out.append(contentsOf: payload)
        return out
    }
}

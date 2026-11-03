// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// A validated ISO/IEC 18013-5 NFC static handover and its exact transcript inputs.
///
/// `handoverSelectBytes` is the complete NDEF Handover Select message as
/// received. `handoverCbor` is the canonical `NFCHandover` value
/// `[HandoverSelectBytes, null]`; neither value is derived from a re-encoded
/// NDEF message or DeviceEngagement.
public struct MdocNfcHandover: Sendable, Equatable, MdocEngagement {
    /// The complete original NDEF Handover Select message.
    public let handoverSelectBytes: [UInt8]
    /// Canonical CBOR encoding of `[HandoverSelectBytes, null]`.
    public let handoverCbor: [UInt8]
    /// The strictly validated DeviceEngagement auxiliary record.
    public let engagement: MdocQrEngagement
    /// BLE metadata usable for transport selection, or nil when incomplete.
    public let ble: MdocQrEngagement.BleRetrievalMetadata?

    /// The exact raw DeviceEngagement bytes from the auxiliary record.
    public var deviceEngagementBytes: [UInt8] { engagement.deviceEngagementBytes }
    /// The exact original tag-24-wrapped EDeviceKeyBytes.
    public var eDeviceKeyBytes: [UInt8] { engagement.eDeviceKeyBytes }
    /// False for incomplete or address-only BLE metadata, including Annex D.3.3.
    public var bleSupported: Bool { ble != nil }

    internal init(
        handoverSelectBytes: [UInt8],
        handoverCbor: [UInt8],
        engagement: MdocQrEngagement,
        ble: MdocQrEngagement.BleRetrievalMetadata?
    ) {
        self.handoverSelectBytes = handoverSelectBytes
        self.handoverCbor = handoverCbor
        self.engagement = engagement
        self.ble = ble
    }
}

/// The NFC static handover is malformed, unsupported, or internally inconsistent.
public enum MdocNfcHandoverError: Error, Sendable, Equatable {
    case handoverTooLarge
    case malformedNDEF(String)
    case invalidHandover(String)
    case invalidDeviceEngagement(String)
    case malformedBluetoothOOB(String)
    case inconsistentBluetoothMetadata(String)
}

extension MdocNfcHandoverError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .handoverTooLarge:
            return "Handover Select exceeds \(MdocNfcHandoverParser.maximumHandoverSelectSize) bytes"
        case .malformedNDEF(let reason):
            return "Malformed Handover Select NDEF: \(reason)"
        case .invalidHandover(let reason):
            return "Invalid NFC static handover: \(reason)"
        case .invalidDeviceEngagement(let reason):
            return "Invalid DeviceEngagement record: \(reason)"
        case .malformedBluetoothOOB(let reason):
            return "Malformed Bluetooth OOB data: \(reason)"
        case .inconsistentBluetoothMetadata(let reason):
            return "Inconsistent Bluetooth handover metadata: \(reason)"
        }
    }
}

extension MdocNfcHandoverError: LocalizedError {
    public var errorDescription: String? { description }
}

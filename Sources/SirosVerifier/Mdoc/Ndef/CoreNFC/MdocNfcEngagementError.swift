// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Failures encountered while reading an NFC static handover from a Type 4 tag.
///
/// Swift task cancellation is deliberately not represented here: cancelling the
/// calling task invalidates the NFC session and throws `CancellationError`.
public enum MdocNfcEngagementError: Error, Sendable, Equatable {
    /// CoreNFC tag reading is unavailable on this device or for this process.
    case unavailable
    /// The session detected no ISO 7816 (Type 4) tag.
    case noTag
    /// This reader already has an outstanding `readHandover` call.
    case readInProgress
    /// CoreNFC could not connect to the tag or complete an APDU exchange.
    case apdu(String)
    /// The tag returned an ISO 7816 status word other than `9000`.
    case apduStatus(sw1: UInt8, sw2: UInt8)
    /// The complete read did not finish within the caller's timeout.
    case timeout
    /// NLEN, the NDEF payload, or the static handover was malformed or unsupported.
    case malformed(String)
}

extension MdocNfcEngagementError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .unavailable:
            return "NFC tag reading is unavailable"
        case .noTag:
            return "No ISO 7816 Type 4 tag was detected"
        case .readInProgress:
            return "An NFC static-handover read is already in progress"
        case .apdu(let reason):
            return "NFC APDU exchange failed: \(reason)"
        case .apduStatus(let sw1, let sw2):
            return String(format: "NFC APDU returned status 0x%02X%02X instead of 9000", sw1, sw2)
        case .timeout:
            return "NFC static-handover read timed out"
        case .malformed(let reason):
            return "Malformed NFC static handover: \(reason)"
        }
    }
}

extension MdocNfcEngagementError: LocalizedError {
    public var errorDescription: String? { description }
}

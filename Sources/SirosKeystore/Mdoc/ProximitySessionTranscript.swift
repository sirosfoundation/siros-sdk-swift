// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
@preconcurrency import SwiftCBOR

/// ISO 18013-5 §9.1.5.1 proximity session transcript:
/// ```
/// SessionTranscript = [ DeviceEngagementBytes, EReaderKeyBytes, Handover ]
/// Handover = QRHandover / NFCHandover
/// QRHandover = null
/// NFCHandover = [ bstr, bstr / null ]   ; [Handover Select msg, Handover Request msg (null for Static Handover)]
/// ```
///
/// A third, distinct session-transcript variant alongside
/// `MdocDeviceResponseBuilder`'s existing `OpenID4VPHandover` (redirect flow)
/// and `OpenID4VPDCAPIHandover` (DC API) transcripts - this one is for real
/// ISO 18013-5 proximity (BLE) presentation, not OpenID4VP.
///
/// Returns the bare (untagged) `SessionTranscript` array bytes, matching
/// `MdocDeviceResponseBuilder.buildForProximity`'s expected input (which
/// decodes and re-embeds them into `DeviceAuthentication` directly, per the
/// spec's `DeviceAuthentication = [..., SessionTranscript, ...]` - note:
/// `SessionTranscript`, not the tag-24-wrapped `SessionTranscriptBytes`).
/// `ProximitySessionCrypto` performs its own tag-24 wrap when it needs the
/// tag-24-wrapped `SessionTranscriptBytes` form for the HKDF salt - see its
/// doc comment.
///
/// Ported from `org.siros.sdk.keystore.mdoc.ProximitySessionTranscript`
/// (Kotlin). Pure CBOR construction - no platform-specific crypto
/// dependency, unlike most of this SDK's other mdoc proximity types.
public enum ProximitySessionTranscript {

    /// - Parameters:
    ///   - deviceEngagementBytes: raw (untagged) `DeviceEngagement` CBOR, as produced by `DeviceEngagement.create`.
    ///   - eReaderKeyBytes: the exact bytes of the incoming `SessionEstablishment` message's
    ///     `eReaderKey` field (already `#6.24`-tagged `COSE_Key`) - reused verbatim, never rebuilt,
    ///     so this transcript matches exactly what the reader itself sent.
    ///   - handoverSelectMessageBytes: the NDEF Handover Select message bytes
    ///     (`NfcHandoverSelect.build`'s output) if device engagement happened via NFC static
    ///     handover; nil if via QR.
    public static func build(
        deviceEngagementBytes: [UInt8],
        eReaderKeyBytes: [UInt8],
        handoverSelectMessageBytes: [UInt8]?
    ) throws -> [UInt8] {
        let taggedDeviceEngagement: CBOR = .tagged(.encodedCBORDataItem, .byteString(deviceEngagementBytes))
        guard let eReaderKey = try CBOR.decode(eReaderKeyBytes) else {
            throw KeystoreError.cryptoError("empty eReaderKey bytes")
        }

        let handover: CBOR
        if let handoverSelectMessageBytes {
            handover = .array([.byteString(handoverSelectMessageBytes), .null])
        } else {
            handover = .null
        }

        let transcript: CBOR = .array([taggedDeviceEngagement, eReaderKey, handover])
        return transcript.encode()
    }
}

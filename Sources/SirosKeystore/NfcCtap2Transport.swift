// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

#if canImport(CoreNFC)
import CoreNFC
import Foundation

/// `Ctap2TransportProvider` implementation for NFC-capable FIDO2
/// authenticators (e.g. a YubiKey 5 NFC), using CoreNFC's
/// `NFCTagReaderSession`/`NFCISO7816Tag`.
///
/// USB HID host mode is not available to third-party iOS apps, and no
/// YubiKey implements BLE-FIDO2 - CoreNFC is the only viable transport
/// for NFC-capable authenticators on iOS.
///
/// The raw CTAP2 command bytes this receives from `send(command:)`
/// (already CBOR-encoded by Rust's `preview_sign_protocol`) are wrapped
/// in the standard `NFCCTAP_MSG` ISO 7816 APDU (`CLA=0x80, INS=0x10`) -
/// confirmed against a real YubiKey 5.8 over NFC this session. The
/// response's first byte is the CTAP2 status, exactly as Rust's response
/// parsers expect; `NFCISO7816Tag.sendCommand` already separates the
/// trailing ISO 7816 SW1/SW2 from the response body, so no reassembly is
/// needed on this side (unlike a raw byte-level transceive API).
public final class NfcCtap2Transport: NSObject, Ctap2TransportProvider, @unchecked Sendable {

    /// FIDO2 applet AID (`A0 00 00 06 47 2F 00 01`), per the CTAP2 NFC
    /// transport binding.
    private static let fidoAid = Data([0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01])

    private var session: NFCTagReaderSession?
    private var isoTag: NFCISO7816Tag?
    private var connectContinuation: CheckedContinuation<Void, Error>?
    private let alertMessage: String

    /// - Parameter alertMessage: Shown in the system NFC scanning sheet
    ///   while waiting for the authenticator to be tapped.
    public init(alertMessage: String = "Hold your security key near the top of the phone.") {
        self.alertMessage = alertMessage
    }

    public func isAvailable() async -> Bool {
        NFCTagReaderSession.readingAvailable
    }

    public func connect() async throws {
        guard NFCTagReaderSession.readingAvailable else {
            throw Ctap2TransportError.notAvailable
        }
        // A second connect() call while a previous one is still pending
        // (e.g. a caller retries before the user has tapped the tag, with no
        // intervening disconnect()) must not silently overwrite
        // connectContinuation - both NFCTagReaderSession instances would
        // share `self` as delegate, so the FIRST session's
        // didDetect/didInvalidateWithError could resolve the SECOND call's
        // continuation, leaving the first caller's `await connect()` hanging
        // forever on a continuation that's never resumed.
        guard connectContinuation == nil else {
            throw Ctap2TransportError.connectionFailed("connect() already in progress")
        }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            self.connectContinuation = continuation
            let session = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)
            session?.alertMessage = alertMessage
            self.session = session
            session?.begin()
        }
    }

    public func disconnect() async throws {
        session?.invalidate()
        session = nil
        isoTag = nil
    }

    public func send(command: Data) async throws -> Data {
        guard let isoTag = isoTag else {
            throw Ctap2TransportError.deviceDisconnected
        }
        // NFCCTAP_MSG: CLA=0x80 INS=0x10 P1=0x00 P2=0x00. `expectedResponseLength:
        // -1` tells CoreNFC to use extended-length APDU encoding automatically -
        // CTAP2 payloads routinely exceed the 256-byte short-APDU limit.
        let apdu = NFCISO7816APDU(
            instructionClass: 0x80,
            instructionCode: 0x10,
            p1Parameter: 0x00,
            p2Parameter: 0x00,
            data: command,
            expectedResponseLength: -1
        )
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            isoTag.sendCommand(apdu: apdu) { responseData, sw1, sw2, error in
                if let error = error {
                    continuation.resume(throwing: Ctap2TransportError.invalidResponse(error.localizedDescription))
                    return
                }
                guard sw1 == 0x90, sw2 == 0x00 else {
                    continuation.resume(throwing: Ctap2TransportError.invalidResponse(
                        String(format: "NFC APDU status 0x%02X%02X", sw1, sw2)))
                    return
                }
                // responseData here is exactly [ctap2Status] + [cborBody] -
                // CoreNFC already stripped SW1/SW2, which is transport-level,
                // not part of the CTAP2 message Rust expects.
                continuation.resume(returning: responseData)
            }
        }
    }
}

extension NfcCtap2Transport: NFCTagReaderSessionDelegate {
    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        if let continuation = connectContinuation {
            connectContinuation = nil
            continuation.resume(throwing: Ctap2TransportError.connectionFailed(error.localizedDescription))
        }
    }

    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard let tag = tags.first, case let .iso7816(iso7816Tag) = tag else {
            connectContinuation?.resume(throwing: Ctap2TransportError.connectionFailed("not an ISO 7816 tag"))
            connectContinuation = nil
            return
        }

        session.connect(to: tag) { [weak self] error in
            guard let self = self else { return }
            if let error = error {
                self.connectContinuation?.resume(throwing: Ctap2TransportError.connectionFailed(error.localizedDescription))
                self.connectContinuation = nil
                return
            }

            let selectApdu = NFCISO7816APDU(
                instructionClass: 0x00,
                instructionCode: 0xA4,
                p1Parameter: 0x04,
                p2Parameter: 0x00,
                data: Self.fidoAid,
                expectedResponseLength: -1
            )
            iso7816Tag.sendCommand(apdu: selectApdu) { _, sw1, sw2, error in
                if let error = error {
                    self.connectContinuation?.resume(throwing: Ctap2TransportError.connectionFailed(error.localizedDescription))
                } else if sw1 == 0x90, sw2 == 0x00 {
                    self.isoTag = iso7816Tag
                    self.connectContinuation?.resume(returning: ())
                } else {
                    self.connectContinuation?.resume(throwing: Ctap2TransportError.connectionFailed(
                        String(format: "SELECT FIDO applet failed: 0x%02X%02X", sw1, sw2)))
                }
                self.connectContinuation = nil
            }
        }
    }
}

#endif // canImport(CoreNFC)

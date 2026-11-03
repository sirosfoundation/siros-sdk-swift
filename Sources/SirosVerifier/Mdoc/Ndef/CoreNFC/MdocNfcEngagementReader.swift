// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

#if os(iOS)
import CoreNFC
import Foundation

/// Reads an ISO/IEC 18013-5 static NFC handover from an NFC Forum Type 4 tag.
///
/// The returned value is intended for subsequent BLE transport selection. This
/// reader performs no negotiated handover and sends no NFC `SessionData`.
///
/// The host application must provide `NFCReaderUsageDescription`, enable TAG
/// reader-session format, and list `D2760000850101` under the ISO 7816 select
/// identifiers key `com.apple.developer.nfc.readersession.iso7816.select-identifiers`.
/// That identifier selects the NDEF Tag Application; the reader then selects
/// NDEF data file `E104`.
public final class MdocNfcEngagementReader: NSObject, @unchecked Sendable {
    private let alertMessage: String
    private let lock = NSLock()
    private var activeOperation: MdocNfcReadOperation?

    /// - Parameter alertMessage: Text displayed in the system NFC scanning sheet.
    public init(alertMessage: String = "Hold the top of your phone near the mdoc.") {
        self.alertMessage = alertMessage
        super.init()
    }

    /// Reads and validates one complete NDEF Handover Select message.
    ///
    /// Only one call may be outstanding on a reader. The timeout covers session
    /// discovery, connection, every APDU, and parsing. Every terminal path
    /// invalidates its `NFCTagReaderSession` before resuming the caller.
    /// Cancelling the calling task invalidates the session and throws
    /// `CancellationError` rather than wrapping cancellation in an SDK error.
    public func readHandover(timeout: TimeInterval = 20) async throws -> MdocNfcHandover {
        try Task.checkCancellation()
        guard NFCTagReaderSession.readingAvailable else {
            throw MdocNfcEngagementError.unavailable
        }

        let operation = MdocNfcReadOperation(alertMessage: alertMessage) { [weak self] operation in
            self?.operationDidFinish(operation)
        }
        lock.lock()
        guard activeOperation == nil else {
            lock.unlock()
            throw MdocNfcEngagementError.readInProgress
        }
        activeOperation = operation
        lock.unlock()

        return try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation {
                (continuation: CheckedContinuation<MdocNfcHandover, Error>) in
                operation.start(continuation: continuation, timeout: timeout)
            }
        }, onCancel: {
            operation.cancel()
        })
    }

    private func operationDidFinish(_ operation: MdocNfcReadOperation) {
        lock.lock()
        if activeOperation === operation {
            activeOperation = nil
        }
        lock.unlock()
    }
}

private final class MdocNfcReadOperation: NSObject, NFCTagReaderSessionDelegate, @unchecked Sendable {
    private typealias ReadResult = Result<MdocNfcHandover, Error>

    private let alertMessage: String
    private let onFinish: (MdocNfcReadOperation) -> Void
    private let callbackQueue = DispatchQueue(label: "foundation.siros.verifier.nfc.type4")
    private let lock = NSLock()

    private var continuation: CheckedContinuation<MdocNfcHandover, Error>?
    private var terminalResult: ReadResult?
    private var finished = false
    private var session: NFCTagReaderSession?
    private var timeoutTask: Task<Void, Never>?

    // The following flow state is accessed only on callbackQueue.
    private var connectionStarted = false
    private var isoTag: NFCISO7816Tag?
    private var chunks: [MdocNfcType4.ReadChunk] = []
    private var nextChunkIndex = 0
    private var rawNDEF: [UInt8] = []

    init(alertMessage: String, onFinish: @escaping (MdocNfcReadOperation) -> Void) {
        self.alertMessage = alertMessage
        self.onFinish = onFinish
        super.init()
    }

    func start(
        continuation: CheckedContinuation<MdocNfcHandover, Error>,
        timeout: TimeInterval
    ) {
        lock.lock()
        if let terminalResult {
            lock.unlock()
            continuation.resume(with: terminalResult)
            return
        }
        self.continuation = continuation

        guard timeout.isFinite, timeout > 0 else {
            lock.unlock()
            finish(.failure(MdocNfcEngagementError.timeout))
            return
        }
        guard let session = NFCTagReaderSession(
            pollingOption: [.iso14443],
            delegate: self,
            queue: callbackQueue
        ) else {
            lock.unlock()
            finish(.failure(MdocNfcEngagementError.unavailable))
            return
        }

        self.session = session
        session.alertMessage = alertMessage
        timeoutTask = Task { [weak self] in
            do {
                try await Task.sleep(nanoseconds: Self.nanoseconds(for: timeout))
            } catch {
                return
            }
            self?.finish(.failure(MdocNfcEngagementError.timeout))
        }
        session.begin()
        lock.unlock()
    }

    func cancel() {
        finish(.failure(CancellationError()))
    }

    private static func nanoseconds(for timeout: TimeInterval) -> UInt64 {
        let value = timeout * 1_000_000_000
        return value >= Double(UInt64.max) ? UInt64.max : UInt64(value)
    }

    private func finish(_ result: ReadResult) {
        lock.lock()
        guard !finished else {
            lock.unlock()
            return
        }
        finished = true
        terminalResult = result
        let continuation = self.continuation
        self.continuation = nil
        let session = self.session
        self.session = nil
        let timeoutTask = self.timeoutTask
        self.timeoutTask = nil
        lock.unlock()

        timeoutTask?.cancel()
        session?.invalidate()
        onFinish(self)
        continuation?.resume(with: result)
    }

    private var isActive: Bool {
        lock.lock()
        defer { lock.unlock() }
        return !finished
    }

    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        finish(.failure(MdocNfcEngagementError.apdu(
            "NFC reader session invalidated: \(error.localizedDescription)"
        )))
    }

    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard isActive, !connectionStarted else { return }
        connectionStarted = true

        for tag in tags {
            guard case let .iso7816(isoTag) = tag else { continue }
            session.connect(to: tag) { [weak self] error in
                guard let self else { return }
                self.callbackQueue.async {
                    self.didConnect(to: isoTag, error: error)
                }
            }
            return
        }
        finish(.failure(MdocNfcEngagementError.noTag))
    }

    private func didConnect(to tag: NFCISO7816Tag, error: Error?) {
        guard isActive else { return }
        if let error {
            finish(.failure(MdocNfcEngagementError.apdu(error.localizedDescription)))
            return
        }
        isoTag = tag
        send(MdocNfcType4.selectNDEFTagApplication) { [weak self] _ in
            self?.selectNDEFDataFile()
        }
    }

    private func selectNDEFDataFile() {
        send(MdocNfcType4.selectNDEFDataFile) { [weak self] _ in
            self?.readNLEN()
        }
    }

    private func readNLEN() {
        send(MdocNfcType4.readNLEN) { [weak self] response in
            guard let self else { return }
            do {
                let length = try MdocNfcType4.parseNLEN(response)
                chunks = try MdocNfcType4.chunkPlan(ndefLength: length)
                rawNDEF.removeAll(keepingCapacity: false)
                rawNDEF.reserveCapacity(length)
                nextChunkIndex = 0
                readNextChunk()
            } catch {
                finish(.failure(error))
            }
        }
    }

    private func readNextChunk() {
        guard nextChunkIndex < chunks.count else {
            parseHandover()
            return
        }

        let chunk = chunks[nextChunkIndex]
        nextChunkIndex += 1
        do {
            let command = try MdocNfcType4.readBinary(offset: chunk.offset, length: chunk.length)
            send(command) { [weak self] response in
                guard let self else { return }
                do {
                    try MdocNfcType4.requireResponseLength(response, expectedLength: chunk.length)
                    rawNDEF.append(contentsOf: response)
                    readNextChunk()
                } catch {
                    finish(.failure(error))
                }
            }
        } catch {
            finish(.failure(error))
        }
    }

    private func parseHandover() {
        do {
            // Preserve the exact bytes read from the tag for both validation and
            // SessionTranscript construction; never re-encode the NDEF records.
            let handover = try MdocNfcHandoverParser.parse(rawNDEF)
            finish(.success(handover))
        } catch {
            finish(.failure(MdocNfcEngagementError.malformed(String(describing: error))))
        }
    }

    private func send(
        _ command: MdocNfcType4.Command,
        completion: @escaping ([UInt8]) -> Void
    ) {
        guard isActive, let isoTag else { return }
        let apdu = NFCISO7816APDU(
            instructionClass: command.instructionClass,
            instructionCode: command.instructionCode,
            p1Parameter: command.p1Parameter,
            p2Parameter: command.p2Parameter,
            data: Data(command.data),
            expectedResponseLength: command.expectedResponseLength
        )
        isoTag.sendCommand(apdu: apdu) { [weak self] responseData, sw1, sw2, error in
            guard let self else { return }
            self.callbackQueue.async {
                guard self.isActive else { return }
                if let error {
                    self.finish(.failure(MdocNfcEngagementError.apdu(error.localizedDescription)))
                    return
                }
                do {
                    try MdocNfcType4.requireSuccess(sw1: sw1, sw2: sw2)
                } catch {
                    self.finish(.failure(error))
                    return
                }
                completion([UInt8](responseData))
            }
        }
    }
}
#endif

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Dispatch
import Foundation

/// A standalone ISO 18013-5 proximity verifier. No wallet or account session is required.
public struct MdocProximityVerifier: Sendable {
    private let pdp: any AuthZenPdp
    private let mdocIssuerRole: String
    private let now: @Sendable () -> Int64
    private let readerFactory: any CoreReaderFactory

    public init(
        pdp: any AuthZenPdp,
        mdocIssuerRole: String = "pid-provider",
        now: @escaping @Sendable () -> Int64 = { Int64(Date().timeIntervalSince1970) }
    ) {
        self.init(
            pdp: pdp,
            mdocIssuerRole: mdocIssuerRole,
            now: now,
            readerFactory: FfiCoreReaderFactory()
        )
    }

    internal init(
        pdp: any AuthZenPdp,
        mdocIssuerRole: String = "pid-provider",
        now: @escaping @Sendable () -> Int64 = { Int64(Date().timeIntervalSince1970) },
        readerFactory: any CoreReaderFactory
    ) {
        self.pdp = pdp
        self.mdocIssuerRole = mdocIssuerRole
        self.now = now
        self.readerFactory = readerFactory
    }

    /// Starts a reader session from exact QR or NFC handover bytes and a verifier-owned request.
    public func start(
        engagement: any MdocEngagement,
        documents: [MdocDocumentRequest]
    ) async throws -> MdocReaderSession {
        let readerFactory = readerFactory
        let deviceEngagement = engagement.deviceEngagementBytes
        let handover = engagement.handoverCbor
        let role = mdocIssuerRole
        let reader = try await CoreIO.run {
            try mapCoreErrors {
                try readerFactory.start(
                    deviceEngagement: deviceEngagement,
                    handover: handover,
                    mdocIssuerRole: role
                )
            }
        }
        return MdocReaderSession(
            reader: reader,
            pdp: pdp,
            now: now,
            initialDocuments: documents
        )
    }
}

/// One serialized reader session. Close it after the elected transport has finished.
///
/// Public operations, including close, are serialized. The native reader is
/// never called on a Swift cooperative executor or the main thread.
public final class MdocReaderSession: @unchecked Sendable {
    private let reader: any CoreReader
    private let pdp: any AuthZenPdp
    private let now: @Sendable () -> Int64
    private let operation = SerializedOperation()
    private var requestedDocuments: [MdocDocumentRequest]
    private var closed = false

    internal init(
        reader: any CoreReader,
        pdp: any AuthZenPdp,
        now: @escaping @Sendable () -> Int64,
        initialDocuments: [MdocDocumentRequest]
    ) {
        self.reader = reader
        self.pdp = pdp
        self.now = now
        self.requestedDocuments = initialDocuments
    }

    deinit {
        // Explicit awaited close is deterministic. This is only a last-resort
        // release for callers that drop an open session.
        if !closed {
            reader.close()
        }
    }

    /// Builds and encrypts the first DeviceRequest while retaining its policy in verifier-core.
    public func establishmentMessage() async throws -> [UInt8] {
        try await operation.withLock {
            try checkOpen()
            let reader = reader
            let documents = requestedDocuments
            return try await CoreIO.run {
                try mapCoreErrors { try reader.establishmentMessage(documents: documents) }
            }
        }
    }

    /// Builds and encrypts a subsequent DeviceRequest and replaces the retained response policy.
    public func dataMessage(documents: [MdocDocumentRequest]) async throws -> [UInt8] {
        try await operation.withLock {
            try checkOpen()
            let reader = reader
            let message = try await CoreIO.run {
                try mapCoreErrors { try reader.dataMessage(documents: documents) }
            }
            requestedDocuments = documents
            return message
        }
    }

    /// Decrypts and verifies a complete SessionData message, enforces the request,
    /// and obtains a go-trust permit for every document before exposing any claims.
    public func openResponse(completeSessionData: [UInt8]) async throws -> MdocReaderInbound {
        try await operation.withLock {
            try checkOpen()
            let reader = reader
            let clock = now
            let acceptedDocTypes = requestedDocuments.map(\.docType).distinctPreservingOrder()
            let coreDocuments: [CoreVerifiedDocument]
            do {
                coreDocuments = try await CoreIO.run {
                    try mapCoreErrors {
                        try reader.openResponse(
                            sessionData: completeSessionData,
                            now: clock(),
                            acceptedDocTypes: acceptedDocTypes
                        )
                    }
                }
            } catch let error as CoreSessionOverError {
                return .sessionOver(status: error.status)
            }

            // No NSLock or dispatch lock is held while the PDP is awaited. Keep
            // the internal core representation until every exact request permits;
            // a later denial or outage therefore cannot expose a partial result.
            for document in coreDocuments {
                guard try await pdp.evaluate(requestJSON: document.authzenRequestJSON) else {
                    throw AuthZenPdpError.denied
                }
            }
            return .verified(documents: coreDocuments.map { document in
                VerifiedMdocDocument(
                    docType: document.docType,
                    elements: document.elements,
                    issuerX5c: document.issuerX5c,
                    validUntil: document.validUntil
                )
            })
        }
    }

    public func terminationMessage() async throws -> [UInt8] {
        try await operation.withLock {
            try checkOpen()
            let reader = reader
            return try await CoreIO.run {
                try mapCoreErrors { try reader.terminationMessage() }
            }
        }
    }

    /// Deterministically releases the native reader after all earlier operations.
    /// Repeated calls have no effect. Operations after close throw `.closed`.
    public func close() async {
        await operation.withLock {
            guard !closed else { return }
            closed = true
            let reader = reader
            // Native destruction also stays off cooperative/main threads.
            await CoreIO.run { reader.close() }
        }
    }

    private func checkOpen() throws {
        guard !closed else { throw MdocReaderSessionError.closed }
    }
}

private func mapCoreErrors<T>(_ operation: () throws -> T) throws -> T {
    do {
        return try operation()
    } catch let error as CoreRejectedError {
        throw MdocVerifierException(code: error.code, detail: error.detail)
    } catch let error as CoreNativeUnavailableError {
        throw MdocVerifierException(code: "native_unavailable", detail: error.detail)
    }
}

private enum CoreIO {
    private static let queue = DispatchQueue(
        label: "org.siros.sdk.verifier.core",
        qos: .userInitiated,
        attributes: .concurrent
    )

    static func run<T: Sendable>(
        _ operation: @escaping @Sendable () -> T
    ) async -> T {
        await withCheckedContinuation { continuation in
            queue.async {
                continuation.resume(returning: operation())
            }
        }
    }

    static func run<T: Sendable>(
        _ operation: @escaping @Sendable () throws -> T
    ) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                continuation.resume(with: Result { try operation() })
            }
        }
    }
}

/// An asynchronous FIFO mutex whose platform lock protects only its own state.
/// In particular, no NSLock is held while an operation or PDP request is awaited.
private final class SerializedOperation: @unchecked Sendable {
    private let lock = NSLock()
    private var busy = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func withLock<T>(_ body: () async throws -> T) async rethrows -> T {
        await acquire()
        defer { release() }
        return try await body()
    }

    private func acquire() async {
        await withCheckedContinuation { continuation in
            lock.lock()
            if busy {
                waiters.append(continuation)
                lock.unlock()
            } else {
                busy = true
                lock.unlock()
                continuation.resume()
            }
        }
    }

    private func release() {
        lock.lock()
        if waiters.isEmpty {
            busy = false
            lock.unlock()
        } else {
            // Ownership passes directly to the next waiter; busy remains true.
            let next = waiters.removeFirst()
            lock.unlock()
            next.resume()
        }
    }
}

private extension Array where Element: Hashable {
    func distinctPreservingOrder() -> [Element] {
        var seen: Set<Element> = []
        return filter { seen.insert($0).inserted }
    }
}

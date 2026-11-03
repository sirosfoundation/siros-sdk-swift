// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

internal protocol MdocBleCandidate: MdocMessageTransport {
    var role: String { get }
    func start()
}

/// Radio-independent reader transport lifecycle. CoreBluetooth subclasses
/// implement discovery plus one framed chunk write/notification; this base
/// owns whole-message I/O, serialization, bounds, timeouts, and cleanup.
internal class MdocBleTransportBase: NSObject, MdocBleCandidate, @unchecked Sendable {
    let role: String

    private let onReady: @Sendable (any MdocBleCandidate) -> Void
    private let onFailure: @Sendable (any MdocBleCandidate, Error) -> Void
    private let readyTimeoutMs: UInt64
    private let ioTimeoutMs: UInt64
    private let incomingQueueLimit: Int

    private let lock = NSLock()
    private let sendMutex = MdocBleAsyncMutex()
    private let receiveMutex = MdocBleAsyncMutex()
    private let reassembler = MdocBleReassembler()

    private var active = true
    private var started = false
    private var ready = false
    private var radioClosed = false
    private var terminalError: Error?
    private var readyTimeoutTask: Task<Void, Never>?
    private var incoming: [[UInt8]] = []
    private var incomingWaiter: CheckedContinuation<Result<[UInt8], Error>, Never>?

    init(
        role: String,
        onReady: @escaping @Sendable (any MdocBleCandidate) -> Void,
        onFailure: @escaping @Sendable (any MdocBleCandidate, Error) -> Void,
        readyTimeoutMs: UInt64 = 60_000,
        ioTimeoutMs: UInt64 = 120_000,
        incomingQueueLimit: Int = 2
    ) {
        self.role = role
        self.onReady = onReady
        self.onFailure = onFailure
        self.readyTimeoutMs = readyTimeoutMs
        self.ioTimeoutMs = ioTimeoutMs
        self.incomingQueueLimit = incomingQueueLimit
        super.init()
    }

    final func start() {
        lock.lock()
        guard active, !started else {
            lock.unlock()
            return
        }
        started = true
        readyTimeoutTask = Task { [weak self] in
            guard let self else { return }
            do {
                try await Task.sleep(nanoseconds: self.readyTimeoutMs * 1_000_000)
            } catch {
                return
            }
            self.fail(MdocBleTransportError.timeout(
                "\(self.role) did not become ready within \(self.readyTimeoutMs) ms"
            ))
        }
        lock.unlock()

        do {
            try startRadio()
        } catch is CancellationError {
            terminate(MdocBleTransportError.closed, notifyFailure: false)
        } catch let error as MdocBleTransportError {
            fail(error)
        } catch {
            fail(MdocBleTransportError.failed("\(role) could not start: \(error.localizedDescription)"))
        }
    }

    final func send(message: [UInt8]) async throws {
        try await withTaskCancellationHandler {
            do {
                try ensureActive()
                guard message.count <= MdocBleProtocol.maximumMessageSize else {
                    throw MdocBleTransportError.messageTooLarge
                }
                try await sendMutex.withLock {
                    try ensureActive()
                    try await withIOTimeout(operation: "send") {
                        let chunks = MdocBleProtocol.chunk(message, maxChunkSize: self.currentMaxChunkSize())
                        for chunk in chunks {
                            try self.ensureActive()
                            try await self.sendChunk(chunk)
                        }
                    }
                }
            } catch {
                if Task.isCancelled {
                    terminate(MdocBleTransportError.closed, notifyFailure: false)
                    throw CancellationError()
                }
                let transportError = asTransportError(error, operation: "send")
                fail(transportError)
                throw terminalFailure(fallback: transportError)
            }
        } onCancel: {
            // Also covers cancellation while queued for the send mutex, before
            // the per-I/O timeout handler below has been entered.
            self.terminate(MdocBleTransportError.closed, notifyFailure: false)
        }
    }

    final func receive() async throws -> [UInt8] {
        try await withTaskCancellationHandler {
            do {
                try ensureActive()
                return try await receiveMutex.withLock {
                    try ensureActive()
                    return try await withIOTimeout(operation: "receive") {
                        try await self.nextIncomingMessage()
                    }
                }
            } catch {
                if Task.isCancelled {
                    terminate(MdocBleTransportError.closed, notifyFailure: false)
                    throw CancellationError()
                }
                let transportError = asTransportError(error, operation: "receive")
                // A peer/disconnect already supplied a more specific terminal error.
                throw terminalFailure(fallback: transportError)
            }
        } onCancel: {
            self.terminate(MdocBleTransportError.closed, notifyFailure: false)
        }
    }

    final func close() async {
        terminate(MdocBleTransportError.closed, notifyFailure: false)
    }

    final func markReady() {
        lock.lock()
        guard active, !ready else {
            lock.unlock()
            return
        }
        ready = true
        let timeout = readyTimeoutTask
        readyTimeoutTask = nil
        lock.unlock()
        timeout?.cancel()
        onReady(self)
    }

    final func fail(_ message: String) {
        fail(MdocBleTransportError.failed("\(role): \(message)"))
    }

    final func fail(_ error: Error) {
        let transportError = error as? MdocBleTransportError
            ?? MdocBleTransportError.failed("\(role): \(error.localizedDescription)")
        terminate(transportError, notifyFailure: true)
    }

    final func acceptIncomingChunk(_ chunk: [UInt8]) {
        var waiter: CheckedContinuation<Result<[UInt8], Error>, Never>?
        var message: [UInt8]?
        var failure: Error?

        lock.lock()
        guard active else {
            lock.unlock()
            return
        }
        do {
            message = try reassembler.feed(chunk)
            if let message {
                if let pending = incomingWaiter {
                    incomingWaiter = nil
                    waiter = pending
                } else if incoming.count < incomingQueueLimit {
                    incoming.append(message)
                } else {
                    failure = MdocBleTransportError.incomingQueueOverflow
                }
            }
        } catch {
            failure = error
        }
        lock.unlock()

        if let failure {
            fail(failure)
        } else if let waiter, let message {
            waiter.resume(returning: .success(message))
        }
    }

    var isActive: Bool {
        lock.lock()
        defer { lock.unlock() }
        return active
    }

    func startRadio() throws {}
    func closeRadio() {}
    func currentMaxChunkSize() -> Int { MdocBleProtocol.defaultMtu - 3 }
    func sendChunk(_ chunk: [UInt8]) async throws {
        throw MdocBleTransportError.failed("BLE radio sending is not implemented")
    }

    private func ensureActive() throws {
        lock.lock()
        let error = active ? nil : (terminalError ?? MdocBleTransportError.closed)
        lock.unlock()
        if let error { throw error }
    }

    private func terminalFailure(fallback: Error) -> Error {
        lock.lock()
        defer { lock.unlock() }
        return terminalError ?? fallback
    }

    private func terminate(_ error: Error, notifyFailure: Bool) {
        var waiter: CheckedContinuation<Result<[UInt8], Error>, Never>?
        var timeout: Task<Void, Never>?
        var shouldCloseRadio = false

        lock.lock()
        if active {
            active = false
            terminalError = error
            timeout = readyTimeoutTask
            readyTimeoutTask = nil
            waiter = incomingWaiter
            incomingWaiter = nil
            incoming.removeAll()
            if !radioClosed {
                radioClosed = true
                shouldCloseRadio = true
            }
        }
        lock.unlock()

        timeout?.cancel()
        waiter?.resume(returning: .failure(error))
        if shouldCloseRadio { closeRadio() }
        if notifyFailure, shouldCloseRadio { onFailure(self, error) }
    }

    private func nextIncomingMessage() async throws -> [UInt8] {
        try await withCheckedContinuation {
            (continuation: CheckedContinuation<Result<[UInt8], Error>, Never>) in
            lock.lock()
            if !active {
                let error = terminalError ?? MdocBleTransportError.closed
                lock.unlock()
                continuation.resume(returning: .failure(error))
            } else if !incoming.isEmpty {
                let message = incoming.removeFirst()
                lock.unlock()
                continuation.resume(returning: .success(message))
            } else if incomingWaiter == nil {
                incomingWaiter = continuation
                lock.unlock()
            } else {
                lock.unlock()
                continuation.resume(returning: .failure(MdocBleTransportError.failed(
                    "Concurrent BLE receive waiters are not supported"
                )))
            }
        }.get()
    }

    private func asTransportError(_ error: Error, operation: String) -> MdocBleTransportError {
        error as? MdocBleTransportError
            ?? MdocBleTransportError.failed("\(role) \(operation) failed: \(error.localizedDescription)")
    }

    private func withIOTimeout<T: Sendable>(
        operation: String,
        body: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await withTaskCancellationHandler {
            try await withThrowingTaskGroup(of: T.self) { group in
                group.addTask { try await body() }
                group.addTask {
                    do {
                        try await Task.sleep(nanoseconds: self.ioTimeoutMs * 1_000_000)
                    } catch {
                        throw CancellationError()
                    }
                    let error = MdocBleTransportError.timeout(
                        "\(self.role) \(operation) timed out after \(self.ioTimeoutMs) ms"
                    )
                    self.fail(error)
                    throw error
                }
                defer { group.cancelAll() }
                guard let result = try await group.next() else {
                    throw MdocBleTransportError.failed("\(role) \(operation) ended without a result")
                }
                return result
            }
        } onCancel: {
            // Checked continuations and CoreBluetooth readiness waits are not
            // implicitly cancellation-aware. Closing resumes both so the task
            // group can finish and rethrow CancellationError to its caller.
            self.terminate(MdocBleTransportError.closed, notifyFailure: false)
        }
    }
}

/// FIFO asynchronous mutex. Platform locks protect only waiter bookkeeping,
/// never a radio call or another awaited operation.
private final class MdocBleAsyncMutex: @unchecked Sendable {
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
            let next = waiters.removeFirst()
            lock.unlock()
            next.resume()
        }
    }
}

/// Bounded hand-off for CoreBluetooth write/notification readiness. The gate
/// re-checks readiness after continuation registration to avoid lost wakeups.
final class MdocBleWriteReadyGate: @unchecked Sendable {
    enum Outcome: Equatable {
        case ready
        case timedOut
        case aborted
        case contended
    }

    private let lock = NSLock()
    private var waiter: CheckedContinuation<Outcome, Never>?
    private var timeoutTask: Task<Void, Never>?
    private var generation: UInt64 = 0
    private var aborted = false

    private var isAborted: Bool {
        lock.lock()
        defer { lock.unlock() }
        return aborted
    }

    func wait(timeoutMs: UInt64, isReady: () -> Bool) async -> Outcome {
        if isAborted { return .aborted }
        if isReady() { return isAborted ? .aborted : .ready }

        return await withCheckedContinuation { continuation in
            lock.lock()
            if aborted {
                lock.unlock()
                continuation.resume(returning: .aborted)
                return
            }
            guard waiter == nil else {
                lock.unlock()
                continuation.resume(returning: .contended)
                return
            }
            generation &+= 1
            let ownGeneration = generation
            waiter = continuation
            if isReady() {
                waiter = nil
                lock.unlock()
                continuation.resume(returning: .ready)
                return
            }
            timeoutTask = Task { [weak self] in
                do {
                    try await Task.sleep(nanoseconds: timeoutMs * 1_000_000)
                } catch {
                    return
                }
                self?.resume(.timedOut, onlyIfGeneration: ownGeneration)
            }
            lock.unlock()
        }
    }

    func signalReady() {
        resume(.ready, onlyIfGeneration: nil)
    }

    func abort() {
        lock.lock()
        aborted = true
        lock.unlock()
        resume(.aborted, onlyIfGeneration: nil)
    }

    private func resume(_ outcome: Outcome, onlyIfGeneration expected: UInt64?) {
        lock.lock()
        guard let waiter, expected == nil || expected == generation else {
            lock.unlock()
            return
        }
        self.waiter = nil
        let timeout = timeoutTask
        timeoutTask = nil
        lock.unlock()
        timeout?.cancel()
        waiter.resume(returning: outcome)
    }
}

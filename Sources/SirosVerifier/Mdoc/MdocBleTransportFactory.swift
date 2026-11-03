// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Starts the reader side of every BLE role offered by an engagement.
///
/// The host application remains responsible for Bluetooth usage descriptions
/// and any permission flow required by its application. No CBOR is sent by the
/// factory or election; send SessionEstablishment only on the elected value.
/// Pure tests cover framing and lifecycle logic; real-device CoreBluetooth
/// interoperability remains a separate validation requirement.
public enum MdocBleTransportFactory {
    public static func start(engagement: any MdocEngagement) throws -> MdocBleTransportElection {
        guard let ble = engagement.ble,
              ble.supportsPeripheralServerMode || ble.supportsCentralClientMode else {
            throw MdocBleTransportError.failed("The engagement offers no supported BLE retrieval role")
        }
        #if os(iOS) && canImport(CoreBluetooth)
        let election = MdocBleTransportElection()
        var candidates: [any MdocBleCandidate] = []
        if ble.supportsPeripheralServerMode {
            guard let serviceUuid = ble.peripheralServerModeUuid else {
                throw MdocBleTransportError.failed("Peripheral-server mode has no engagement UUID")
            }
            candidates.append(MdocBleGattClientTransport(
                serviceUuid: serviceUuid,
                onReady: { [weak election] candidate in election?.candidateReady(candidate) },
                onFailure: { [weak election] candidate, error in election?.candidateFailed(candidate, error: error) }
            ))
        }
        if ble.supportsCentralClientMode {
            guard let serviceUuid = ble.centralClientModeUuid else {
                throw MdocBleTransportError.failed("Central-client mode has no engagement UUID")
            }
            candidates.append(MdocBleGattServerTransport(
                serviceUuid: serviceUuid,
                eDeviceKeyBytes: engagement.eDeviceKeyBytes,
                onReady: { [weak election] candidate in election?.candidateReady(candidate) },
                onFailure: { [weak election] candidate, error in election?.candidateFailed(candidate, error: error) }
            ))
        }
        election.start(candidates)
        return election
        #else
        throw MdocBleTransportError.unsupportedPlatform
        #endif
    }
}

/// One-shot, thread-safe election across all offered BLE roles.
///
/// The first fully connected, STATE_START-ready candidate wins. Every loser
/// is closed before `transport()` returns. Repeated calls return the same
/// winner. Cancelling a waiting call closes all candidates.
public final class MdocBleTransportElection: @unchecked Sendable {
    typealias Candidate = any MdocBleCandidate
    private typealias TransportResult = Result<any MdocMessageTransport, Error>

    private enum Event {
        case ready(Candidate)
        case failed(Candidate, Error)
    }

    private enum CloseAction {
        case drive(transports: [Candidate], tasks: [Task<Void, Never>])
        case wait
        case finished
    }

    private let lock = NSLock()
    private var started = false
    private var registrationFinished = false
    private var drainingEvents = false
    private var events: [Event] = []
    private var pending: [ObjectIdentifier: Candidate] = [:]
    private var closing: Set<ObjectIdentifier> = []
    private var closeTasks: [Task<Void, Never>] = []
    private var failures: [String] = []

    private var elected: Candidate?
    private var result: TransportResult?
    private var resultWaiters: [CheckedContinuation<TransportResult, Never>] = []

    private var closed = false
    private var closeFinished = false
    private var closeError: Error = MdocBleTransportError.closed
    private var closeWaiters: [CheckedContinuation<Void, Never>] = []

    internal init() {}

    /// Suspends until one role is ready or every offered role has failed.
    public func transport() async throws -> any MdocMessageTransport {
        try await withTaskCancellationHandler {
            do {
                try Task.checkCancellation()
            } catch {
                // Even an already-cancelled caller owns cancellation cleanup.
                await close()
                throw error
            }
            return try await withCheckedContinuation {
                (continuation: CheckedContinuation<TransportResult, Never>) in
                lock.lock()
                if let result {
                    lock.unlock()
                    continuation.resume(returning: result)
                } else {
                    resultWaiters.append(continuation)
                    lock.unlock()
                }
            }.get()
        } onCancel: {
            beginCloseFromCancellation()
        }
    }

    /// Deterministically closes pending candidates and any elected transport.
    public func close() async {
        switch takeCloseAction(error: MdocBleTransportError.closed) {
        case .finished:
            return
        case .wait:
            await withCheckedContinuation { continuation in
                lock.lock()
                if closeFinished {
                    lock.unlock()
                    continuation.resume()
                } else {
                    closeWaiters.append(continuation)
                    lock.unlock()
                }
            }
        case .drive(let transports, let tasks):
            await driveClose(transports: transports, tasks: tasks)
        }
    }

    internal func start(_ candidates: [Candidate]) {
        lock.lock()
        precondition(!started, "BLE candidates have already been started")
        precondition(!candidates.isEmpty, "At least one BLE candidate is required")
        started = true
        for candidate in candidates {
            pending[ObjectIdentifier(candidate)] = candidate
        }
        lock.unlock()

        // Registration stays open while every offered role is started. Ready
        // and failure callbacks are queued, so a synchronous first candidate
        // cannot prevent a later offered role from starting.
        for candidate in candidates {
            candidate.start()
        }

        lock.lock()
        registrationFinished = true
        let shouldDrain = shouldDrainLocked()
        lock.unlock()
        if shouldDrain { drainEvents() }
    }

    internal func candidateReady(_ candidate: Candidate) {
        enqueue(.ready(candidate))
    }

    internal func candidateFailed(_ candidate: Candidate, error: Error) {
        enqueue(.failed(candidate, error))
    }

    private func enqueue(_ event: Event) {
        lock.lock()
        events.append(event)
        let shouldDrain = shouldDrainLocked()
        lock.unlock()
        if shouldDrain { drainEvents() }
    }

    private func shouldDrainLocked() -> Bool {
        guard registrationFinished, !drainingEvents, !events.isEmpty else { return false }
        drainingEvents = true
        return true
    }

    private func drainEvents() {
        while true {
            lock.lock()
            guard !events.isEmpty else {
                drainingEvents = false
                lock.unlock()
                return
            }
            let event = events.removeFirst()
            lock.unlock()

            switch event {
            case .ready(let candidate):
                handleReady(candidate)
            case .failed(let candidate, let error):
                handleFailure(candidate, error: error)
            }
        }
    }

    private func handleReady(_ candidate: Candidate) {
        lock.lock()
        let identifier = ObjectIdentifier(candidate)
        guard pending.removeValue(forKey: identifier) != nil else {
            lock.unlock()
            return
        }
        guard !closed, elected == nil, result == nil else {
            if !closing.contains(identifier) {
                closing.insert(identifier)
                let task = Task { await candidate.close() }
                closeTasks.append(task)
            }
            lock.unlock()
            return
        }

        elected = candidate
        var losers: [Candidate] = []
        for (key, loser) in pending where !closing.contains(key) {
            closing.insert(key)
            losers.append(loser)
        }
        pending.removeAll()
        // Register the cleanup task while holding the state lock. A concurrent
        // close therefore always observes and awaits this same task rather
        // than closing a loser twice or returning before its cleanup ends.
        let task = Task {
            await Self.closeAll(losers)
            self.completeElection(candidate)
        }
        closeTasks.append(task)
        lock.unlock()
    }

    private func completeElection(_ candidate: Candidate) {
        var waiters: [CheckedContinuation<TransportResult, Never>] = []
        lock.lock()
        if !closed, result == nil, elected != nil,
           ObjectIdentifier(elected!) == ObjectIdentifier(candidate) {
            result = .success(candidate)
            waiters = resultWaiters
            resultWaiters.removeAll()
        }
        lock.unlock()
        for waiter in waiters { waiter.resume(returning: .success(candidate)) }
    }

    private func handleFailure(_ candidate: Candidate, error: Error) {
        var terminalError: Error?
        var waiters: [CheckedContinuation<TransportResult, Never>] = []

        lock.lock()
        let identifier = ObjectIdentifier(candidate)
        if !closed, elected == nil, result == nil,
           pending.removeValue(forKey: identifier) != nil {
            failures.append("\(candidate.role): \(error.localizedDescription)")
            if registrationFinished, pending.isEmpty {
                let detail = failures.joined(separator: "; ")
                let failure = MdocBleTransportError.noReadyTransport(detail)
                result = .failure(failure)
                waiters = resultWaiters
                resultWaiters.removeAll()
                terminalError = failure
            }
        }
        lock.unlock()

        if let terminalError {
            for waiter in waiters { waiter.resume(returning: .failure(terminalError)) }
        }
    }

    private func takeCloseAction(error: Error) -> CloseAction {
        lock.lock()
        if closeFinished {
            lock.unlock()
            return .finished
        }
        if closed {
            lock.unlock()
            return .wait
        }

        closed = true
        closeError = error
        var transports: [Candidate] = []
        if let elected, !closing.contains(ObjectIdentifier(elected)) {
            closing.insert(ObjectIdentifier(elected))
            transports.append(elected)
        }
        for (identifier, candidate) in pending where !closing.contains(identifier) {
            closing.insert(identifier)
            transports.append(candidate)
        }
        pending.removeAll()
        let action = CloseAction.drive(transports: transports, tasks: closeTasks)
        lock.unlock()
        return action
    }

    private func beginCloseFromCancellation() {
        guard case .drive(let transports, let tasks) = takeCloseAction(error: CancellationError()) else {
            return
        }
        Task {
            await self.driveClose(transports: transports, tasks: tasks)
        }
    }

    private func driveClose(transports: [Candidate], tasks: [Task<Void, Never>]) async {
        for task in tasks { await task.value }
        await Self.closeAll(transports)

        var resultWaiters: [CheckedContinuation<TransportResult, Never>] = []
        var closeWaiters: [CheckedContinuation<Void, Never>] = []
        lock.lock()
        if !closeFinished {
            closeFinished = true
            result = .failure(closeError)
            resultWaiters = self.resultWaiters
            self.resultWaiters.removeAll()
            closeWaiters = self.closeWaiters
            self.closeWaiters.removeAll()
        }
        let error = closeError
        lock.unlock()

        for waiter in resultWaiters { waiter.resume(returning: .failure(error)) }
        for waiter in closeWaiters { waiter.resume() }
    }

    private static func closeAll(_ transports: [Candidate]) async {
        for transport in transports {
            await transport.close()
        }
    }
}

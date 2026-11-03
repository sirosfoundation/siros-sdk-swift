// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosVerifier
@testable import SirosSampleApp

/// These tests exercise only the sample verifier coordinator with injected
/// engagements/sessions/transports. They are not native verifier-core, PDP,
/// CoreNFC, BLE-radio, or two-device interoperability tests.
@MainActor
final class VerifierViewModelTests: XCTestCase {
    func testInvalidQRClearsStaleClaimsWithoutStartingSessionOrElection() async throws {
        let environment = FakeVerifierEnvironment()
        let viewModel = makeViewModel(environment: environment, engagementProducer: nil)
        viewModel.claims = [Self.staleClaim]

        let task = try XCTUnwrap(viewModel.start(qrCode: "https://example.invalid/not-an-mdoc"))
        // Clearing is synchronous: it does not wait for parsing or any I/O.
        XCTAssertTrue(viewModel.claims.isEmpty)
        await task.value

        XCTAssertEqual(environment.sessionStartCount, 0)
        XCTAssertEqual(environment.electionStartCount, 0)
        XCTAssertTrue(viewModel.claims.isEmpty)
        guard case .failed = viewModel.phase else {
            return XCTFail("Expected invalid QR failure, got \(viewModel.phase)")
        }
        XCTAssertFalse(viewModel.isRunning)
    }

    func testNfcTimeoutIsAClaimsFreeErrorAndDoesNotStartCoreOrBle() async throws {
        let environment = FakeVerifierEnvironment()
        let viewModel = makeViewModel(
            environment: environment,
            nfcEngagementProducer: { throw MdocNfcEngagementError.timeout }
        )
        viewModel.claims = [Self.staleClaim]

        let task = try XCTUnwrap(viewModel.startNfc())
        await task.value

        XCTAssertEqual(environment.sessionStartCount, 0)
        XCTAssertEqual(environment.electionStartCount, 0)
        XCTAssertTrue(viewModel.claims.isEmpty)
        guard case .failed(let message) = viewModel.phase else {
            return XCTFail("Expected NFC timeout failure, got \(viewModel.phase)")
        }
        XCTAssertTrue(message.contains("timed out"))
        XCTAssertTrue(message.contains("No claims"))
    }

    func testNfcUnavailableIsAClaimsFreeUnsupportedError() async throws {
        let environment = FakeVerifierEnvironment()
        let viewModel = makeViewModel(
            environment: environment,
            nfcEngagementProducer: { throw MdocNfcEngagementError.unavailable }
        )
        viewModel.claims = [Self.staleClaim]

        let task = try XCTUnwrap(viewModel.startNfc())
        await task.value

        XCTAssertTrue(viewModel.claims.isEmpty)
        guard case .failed(let message) = viewModel.phase else {
            return XCTFail("Expected NFC unavailable failure, got \(viewModel.phase)")
        }
        XCTAssertTrue(message.contains("unavailable"))
        XCTAssertTrue(message.contains("No claims"))
        XCTAssertEqual(environment.sessionStartCount, 0)
        XCTAssertEqual(environment.electionStartCount, 0)
    }

    func testCancellationDuringNfcHandoverFinishesWithoutStartingCoreOrBle() async throws {
        let nfcStarted = expectation(description: "fake NFC handover is pending")
        let nfc = FakeNfcEngagementProducer(started: nfcStarted)
        let environment = FakeVerifierEnvironment()
        let viewModel = makeViewModel(
            environment: environment,
            nfcEngagementProducer: { try await nfc.readHandover() }
        )
        viewModel.claims = [Self.staleClaim]

        _ = viewModel.startNfc()
        await fulfillment(of: [nfcStarted], timeout: 2)
        await viewModel.cancel()

        XCTAssertEqual(nfc.closeCount, 1)
        XCTAssertEqual(environment.sessionStartCount, 0)
        XCTAssertEqual(environment.electionStartCount, 0)
        XCTAssertEqual(viewModel.phase, .idle)
        XCTAssertTrue(viewModel.claims.isEmpty)
        XCTAssertFalse(viewModel.isRunning)
    }

    func testNfcEngagementUsesTheSameCoreSessionAndBlePath() async throws {
        let environment = FakeVerifierEnvironment(response: .sessionOver)
        let viewModel = makeViewModel(environment: environment)

        let task = try XCTUnwrap(viewModel.startNfc())
        await task.value

        XCTAssertEqual(environment.sessionStartCount, 1)
        XCTAssertEqual(environment.electionStartCount, 1)
        XCTAssertEqual(environment.transport.sentMessages, [[0xA1, 0xA2]])
        XCTAssertEqual(viewModel.phase, .sessionOver(20))
        XCTAssertTrue(viewModel.claims.isEmpty)
        XCTAssertEqual(environment.transport.closeCount, 1)
        XCTAssertEqual(environment.election.closeCount, 1)
        XCTAssertEqual(environment.session.closeCount, 1)
    }

    func testSessionOverUsesDefaultMdlRequestAndClosesEverythingWithoutClaims() async throws {
        let environment = FakeVerifierEnvironment(response: .sessionOver)
        let viewModel = makeViewModel(environment: environment)
        viewModel.claims = [Self.staleClaim]

        let task = try XCTUnwrap(viewModel.start(qrCode: "fake-qr"))
        await task.value

        XCTAssertEqual(environment.sessionStartCount, 1)
        XCTAssertEqual(environment.electionStartCount, 1)
        XCTAssertEqual(viewModel.phase, .sessionOver(20))
        XCTAssertTrue(viewModel.claims.isEmpty)

        let documents = environment.requestedDocuments
        XCTAssertEqual(documents.count, 1)
        XCTAssertEqual(documents.first?.docType, "org.iso.18013.5.1.mDL")
        XCTAssertEqual(documents.first?.namespaces.count, 1)
        XCTAssertEqual(documents.first?.namespaces.first?.namespace, "org.iso.18013.5.1")
        XCTAssertEqual(
            documents.first?.namespaces.first?.elements.map(\.identifier),
            ["given_name", "family_name"]
        )
        XCTAssertEqual(
            documents.first?.namespaces.first?.elements.map(\.intentToRetain),
            [false, false]
        )

        XCTAssertEqual(environment.transport.sentMessages, [[0xA1, 0xA2]])
        XCTAssertEqual(environment.transport.closeCount, 1)
        XCTAssertEqual(environment.election.closeCount, 1)
        XCTAssertEqual(environment.session.closeCount, 1)
        XCTAssertFalse(viewModel.isRunning)
    }

    func testPdpDenialDoesNotExposeClaimsAndStillCleansUp() async throws {
        let environment = FakeVerifierEnvironment(response: .denied)
        let viewModel = makeViewModel(environment: environment)
        viewModel.claims = [Self.staleClaim]

        let task = try XCTUnwrap(viewModel.start(qrCode: "fake-qr"))
        await task.value

        guard case .denied = viewModel.phase else {
            return XCTFail("Expected a go-trust denial, got \(viewModel.phase)")
        }
        XCTAssertTrue(viewModel.claims.isEmpty)
        XCTAssertEqual(environment.transport.closeCount, 1)
        XCTAssertEqual(environment.election.closeCount, 1)
        XCTAssertEqual(environment.session.closeCount, 1)
    }

    func testCancellationDuringReceiveAwaitsDeterministicCleanup() async throws {
        let receiveStarted = expectation(description: "fake transport is waiting for a response")
        let environment = FakeVerifierEnvironment(receiveStarted: receiveStarted)
        let viewModel = makeViewModel(environment: environment)
        viewModel.claims = [Self.staleClaim]

        _ = viewModel.start(qrCode: "fake-qr")
        await fulfillment(of: [receiveStarted], timeout: 2)
        await viewModel.cancel()

        XCTAssertEqual(viewModel.phase, .idle)
        XCTAssertTrue(viewModel.claims.isEmpty)
        XCTAssertEqual(environment.transport.closeCount, 1)
        XCTAssertEqual(environment.election.closeCount, 1)
        XCTAssertEqual(environment.session.closeCount, 1)
        XCTAssertFalse(viewModel.isRunning)
    }

    private func makeViewModel(
        environment: FakeVerifierEnvironment,
        engagementProducer: VerifierEngagementProducer? = { _ in FakeEngagement() },
        nfcEngagementProducer: VerifierNfcEngagementProducer? = { FakeEngagement() }
    ) -> VerifierViewModel {
        let suiteName = "VerifierViewModelTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        addTeardownBlock {
            defaults.removePersistentDomain(forName: suiteName)
        }
        let viewModel = VerifierViewModel(
            defaults: defaults,
            environment: [:],
            engagementProducer: engagementProducer,
            nfcEngagementProducer: nfcEngagementProducer,
            sessionFactory: { engagement, documents, endpoint, tenant in
                await environment.makeSession(
                    engagement: engagement,
                    documents: documents,
                    evaluationEndpoint: endpoint,
                    tenantId: tenant
                )
            },
            electionFactory: { engagement in
                environment.makeElection(engagement: engagement)
            }
        )
        viewModel.evaluationEndpoint = "https://trust.example/v1/evaluate"
        viewModel.tenantId = "test-tenant"
        return viewModel
    }

    private static let staleClaim = MdocVerifierClaim(
        id: "stale",
        docType: "org.iso.18013.5.1.mDL",
        namespace: "org.iso.18013.5.1",
        identifier: "given_name",
        value: "STALE"
    )
}

private struct FakeEngagement: MdocEngagement {
    let deviceEngagementBytes: [UInt8] = [0x01]
    let eDeviceKeyBytes: [UInt8] = [0x02]
    let handoverCbor: [UInt8] = [0xF6]
    let ble: MdocQrEngagement.BleRetrievalMetadata? = nil
}

private final class FakeNfcEngagementProducer: @unchecked Sendable {
    private let started: XCTestExpectation
    private let lock = NSLock()
    private var waiter: CheckedContinuation<any MdocEngagement, Error>?
    private var cancelled = false
    private var _closeCount = 0

    init(started: XCTestExpectation) {
        self.started = started
    }

    func readHandover() async throws -> any MdocEngagement {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation {
                (continuation: CheckedContinuation<any MdocEngagement, Error>) in
                lock.lock()
                if cancelled {
                    lock.unlock()
                    continuation.resume(throwing: CancellationError())
                } else {
                    waiter = continuation
                    lock.unlock()
                    started.fulfill()
                }
            }
        } onCancel: {
            cancel()
        }
    }

    private func cancel() {
        lock.lock()
        guard !cancelled else {
            lock.unlock()
            return
        }
        cancelled = true
        _closeCount += 1
        let waiter = self.waiter
        self.waiter = nil
        lock.unlock()
        waiter?.resume(throwing: CancellationError())
    }

    var closeCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return _closeCount
    }
}

private enum FakeResponse {
    case sessionOver
    case denied
}

/// Method references from this probe form the ViewModel's injectable factories.
/// No call reaches MdocProximityVerifier, verifier-core, CoreNFC, CoreBluetooth,
/// or a wallet object in these tests.
private final class FakeVerifierEnvironment: @unchecked Sendable {
    let session: FakeReaderSession
    let transport: FakeMessageTransport
    let election: FakeTransportElection

    private let lock = NSLock()
    private var _sessionStartCount = 0
    private var _electionStartCount = 0
    private var _requestedDocuments: [MdocDocumentRequest] = []

    init(
        response: FakeResponse = .sessionOver,
        receiveStarted: XCTestExpectation? = nil
    ) {
        let transport = FakeMessageTransport(receiveStarted: receiveStarted)
        self.session = FakeReaderSession(response: response)
        self.transport = transport
        self.election = FakeTransportElection(transport: transport)
    }

    func makeSession(
        engagement: any MdocEngagement,
        documents: [MdocDocumentRequest],
        evaluationEndpoint: URL,
        tenantId: String
    ) async -> any VerifierReaderSession {
        recordSessionStart(documents: documents)
        return session
    }

    private func recordSessionStart(documents: [MdocDocumentRequest]) {
        lock.lock()
        _sessionStartCount += 1
        _requestedDocuments = documents
        lock.unlock()
    }

    func makeElection(engagement: any MdocEngagement) -> any VerifierTransportElection {
        lock.lock()
        _electionStartCount += 1
        lock.unlock()
        return election
    }

    var sessionStartCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return _sessionStartCount
    }

    var electionStartCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return _electionStartCount
    }

    var requestedDocuments: [MdocDocumentRequest] {
        lock.lock()
        defer { lock.unlock() }
        return _requestedDocuments
    }
}

private final class FakeReaderSession: VerifierReaderSession, @unchecked Sendable {
    private let response: FakeResponse
    private let lock = NSLock()
    private var closed = false
    private var _closeCount = 0

    init(response: FakeResponse) {
        self.response = response
    }

    func establishmentMessage() async throws -> [UInt8] {
        [0xA1, 0xA2]
    }

    func openResponse(completeSessionData: [UInt8]) async throws -> MdocReaderInbound {
        switch response {
        case .sessionOver:
            return .sessionOver(status: 20)
        case .denied:
            throw AuthZenPdpError.denied
        }
    }

    func terminationMessage() async throws -> [UInt8] {
        [0xF6]
    }

    func close() async {
        closeResources()
    }

    private func closeResources() {
        lock.lock()
        defer { lock.unlock() }
        guard !closed else { return }
        closed = true
        _closeCount += 1
    }

    var closeCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return _closeCount
    }
}

private final class FakeTransportElection: VerifierTransportElection, @unchecked Sendable {
    private let electedTransport: FakeMessageTransport
    private let lock = NSLock()
    private var closed = false
    private var _closeCount = 0

    init(transport: FakeMessageTransport) {
        self.electedTransport = transport
    }

    func transport() async throws -> any MdocMessageTransport {
        electedTransport
    }

    func close() async {
        closeResources()
    }

    private func closeResources() {
        lock.lock()
        defer { lock.unlock() }
        guard !closed else { return }
        closed = true
        _closeCount += 1
    }

    var closeCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return _closeCount
    }
}

private final class FakeMessageTransport: MdocMessageTransport, @unchecked Sendable {
    private enum Failure: Error {
        case closed
    }

    private let receiveStarted: XCTestExpectation?
    private let lock = NSLock()
    private var incoming: [[UInt8]]
    private var waiter: CheckedContinuation<[UInt8], Error>?
    private var closed = false
    private var _closeCount = 0
    private var _sentMessages: [[UInt8]] = []

    init(receiveStarted: XCTestExpectation? = nil) {
        self.receiveStarted = receiveStarted
        // With no cancellation expectation, return one complete fake
        // SessionData value. With it, remain pending until close/cancel.
        self.incoming = receiveStarted == nil ? [[0x01]] : []
    }

    func send(message: [UInt8]) async throws {
        try sendSynchronously(message: message)
    }

    private func sendSynchronously(message: [UInt8]) throws {
        lock.lock()
        defer { lock.unlock() }
        guard !closed else { throw Failure.closed }
        _sentMessages.append(message)
    }

    func receive() async throws -> [UInt8] {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation {
                (continuation: CheckedContinuation<[UInt8], Error>) in
                lock.lock()
                if closed {
                    lock.unlock()
                    continuation.resume(throwing: Failure.closed)
                } else if !incoming.isEmpty {
                    let message = incoming.removeFirst()
                    lock.unlock()
                    continuation.resume(returning: message)
                } else {
                    waiter = continuation
                    lock.unlock()
                    receiveStarted?.fulfill()
                }
            }
        } onCancel: {
            closeLockedResources()
        }
    }

    func close() async {
        closeLockedResources()
    }

    private func closeLockedResources() {
        lock.lock()
        guard !closed else {
            lock.unlock()
            return
        }
        closed = true
        _closeCount += 1
        let waiter = self.waiter
        self.waiter = nil
        lock.unlock()
        waiter?.resume(throwing: CancellationError())
    }

    var sentMessages: [[UInt8]] {
        lock.lock()
        defer { lock.unlock() }
        return _sentMessages
    }

    var closeCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return _closeCount
    }
}

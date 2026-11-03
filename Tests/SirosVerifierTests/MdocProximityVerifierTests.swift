// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosVerifier

final class MdocProximityVerifierTests: XCTestCase {
    func testStartPreservesEngagementRoleAndRequest() async throws {
        let core = FakeCoreReader()
        let factory = FakeFactory(reader: core)
        let verifier = MdocProximityVerifier(
            pdp: FakePdp(),
            mdocIssuerRole: "mdl-issuer",
            now: { 123 },
            readerFactory: factory
        )
        let engagement = try engagement()
        let session = try await verifier.start(engagement: engagement, documents: [request()])

        XCTAssertEqual(factory.deviceEngagement, engagement.deviceEngagementBytes)
        XCTAssertEqual(factory.handover, [0xF6])
        XCTAssertEqual(factory.role, "mdl-issuer")
        let establishmentMessage = try await session.establishmentMessage()
        XCTAssertEqual(establishmentMessage, [1])
        XCTAssertEqual(core.establishmentDocuments?.count, 1)
        XCTAssertEqual(core.establishmentDocuments?.first?.docType, request().docType)
        XCTAssertEqual(core.establishmentDocuments?.first?.namespaces, request().namespaces)
        let terminationMessage = try await session.terminationMessage()
        XCTAssertEqual(terminationMessage, [3])
        await session.close()
        XCTAssertTrue(core.closed)
    }

    func testDefaultRoleIsPidProvider() async throws {
        let core = FakeCoreReader()
        let factory = FakeFactory(reader: core)
        // Public construction uses the native factory; this internal overload
        // changes only that factory and retains all public defaults.
        let verifier = MdocProximityVerifier(pdp: FakePdp(), readerFactory: factory)
        let session = try await verifier.start(engagement: engagement(), documents: [request()])

        XCTAssertEqual(factory.role, "pid-provider")
        await session.close()
    }

    func testOpenResponseEvaluatesExactAuthzenBeforeMappingClaims() async throws {
        let pdp = FakePdp()
        let core = FakeCoreReader()
        core.response = [coreDocument(authzen: "authzen-request")]
        let session = makeSession(core: core, pdp: pdp)

        let inbound = try await session.openResponse(completeSessionData: [9])

        XCTAssertEqual(pdp.evaluations, ["authzen-request"])
        XCTAssertEqual(core.acceptedDocTypes, ["org.iso.18013.5.1.mDL"])
        XCTAssertEqual(core.now, 123)
        XCTAssertEqual(core.sessionData, [9])
        guard case .verified(let documents) = inbound else {
            return XCTFail("expected verified documents")
        }
        XCTAssertEqual(documents.count, 1)
        XCTAssertEqual(documents[0].docType, "org.iso.18013.5.1.mDL")
        XCTAssertEqual(documents[0].elements, [
            VerifiedMdocElement(namespace: "org.iso.18013.5.1", identifier: "given_name", valueCbor: [7]),
        ])
        XCTAssertEqual(documents[0].issuerX5c, [[8]])
        XCTAssertEqual(documents[0].validUntil, 456)
        await session.close()
    }

    func testExplicitDenialReturnsNoClaims() async throws {
        let core = FakeCoreReader()
        core.response = [coreDocument(authzen: "deny-this")]
        let session = makeSession(core: core, pdp: FakePdp { _ in
            throw AuthZenPdpError.denied
        })

        do {
            _ = try await session.openResponse(completeSessionData: [9])
            XCTFail("denial must not expose claims")
        } catch AuthZenPdpError.denied {
            // Expected.
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        await session.close()
    }

    func testPdpOutageReturnsNoClaims() async throws {
        let core = FakeCoreReader()
        core.response = [coreDocument(authzen: "outage")]
        let session = makeSession(core: core, pdp: FakePdp { _ in
            throw AuthZenPdpError.network(underlying: URLError(.notConnectedToInternet))
        })

        do {
            _ = try await session.openResponse(completeSessionData: [9])
            XCTFail("outage must not expose claims")
        } catch AuthZenPdpError.network(let underlying) {
            XCTAssertEqual((underlying as? URLError)?.code, .notConnectedToInternet)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        await session.close()
    }

    func testLaterDenialDoesNotReturnPartiallyAcceptedDocuments() async throws {
        let core = FakeCoreReader()
        core.response = [coreDocument(authzen: "permit"), coreDocument(authzen: "deny")]
        let pdp = FakePdp { request in
            if request == "deny" { throw AuthZenPdpError.denied }
            return true
        }
        let session = makeSession(core: core, pdp: pdp)

        do {
            _ = try await session.openResponse(completeSessionData: [9])
            XCTFail("a later denial must not return the first document")
        } catch AuthZenPdpError.denied {
            // Expected.
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        XCTAssertEqual(pdp.evaluations, ["permit", "deny"])
        await session.close()
    }

    func testFalseDecisionAlsoFailsClosed() async throws {
        let core = FakeCoreReader()
        let session = makeSession(core: core, pdp: FakePdp { _ in false })

        do {
            _ = try await session.openResponse(completeSessionData: [9])
            XCTFail("a non-permit result must not expose claims")
        } catch AuthZenPdpError.denied {
            // Expected even for a PDP implementation that violates the throws-on-deny convention.
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        await session.close()
    }

    func testPeerTerminationIsDataNotCryptographicFailure() async throws {
        let core = FakeCoreReader()
        core.sessionOverStatus = 20
        let session = makeSession(core: core)

        let inbound = try await session.openResponse(completeSessionData: [9])

        XCTAssertEqual(inbound, .sessionOver(status: 20))
        await session.close()
    }

    func testCoreRejectionKeepsItsStableCode() async throws {
        let core = FakeCoreReader()
        core.rejection = CoreRejectedError(code: "integrity", detail: "bad mac")
        let session = makeSession(core: core)

        do {
            _ = try await session.openResponse(completeSessionData: [9])
            XCTFail("expected core rejection")
        } catch let error as MdocVerifierException {
            XCTAssertEqual(error.code, "integrity")
            XCTAssertEqual(error.detail, "bad mac")
            XCTAssertEqual(error.description, "integrity: bad mac")
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        await session.close()
    }

    func testDataMessageForwardsReplacementAndAcceptedTypesFollowIt() async throws {
        let core = FakeCoreReader()
        let session = makeSession(core: core)
        let replacement = MdocDocumentRequest(
            docType: "eu.europa.ec.eudi.pid.1",
            namespaces: [MdocRequestedNamespace(
                namespace: "eu.europa.ec.eudi.pid.1",
                elements: [MdocRequestedElement(identifier: "age_over_18", intentToRetain: true)]
            )]
        )

        let message = try await session.dataMessage(documents: [replacement, replacement])
        XCTAssertEqual(message, [2])
        XCTAssertEqual(core.dataDocuments?.count, 2)
        XCTAssertEqual(core.dataDocuments?.first?.namespaces, replacement.namespaces)
        _ = try await session.openResponse(completeSessionData: [9])
        XCTAssertEqual(core.acceptedDocTypes, ["eu.europa.ec.eudi.pid.1"])
        await session.close()
    }

    func testOperationsStaySerializedAcrossPdpAwait() async throws {
        let core = FakeCoreReader()
        let pdpStarted = AsyncTestGate()
        let permit = AsyncTestGate()
        let session = makeSession(core: core, pdp: FakePdp { _ in
            pdpStarted.open()
            await permit.wait()
            return true
        })

        let responseTask = Task { try await session.openResponse(completeSessionData: [9]) }
        await pdpStarted.wait()
        let terminationTask = Task { try await session.terminationMessage() }
        for _ in 0..<10 { await Task.yield() }
        XCTAssertEqual(core.terminationCalls, 0, "a native operation overtook the pending PDP decision")

        permit.open()
        _ = try await responseTask.value
        let terminationMessage = try await terminationTask.value
        XCTAssertEqual(terminationMessage, [3])
        XCTAssertEqual(core.terminationCalls, 1)
        await session.close()
    }

    @MainActor
    func testNativeCallsAreMovedOffMainThread() async throws {
        let core = FakeCoreReader()
        let factory = FakeFactory(reader: core)
        let verifier = MdocProximityVerifier(
            pdp: FakePdp(),
            mdocIssuerRole: "mdl-issuer",
            now: { 123 },
            readerFactory: factory
        )
        let session = try await verifier.start(engagement: engagement(), documents: [request()])
        _ = try await session.establishmentMessage()
        _ = try await session.openResponse(completeSessionData: [9])
        _ = try await session.terminationMessage()
        await session.close()

        XCTAssertTrue(Thread.isMainThread)
        XCTAssertEqual(factory.mainThreadCallCount, 0)
        XCTAssertEqual(core.mainThreadCallCount, 0)
    }

    func testCloseIsIdempotentAndLaterOperationsFail() async throws {
        let core = FakeCoreReader()
        let session = makeSession(core: core)

        await session.close()
        await session.close()

        XCTAssertTrue(core.closed)
        XCTAssertEqual(core.closeCalls, 1)
        do {
            _ = try await session.terminationMessage()
            XCTFail("closed session accepted an operation")
        } catch MdocReaderSessionError.closed {
            // Expected.
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    private func makeSession(
        core: FakeCoreReader,
        pdp: FakePdp = FakePdp()
    ) -> MdocReaderSession {
        MdocReaderSession(reader: core, pdp: pdp, now: { 123 }, initialDocuments: [request()])
    }

    private func request() -> MdocDocumentRequest {
        MdocDocumentRequest(
            docType: "org.iso.18013.5.1.mDL",
            namespaces: [MdocRequestedNamespace(
                namespace: "org.iso.18013.5.1",
                elements: [MdocRequestedElement(identifier: "given_name")]
            )]
        )
    }

    private func engagement() throws -> MdocQrEngagement {
        try MdocQrEngagement.parse(Self.goldenEngagementURI)
    }

    private func coreDocument(authzen: String) -> CoreVerifiedDocument {
        CoreVerifiedDocument(
            docType: "org.iso.18013.5.1.mDL",
            elements: [VerifiedMdocElement(
                namespace: "org.iso.18013.5.1",
                identifier: "given_name",
                valueCbor: [7]
            )],
            issuerX5c: [[8]],
            validUntil: 456,
            authzenRequestJSON: authzen
        )
    }

    private static let goldenEngagementURI = "mdoc:owKBgwIBpAD1AfUKUAARIjNEVWZ3iJmqu8zd7v8LUP_u3cy7qpmId2ZVRDMiEQAAYzEuMAGCAdgYWEukAQIgASFYIGsX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWIlggT-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"
}

private final class AsyncTestGate: @unchecked Sendable {
    private let lock = NSLock()
    private var isOpen = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        await withCheckedContinuation { continuation in
            lock.lock()
            if isOpen {
                lock.unlock()
                continuation.resume()
            } else {
                waiters.append(continuation)
                lock.unlock()
            }
        }
    }

    func open() {
        lock.lock()
        isOpen = true
        let continuations = waiters
        waiters.removeAll()
        lock.unlock()
        continuations.forEach { $0.resume() }
    }
}

private final class FakePdp: AuthZenPdp, @unchecked Sendable {
    private let handler: @Sendable (String) async throws -> Bool
    private let lock = NSLock()
    private var requests: [String] = []

    init(handler: @escaping @Sendable (String) async throws -> Bool = { _ in true }) {
        self.handler = handler
    }

    var evaluations: [String] {
        lock.lock()
        defer { lock.unlock() }
        return requests
    }

    func evaluate(requestJSON: String) async throws -> Bool {
        record(requestJSON)
        return try await handler(requestJSON)
    }

    private func record(_ requestJSON: String) {
        lock.lock()
        requests.append(requestJSON)
        lock.unlock()
    }
}

private final class FakeFactory: CoreReaderFactory, @unchecked Sendable {
    private let reader: any CoreReader
    private(set) var deviceEngagement: [UInt8]?
    private(set) var handover: [UInt8]?
    private(set) var role: String?
    private(set) var mainThreadCallCount = 0

    init(reader: any CoreReader) {
        self.reader = reader
    }

    func start(
        deviceEngagement: [UInt8],
        handover: [UInt8],
        mdocIssuerRole: String
    ) throws -> any CoreReader {
        if Thread.isMainThread { mainThreadCallCount += 1 }
        self.deviceEngagement = deviceEngagement
        self.handover = handover
        role = mdocIssuerRole
        return reader
    }
}

private final class FakeCoreReader: CoreReader, @unchecked Sendable {
    var establishmentDocuments: [MdocDocumentRequest]?
    var dataDocuments: [MdocDocumentRequest]?
    var acceptedDocTypes: [String]?
    var now: Int64?
    var sessionData: [UInt8]?
    var response: [CoreVerifiedDocument]
    var rejection: CoreRejectedError?
    var sessionOverStatus: UInt64?
    private(set) var closed = false
    private(set) var closeCalls = 0
    private(set) var terminationCalls = 0
    private(set) var mainThreadCallCount = 0

    init() {
        response = [CoreVerifiedDocument(
            docType: "org.iso.18013.5.1.mDL",
            elements: [VerifiedMdocElement(
                namespace: "org.iso.18013.5.1",
                identifier: "given_name",
                valueCbor: [7]
            )],
            issuerX5c: [[8]],
            validUntil: 456,
            authzenRequestJSON: "authzen"
        )]
    }

    func establishmentMessage(documents: [MdocDocumentRequest]) throws -> [UInt8] {
        recordThread()
        establishmentDocuments = documents
        return [1]
    }

    func dataMessage(documents: [MdocDocumentRequest]) throws -> [UInt8] {
        recordThread()
        dataDocuments = documents
        return [2]
    }

    func openResponse(
        sessionData: [UInt8],
        now: Int64,
        acceptedDocTypes: [String]
    ) throws -> [CoreVerifiedDocument] {
        recordThread()
        self.sessionData = sessionData
        self.now = now
        self.acceptedDocTypes = acceptedDocTypes
        if let rejection { throw rejection }
        if let sessionOverStatus { throw CoreSessionOverError(status: sessionOverStatus) }
        return response
    }

    func terminationMessage() throws -> [UInt8] {
        recordThread()
        terminationCalls += 1
        return [3]
    }

    func close() {
        recordThread()
        closed = true
        closeCalls += 1
    }

    private func recordThread() {
        if Thread.isMainThread { mainThreadCallCount += 1 }
    }
}

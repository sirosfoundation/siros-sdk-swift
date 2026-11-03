// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosVerifier

/// Pure election tests. Radio behavior is deliberately left to device testing.
final class MdocBleTransportElectionTests: XCTestCase {
    func testStartsEveryRoleAndClosesLoserBeforeReturningWinner() async throws {
        let election = MdocBleTransportElection()
        let client = FakeMdocBleCandidate(role: "client")
        let server = FakeMdocBleCandidate(role: "server")
        election.start([client, server])

        XCTAssertEqual(client.startCalls, 1)
        XCTAssertEqual(server.startCalls, 1)
        election.candidateReady(client)
        election.candidateReady(server)

        let winner = try await election.transport()
        XCTAssertTrue(winner === client)
        let repeatedWinner = try await election.transport()
        XCTAssertTrue(repeatedWinner === winner)
        XCTAssertEqual(client.closeCalls, 0)
        XCTAssertEqual(server.closeCalls, 1, "loser must close before the winner is returned")
        await election.close()
        XCTAssertEqual(client.closeCalls, 1)
        XCTAssertEqual(server.closeCalls, 1)
    }

    func testEstablishmentIsSentOnlyOnceOnElectedTransport() async throws {
        let election = MdocBleTransportElection()
        let client = FakeMdocBleCandidate(role: "client")
        let server = FakeMdocBleCandidate(role: "server")
        election.start([client, server])
        election.candidateReady(server)
        election.candidateReady(client)
        let establishment: [UInt8] = [1, 2, 3]

        let winner = try await election.transport()
        try await winner.send(message: establishment)

        XCTAssertEqual(client.sentMessages, [])
        XCTAssertEqual(server.sentMessages, [establishment])
        XCTAssertEqual(client.closeCalls, 1)
        XCTAssertEqual(server.closeCalls, 0)
        await election.close()
    }

    func testSynchronousReadyCannotSkipStartingAnotherOfferedRole() async throws {
        let election = MdocBleTransportElection()
        let client = FakeMdocBleCandidate(role: "client")
        let server = FakeMdocBleCandidate(role: "server")
        client.onStart = { candidate in election.candidateReady(candidate) }

        election.start([client, server])
        let winner = try await election.transport()

        XCTAssertEqual(client.startCalls, 1)
        XCTAssertEqual(server.startCalls, 1)
        XCTAssertTrue(winner === client)
        XCTAssertEqual(server.closeCalls, 1)
        await election.close()
    }

    func testOneRoleFailureDoesNotBeatAnotherReadyRole() async throws {
        let election = MdocBleTransportElection()
        let client = FakeMdocBleCandidate(role: "client")
        let server = FakeMdocBleCandidate(role: "server")
        election.start([client, server])

        election.candidateFailed(client, error: TestError("scan failed"))
        election.candidateReady(server)

        let winner = try await election.transport()
        XCTAssertTrue(winner === server)
        await election.close()
    }

    func testAllRoleFailuresRejectTransport() async {
        let election = MdocBleTransportElection()
        let client = FakeMdocBleCandidate(role: "client")
        let server = FakeMdocBleCandidate(role: "server")
        election.start([client, server])

        election.candidateFailed(client, error: TestError("scan failed"))
        election.candidateFailed(server, error: TestError("advertise failed"))

        do {
            _ = try await election.transport()
            XCTFail("election succeeded without a ready role")
        } catch let error as MdocBleTransportError {
            guard case .noReadyTransport(let detail) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            XCTAssertTrue(detail.contains("scan failed"))
            XCTAssertTrue(detail.contains("advertise failed"))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        await election.close()
    }

    func testCloseIsIdempotentAndClosesPendingCandidates() async {
        let election = MdocBleTransportElection()
        let candidate = FakeMdocBleCandidate(role: "client")
        election.start([candidate])

        await election.close()
        await election.close()

        XCTAssertEqual(candidate.closeCalls, 1)
        do {
            _ = try await election.transport()
            XCTFail("closed election returned a transport")
        } catch let error as MdocBleTransportError {
            XCTAssertEqual(error, .closed)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testCancellingAwaitClosesAllCandidatesBeforeItReturns() async {
        let election = MdocBleTransportElection()
        let client = FakeMdocBleCandidate(role: "client")
        let server = FakeMdocBleCandidate(role: "server")
        election.start([client, server])
        let waiting = Task {
            do {
                _ = try await election.transport()
                XCTFail("cancelled election returned a transport")
            } catch is CancellationError {
                // Expected.
            } catch {
                XCTFail("unexpected error: \(error)")
            }
        }
        try? await Task.sleep(nanoseconds: 20_000_000)

        waiting.cancel()
        await waiting.value

        XCTAssertTrue(waiting.isCancelled)
        XCTAssertEqual(client.closeCalls, 1)
        XCTAssertEqual(server.closeCalls, 1)
        await election.close()
        XCTAssertEqual(client.closeCalls, 1)
        XCTAssertEqual(server.closeCalls, 1)
    }
}

private struct TestError: Error, LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

private final class FakeMdocBleCandidate: MdocBleCandidate, @unchecked Sendable {
    let role: String
    var onStart: ((FakeMdocBleCandidate) -> Void)?

    private let lock = NSLock()
    private var starts = 0
    private var closes = 0
    private var messages: [[UInt8]] = []

    init(role: String) {
        self.role = role
    }

    var startCalls: Int {
        lock.lock()
        defer { lock.unlock() }
        return starts
    }

    var closeCalls: Int {
        lock.lock()
        defer { lock.unlock() }
        return closes
    }

    var sentMessages: [[UInt8]] {
        lock.lock()
        defer { lock.unlock() }
        return messages
    }

    func start() {
        lock.lock()
        starts += 1
        lock.unlock()
        onStart?(self)
    }

    func send(message: [UInt8]) async throws {
        lock.lock()
        messages.append(message)
        lock.unlock()
    }

    func receive() async throws -> [UInt8] { [] }

    func close() async {
        lock.lock()
        closes += 1
        lock.unlock()
    }
}

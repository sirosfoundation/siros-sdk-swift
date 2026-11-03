// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosVerifier

/// Radio-independent base transport tests; no CoreBluetooth APIs are loaded.
final class MdocBleTransportTests: XCTestCase {
    func testReceiveReturnsOnlyReassembledWholeMessages() async throws {
        let transport = FakeMdocBleTransport()
        transport.start()

        transport.accept([0x01, 1, 2])
        transport.accept([0x00, 3])

        let message = try await transport.receive()
        XCTAssertEqual(message, [1, 2, 3])
        await transport.close()
    }

    func testIncomingQueueIsBoundedAndPreservesFIFOUntilFull() async throws {
        let transport = FakeMdocBleTransport()
        transport.start()
        transport.accept([0x00, 1])
        transport.accept([0x00, 2])
        let first = try await transport.receive()
        let second = try await transport.receive()
        XCTAssertEqual(first, [1])
        XCTAssertEqual(second, [2])

        transport.accept([0x00, 3])
        transport.accept([0x00, 4])
        transport.accept([0x00, 5])
        do {
            _ = try await transport.receive()
            XCTFail("a full incoming queue must fail the session")
        } catch let error as MdocBleTransportError {
            XCTAssertEqual(error, .incomingQueueOverflow)
        }
        XCTAssertEqual(transport.closeRadioCalls, 1)
        await transport.close()
        XCTAssertEqual(transport.closeRadioCalls, 1)
    }

    func testSendsAreSerializedWithoutInterleavingChunks() async throws {
        let transport = FakeMdocBleTransport()
        transport.start()

        async let first: Void = transport.send(message: [1, 1, 1])
        async let second: Void = transport.send(message: [2, 2, 2])
        _ = try await (first, second)

        let chunks = transport.sentChunks
        XCTAssertEqual(chunks.count, 4)
        XCTAssertTrue(chunks.allSatisfy { $0.count <= 3 })
        let payload = chunks.flatMap { $0.dropFirst() }
        XCTAssertTrue(payload == [1, 1, 1, 2, 2, 2] || payload == [2, 2, 2, 1, 1, 1])
        XCTAssertEqual(chunks.filter { $0.first == 0x00 }.count, 2)
        await transport.close()
    }

    func testMalformedInputFailsSessionInsteadOfCrashingCallback() async {
        let transport = FakeMdocBleTransport()
        transport.start()

        transport.accept([])

        do {
            _ = try await transport.receive()
            XCTFail("malformed input was accepted")
        } catch let error as MdocBleTransportError {
            guard case .malformedMessage = error else {
                return XCTFail("unexpected error: \(error)")
            }
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        XCTAssertEqual(transport.closeRadioCalls, 1)
        await transport.close()
        XCTAssertEqual(transport.closeRadioCalls, 1)
    }

    func testDisconnectRejectsReceiveAndCloseIsDeterministic() async {
        let transport = FakeMdocBleTransport()
        transport.start()

        transport.disconnect()
        do {
            _ = try await transport.receive()
            XCTFail("disconnected transport received a message")
        } catch let error as MdocBleTransportError {
            guard case .disconnected(let detail) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            XCTAssertTrue(detail.contains("disconnected"))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        await transport.close()
        await transport.close()
        XCTAssertEqual(transport.closeRadioCalls, 1)
        do {
            try await transport.send(message: [1])
            XCTFail("closed transport accepted a send")
        } catch {
            // Expected terminal disconnect.
        }
    }

    func testReceiveTimeoutFailsAndClosesSession() async {
        let transport = FakeMdocBleTransport(ioTimeoutMs: 25)
        transport.start()

        do {
            _ = try await transport.receive()
            XCTFail("receive did not time out")
        } catch let error as MdocBleTransportError {
            guard case .timeout(let detail) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            XCTAssertTrue(detail.contains("timed out"))
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        XCTAssertEqual(transport.closeRadioCalls, 1)
    }

    func testCancellingBlockedReceiveClosesSessionOnce() async {
        let transport = FakeMdocBleTransport()
        transport.start()
        let waiting = Task {
            do {
                _ = try await transport.receive()
                XCTFail("cancelled receive returned a message")
            } catch is CancellationError {
                // Expected.
            } catch {
                XCTFail("unexpected error: \(error)")
            }
        }
        try? await Task.sleep(nanoseconds: 20_000_000)

        waiting.cancel()
        await waiting.value
        await transport.close()

        XCTAssertTrue(waiting.isCancelled)
        XCTAssertEqual(transport.closeRadioCalls, 1)
    }

    func testOutgoingMessageBoundFailsAndCloses() async {
        let transport = FakeMdocBleTransport()
        transport.start()
        let message = [UInt8](repeating: 0, count: MdocBleProtocol.maximumMessageSize + 1)

        do {
            try await transport.send(message: message)
            XCTFail("oversized message was sent")
        } catch let error as MdocBleTransportError {
            XCTAssertEqual(error, .messageTooLarge)
        } catch {
            XCTFail("unexpected error: \(error)")
        }
        XCTAssertEqual(transport.sentChunks, [])
        XCTAssertEqual(transport.closeRadioCalls, 1)
    }
}

private final class FakeMdocBleTransport: MdocBleTransportBase, @unchecked Sendable {
    private let fakeLock = NSLock()
    private var chunks: [[UInt8]] = []
    private var radioCloseCount = 0

    init(
        readyTimeoutMs: UInt64 = 5_000,
        ioTimeoutMs: UInt64 = 5_000
    ) {
        super.init(
            role: "fake",
            onReady: { _ in },
            onFailure: { _, _ in },
            readyTimeoutMs: readyTimeoutMs,
            ioTimeoutMs: ioTimeoutMs
        )
    }

    var sentChunks: [[UInt8]] {
        fakeLock.lock()
        defer { fakeLock.unlock() }
        return chunks
    }

    var closeRadioCalls: Int {
        fakeLock.lock()
        defer { fakeLock.unlock() }
        return radioCloseCount
    }

    override func startRadio() throws {}

    override func closeRadio() {
        fakeLock.lock()
        radioCloseCount += 1
        fakeLock.unlock()
    }

    override func currentMaxChunkSize() -> Int { 3 }

    override func sendChunk(_ chunk: [UInt8]) async throws {
        await Task.yield()
        fakeLock.lock()
        chunks.append(chunk)
        fakeLock.unlock()
    }

    func accept(_ chunk: [UInt8]) {
        acceptIncomingChunk(chunk)
    }

    func disconnect() {
        fail(MdocBleTransportError.disconnected("fake disconnected"))
    }
}

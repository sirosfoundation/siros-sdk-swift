// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosTransport

final class WmpSessionTests: XCTestCase {
    private let codec = WmpCodec()

    func testCreateSendsSessionCreateAndTransitionsActive() async throws {
        let transport = FakeTransport()
        let session = WmpSession(
            transport: transport,
            config: WmpSessionConfig(requestTimeoutMs: 2_000)
        )

        let createTask = Task {
            try await session.create(authToken: "app-token", sender: "sample-wallet")
        }

        // Wait for the create request to be sent
        try await waitForSentCount(transport, expected: 1)
        let createReq = try codec.decodeRequest(transport.sentMessages.last!)
        XCTAssertEqual(createReq.method, "wmp.session.create")
        XCTAssertNotNil(createReq.id)

        let createText = String(data: transport.sentMessages.last!, encoding: .utf8)!
        XCTAssertTrue(createText.contains("\"type\":\"bearer\""))
        XCTAssertTrue(createText.contains("\"token\":\"app-token\""))

        // Send success response
        transport.receiveFromServer(createSuccessResponse(requestId: createReq.id!).data(using: .utf8)!)
        try await createTask.value

        XCTAssertEqual(session.currentState, .active)

        try await session.close()
    }

    func testSendRequestTimesOutWithoutResponse() async {
        let transport = FakeTransport()
        let session = WmpSession(
            transport: transport,
            config: WmpSessionConfig(requestTimeoutMs: 100)
        )

        // Connect first
        try? await transport.connect()

        do {
            _ = try await session.sendRequest(method: "wmp.flow.action", params: nil, timeoutMs: 100)
            XCTFail("Expected WmpTimeoutError")
        } catch is WmpTimeoutError {
            // expected
        } catch {
            XCTFail("Expected WmpTimeoutError, got \(error)")
        }
    }

    func testNotificationsFlowEmitsServerNotification() async throws {
        let transport = FakeTransport()
        let session = WmpSession(
            transport: transport,
            config: WmpSessionConfig(requestTimeoutMs: 2_000)
        )

        // Create session
        let createTask = Task { try await session.create(authToken: "token") }
        try await waitForSentCount(transport, expected: 1)
        let createReq = try codec.decodeRequest(transport.sentMessages.last!)
        transport.receiveFromServer(createSuccessResponse(requestId: createReq.id!).data(using: .utf8)!)
        try await createTask.value

        // Listen for notification
        let notificationTask = Task {
            for await notification in session.notifications() {
                return notification
            }
            fatalError("Stream ended")
        }

        // Send a notification from server
        transport.receiveFromServer(
            """
            {"jsonrpc":"2.0","method":"wmp.flow.progress","params":{"state":"processing"}}
            """.data(using: .utf8)!
        )

        let notification = try await withTimeout(seconds: 2) {
            await notificationTask.value
        }
        XCTAssertEqual(notification.method, "wmp.flow.progress")

        try await session.close()
    }

    func testResumeWithSeedsPersistedSessionAndRotatesToken() async throws {
        let transport = FakeTransport()
        let session = WmpSession(
            transport: transport,
            config: WmpSessionConfig(requestTimeoutMs: 2_000)
        )

        let resumeTask = Task {
            try await session.resumeWith(sessionId: "session-123", resumptionToken: "resume-abc")
        }
        try await waitForSentCount(transport, expected: 1)
        let request = try codec.decodeRequest(transport.sentMessages.last!)
        XCTAssertEqual(request.method, "wmp.session.resume")
        let requestText = String(decoding: transport.sentMessages.last!, as: UTF8.self)
        XCTAssertTrue(requestText.contains("session-123"))
        XCTAssertTrue(requestText.contains("resume-abc"))

        transport.receiveFromServer(Data(
            #"{"jsonrpc":"2.0","id":"\#(request.id!)","result":{"wmp":{"version":"0.1","session_id":"session-123"},"resumed":true,"resumption_token":"resume-rotated"}}"#.utf8
        ))
        try await resumeTask.value

        XCTAssertEqual(session.currentState, .active)
        XCTAssertEqual(session.currentSessionId, "session-123")
        XCTAssertEqual(session.currentResumptionToken, "resume-rotated")
        try await session.close()
    }

    // MARK: - Helpers

    /// `onTerminal` fires when the session ends for good: on close, and once every reconnect attempt has failed;
    /// never on the transient `.failed` of one failed resume.
    func testOnTerminalFiresOnCloseAndWhenReconnectsAreExhaustedOnly() async throws {
        actor Count { var n = 0; func bump() { n += 1 }; var value: Int { n } }
        let counter = Count()
        let transport = FakeTransport()
        let session = WmpSession(transport: transport, config: WmpSessionConfig(requestTimeoutMs: 2_000))
        session.onTerminal = { Task { await counter.bump() } }
        let createTask = Task { try await session.create(authToken: "t", sender: "s") }
        try await waitForSentCount(transport, expected: 1)
        let req = try codec.decodeRequest(transport.sentMessages.last!)
        transport.receiveFromServer(createSuccessResponse(requestId: req.id!).data(using: .utf8)!)
        try await createTask.value
        let before = await counter.value
        XCTAssertEqual(before, 0, "an active session is not terminal")
        try await session.close()
        try await Task.sleep(nanoseconds: 100_000_000)
        let after = await counter.value
        XCTAssertEqual(after, 1)
    }

    /// A session created without a `resumption_token` has nothing to resume: losing the connection ends it at once,
    /// the same way an exhausted resume does (terminal hook, pending requests failed).
    func testLosingTheConnectionWithoutAResumptionTokenEndsTheSession() async throws {
        actor Count { var n = 0; func bump() { n += 1 }; var value: Int { n } }
        let counter = Count()
        let transport = FakeTransport()
        let session = WmpSession(transport: transport, config: WmpSessionConfig(requestTimeoutMs: 2_000))
        session.onTerminal = { Task { await counter.bump() } }
        let createTask = Task { try await session.create(authToken: "t", sender: "s") }
        try await waitForSentCount(transport, expected: 1)
        let req = try codec.decodeRequest(transport.sentMessages.last!)
        transport.receiveFromServer(
            #"{"jsonrpc":"2.0","id":"\#(req.id!)","result":{"wmp":{"version":"0.1","session_id":"session-123"}}}"#.data(using: .utf8)!
        )
        try await createTask.value
        await transport.disconnect()
        for _ in 0..<100 { if await counter.value > 0 { break }; try await Task.sleep(nanoseconds: 20_000_000) }
        let fired = await counter.value
        XCTAssertEqual(fired, 1)
        XCTAssertEqual(session.currentState, .failed)
    }

    /// A permanent disconnect and a later `close()` of the same session notify once, not twice.
    func testTerminalIsNotifiedOnceForFailureFollowedByClose() async throws {
        actor Count { var n = 0; func bump() { n += 1 }; var value: Int { n } }
        let counter = Count()
        let transport = FakeTransport()
        let session = WmpSession(transport: transport, config: WmpSessionConfig(requestTimeoutMs: 2_000))
        session.onTerminal = { Task { await counter.bump() } }
        let createTask = Task { try await session.create(authToken: "t", sender: "s") }
        try await waitForSentCount(transport, expected: 1)
        let req = try codec.decodeRequest(transport.sentMessages.last!)
        transport.receiveFromServer(
            #"{"jsonrpc":"2.0","id":"\#(req.id!)","result":{"wmp":{"version":"0.1","session_id":"session-123"}}}"#.data(using: .utf8)!
        )
        try await createTask.value
        await transport.disconnect()
        for _ in 0..<100 { if await counter.value > 0 { break }; try await Task.sleep(nanoseconds: 20_000_000) }
        try await session.close()
        try await Task.sleep(nanoseconds: 100_000_000)
        let fired = await counter.value
        XCTAssertEqual(fired, 1)
    }

    // MARK: - The transport-state collector handles a failure whatever the session state (#306)

    /// #306: a transport failure while the session is CONNECTING (the create
    /// in flight) used to be silently dropped — the collector only acted on
    /// ACTIVE — so the create then hung to its full request timeout and
    /// orphaned. The failure is now handled whatever the session state: the
    /// recovery fails the create's pending request at once, the session is
    /// FAILED and the terminal hook fires.
    func testATransportFailureWhileConnectingEndsTheCreateAtOnce() async throws {
        actor Count { var n = 0; func bump() { n += 1 }; var value: Int { n } }
        let counter = Count()
        let transport = FakeTransport()
        let session = WmpSession(transport: transport, config: WmpSessionConfig(requestTimeoutMs: 5_000))
        session.onTerminal = { Task { await counter.bump() } }

        let createTask = Task { try await session.create(authToken: "t") }
        // The create POST is out but unanswered when the transport fails.
        try await waitForSentCount(transport, expected: 1)
        transport.simulateFailure()

        // Handled despite the session being CONNECTING: fast, not the 5 s
        // request timeout the old drop condemned it to.
        do {
            _ = try await createTask.value
            XCTFail("the create must fail when its transport does")
        } catch WmpSessionError.connectionFailed {
            // the recovery failed the pending create request
        } catch {
            XCTFail("expected WmpSessionError.connectionFailed, got \(error)")
        }
        XCTAssertEqual(session.currentState, .failed)
        let fired = await counter.value
        XCTAssertEqual(fired, 1)
    }

    /// #306: a transport failure while the session is RESUMING (the resume in
    /// flight) used to be silently dropped the same way: the resume threw its
    /// timeout and the session stranded — the transport was dead and nothing
    /// ran the recovery. The failure is now handled whatever the state: the
    /// recovery's own resume re-opens the stream, rotates the token, and the
    /// session comes back ACTIVE (the resume path is idempotent).
    func testATransportFailureWhileResumingIsRecovered() async throws {
        let transport = FakeTransport()
        let session = WmpSession(
            transport: transport,
            config: WmpSessionConfig(requestTimeoutMs: 5_000, maxReconnectAttempts: 2, reconnectBaseMs: 1, reconnectMaxMs: 1)
        )

        // A resume in flight: the POST is out but unanswered.
        let resumeTask = Task { try await session.resumeWith(sessionId: "session-123", resumptionToken: "resume-abc") }
        try await waitForSentCount(transport, expected: 1)

        // The recovery's resume (the SECOND one — the first is the in-flight
        // call this failure interrupts), answered on sight.
        let answerer = Task { await self.answerResumes(on: transport, fromResume: 2) }

        // The transport fails WHILE the session is resuming.
        transport.simulateFailure()

        // The failure is handled despite RESUMING: the recovery loop resumes
        // and the session is active again over the re-opened stream.
        let deadline = Date().addingTimeInterval(3)
        while session.currentState != .active, Date() < deadline {
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTAssertEqual(session.currentState, .active, "the dropped disconnect used to strand the session at .resuming forever")
        _ = await answerer.value
        // The superseded in-flight resume times out into the void a few
        // seconds later; its caller's error is not the session's state, and
        // the session stays healed regardless of it.
        _ = resumeTask
    }

    /// #306 end to end: a stream that goes silent — no line for the
    /// watchdog's idle limit (the production limit is 60 s at the engine's
    /// ~15 s heartbeats; milliseconds here) — fails the transport, and the
    /// session's collector answers with the existing reconnect: the resume
    /// re-opens the stream and rotates the token.
    func testASilentStreamFailsTheTransportAndTheSessionResumes() async throws {
        let transport = FakeTransport()
        let session = WmpSession(
            transport: transport,
            config: WmpSessionConfig(requestTimeoutMs: 2_000, maxReconnectAttempts: 2, reconnectBaseMs: 1, reconnectMaxMs: 1)
        )

        let createTask = Task { try await session.create(authToken: "t", sender: "s") }
        try await waitForSentCount(transport, expected: 1)
        let req = try codec.decodeRequest(transport.sentMessages.last!)
        transport.receiveFromServer(createSuccessResponse(requestId: req.id!).data(using: .utf8)!)
        try await createTask.value
        XCTAssertEqual(session.currentState, .active)

        actor Count { var n = 0; func bump() { n += 1 }; var value: Int { n } }
        let counter = Count()

        // The watchdog, wired the way the HTTP+SSE transport wires it (#306):
        // no line for the idle limit — the half-open socket case, the kernel
        // still calls the connection established — marks the transport FAILED.
        let watchdog = SseLivenessWatchdog(checkInterval: 0.05, idleLimit: 0.2)
        watchdog.onIdle = {
            Task { await counter.bump() }
            transport.simulateFailure()
        }
        watchdog.arm()

        // The recovery's resume, answered on sight.
        let answerer = Task { await self.answerResumes(on: transport) }

        // Silent stream → watchdog trip → transport FAILED → the collector's
        // reconnect → the session active again over the re-opened stream.
        let deadline = Date().addingTimeInterval(3)
        while Date() < deadline {
            if await counter.value > 0, session.currentState == .active { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTAssertEqual(session.currentState, .active, "the watchdog's FAILED must run the session's reconnect")
        let fired = await counter.value
        XCTAssertEqual(fired, 1, "the silent stream trips the watchdog once")
        let events = transport.events
        XCTAssertEqual(events.filter { $0 == "connect" }.count, 2, "the stream re-opened for the resume")
        XCTAssertTrue(events.contains("send:wmp.session.resume"), "the recovery resumed the session")
        watchdog.stop()
        _ = await answerer.value
    }

    private func waitForSentCount(_ transport: FakeTransport, expected: Int) async throws {
        let deadline = Date().addingTimeInterval(2)
        while transport.sentMessages.count < expected {
            if Date() > deadline { throw TimeoutError() }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
    }

    /// Answers `wmp.session.resume` requests on sight — from the `fromResume`-th
    /// one on (the earlier ones belong to the interrupted caller), rotating
    /// the resumption token — returning once `untilAnswered` answers went
    /// out. Bounded by `seconds`, so a test can also leave it polling on a
    /// task.
    private func answerResumes(
        on transport: FakeTransport,
        fromResume: Int = 1,
        rotatingTo token: String = "resume-rotated",
        untilAnswered: Int = 1,
        seconds: Double = 5
    ) async {
        var answered = Set<Int>()
        var resumes = 0
        var answeredCount = 0
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            for (i, data) in transport.sentMessages.enumerated() where !answered.contains(i) {
                answered.insert(i)
                guard let req = try? codec.decodeRequest(data),
                      req.method == "wmp.session.resume" else { continue }
                resumes += 1
                guard resumes >= fromResume else { continue }
                transport.receiveFromServer(
                    #"{"jsonrpc":"2.0","id":"\#(req.id!)","result":{"wmp":{"version":"0.1","session_id":"session-123"},"resumed":true,"resumption_token":"\#(token)"}}"#.data(using: .utf8)!
                )
                answeredCount += 1
                if answeredCount >= untilAnswered { return }
            }
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
    }

    private func createSuccessResponse(requestId: String) -> String {
        """
        {"jsonrpc":"2.0","id":"\(requestId)","result":{"wmp":{"version":"0.1","session_id":"session-123"},"resumption_token":"resume-abc"}}
        """
    }

    private func withTimeout<T>(seconds: TimeInterval, operation: @escaping () async throws -> T) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask { try await operation() }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                throw TimeoutError()
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
    }
}

private struct TimeoutError: Error {}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosWallet
import SirosCredentials
@testable import SirosSampleApp

/// The sample app's EC TS12 surface: the settings toggle and the consent
/// bridge. The TS12 behaviour itself is tested in the SDK; these only prove
/// the app hands the user's choices to it.
@MainActor
final class TransactionDataSettingsTests: XCTestCase {

    override func setUp() {
        super.setUp()
        UserDefaults.standard.removeObject(forKey: WalletViewModel.transactionDataEnabledKey)
    }

    override func tearDown() {
        UserDefaults.standard.removeObject(forKey: WalletViewModel.transactionDataEnabledKey)
        super.tearDown()
    }

    private struct NoPrompt: Error {}

    static func sampleRequest() -> TransactionConsentRequest {
        TransactionConsentRequest(
            verifier: "Shop AB", credentialName: "Visa card",
            entries: [TransactionConsentEntry(
                title: nil, typeName: "Payment Confirmation",
                fields: [TransactionConsentField(label: "Amount", value: "49.99", level: 1, path: ["amount"])],
                affirmativeLabel: "Confirm Payment", denialLabel: nil, securityHint: nil
            )],
            requestSigned: nil, locale: "en"
        )
    }

    private func waitForPending(_ vm: WalletViewModel) async throws -> PendingTransactionConsent {
        for _ in 0..<200 {
            if let pending = vm.pendingTransactionConsent { return pending }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTFail("no prompt was presented")
        throw NoPrompt()
    }

    func testToggleIsOffByDefaultAndPersists() {
        let vm = WalletViewModel()
        XCTAssertFalse(vm.transactionDataEnabled)
        vm.transactionDataEnabled = true
        XCTAssertTrue(UserDefaults.standard.bool(forKey: WalletViewModel.transactionDataEnabledKey))
        XCTAssertTrue(WalletViewModel().transactionDataEnabled, "a new instance reads the persisted setting")
        vm.transactionDataEnabled = false
        XCTAssertFalse(WalletViewModel().transactionDataEnabled)
    }

    func testToggleAppliesToTheWalletAtRuntime() throws {
        let vm = WalletViewModel()
        vm.rebuildWalletIfNeeded()          // a wallet exists only after a login/registration builds one
        let wallet = try XCTUnwrap(vm.wallet)
        XCTAssertFalse(wallet.transactionDataEnabled)
        vm.transactionDataEnabled = true
        XCTAssertTrue(wallet.transactionDataEnabled)
        vm.transactionDataEnabled = false
        XCTAssertFalse(wallet.transactionDataEnabled)
    }

    func testConfirmingReturnsTrueToTheSdk() async throws {
        let vm = WalletViewModel()
        let bridge = Task { await vm.requestTransactionConsent(Self.sampleRequest()) }
        let pending = try await waitForPending(vm)
        XCTAssertEqual(pending.request.entries.first?.fields.first?.value, "49.99")
        pending.respond(true)
        let answer = await bridge.value
        XCTAssertTrue(answer)
        XCTAssertNil(vm.pendingTransactionConsent)
    }

    func testDecliningAndDismissingBothReturnFalse() async throws {
        let vm = WalletViewModel()
        let declined = Task { await vm.requestTransactionConsent(Self.sampleRequest()) }
        let first = try await waitForPending(vm)
        first.respond(false)
        let declinedAnswer = await declined.value
        XCTAssertFalse(declinedAnswer)

        let dismissed = Task { await vm.requestTransactionConsent(Self.sampleRequest()) }
        _ = try await waitForPending(vm)
        vm.dismissTransactionConsent()
        let dismissedAnswer = await dismissed.value
        XCTAssertFalse(dismissedAnswer, "swiping the sheet away is a decline, never consent")
    }

    func testANewPromptDeclinesThePendingOne() async throws {
        let vm = WalletViewModel()
        let firstTask = Task { await vm.requestTransactionConsent(Self.sampleRequest()) }
        let first = try await waitForPending(vm)
        let secondTask = Task { await vm.requestTransactionConsent(Self.sampleRequest()) }
        // Fails (rather than hanging on `firstTask.value`) when the second prompt never replaces the first.
        for _ in 0..<200 where vm.pendingTransactionConsent?.id == first.id { try await Task.sleep(nanoseconds: 10_000_000) }
        if vm.pendingTransactionConsent?.id == first.id {
            vm.dismissTransactionConsent(); secondTask.cancel()
            XCTFail("the second prompt was never presented")
            return
        }
        let firstAnswer = await firstTask.value
        XCTAssertFalse(firstAnswer)
        vm.pendingTransactionConsent?.respond(true)
        let secondAnswer = await secondTask.value
        XCTAssertTrue(secondAnswer)
    }
}

@MainActor
final class TransactionDataLifecycleTests: XCTestCase {
    func testCancellingTheAwaitingTaskWithdrawsThePromptAndDeclines() async throws {
        let vm = WalletViewModel()
        let task = Task { await vm.requestTransactionConsent(TransactionDataSettingsTests.sampleRequest()) }
        for _ in 0..<200 where vm.pendingTransactionConsent == nil { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertNotNil(vm.pendingTransactionConsent)
        task.cancel()
        let answer = await task.value
        XCTAssertFalse(answer, "the SDK's deadline passing declines")
        for _ in 0..<200 where vm.pendingTransactionConsent != nil { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertNil(vm.pendingTransactionConsent, "the sheet is withdrawn, not left showing a request the SDK already declined")
    }

    func testAStaleResponseDoesNotClearANewerPrompt() async throws {
        let vm = WalletViewModel()
        let first = Task { await vm.requestTransactionConsent(TransactionDataSettingsTests.sampleRequest()) }
        for _ in 0..<200 where vm.pendingTransactionConsent == nil { try await Task.sleep(nanoseconds: 10_000_000) }
        let stale = try XCTUnwrap(vm.pendingTransactionConsent)
        let second = Task { await vm.requestTransactionConsent(TransactionDataSettingsTests.sampleRequest()) }
        for _ in 0..<200 where vm.pendingTransactionConsent?.id == stale.id { try await Task.sleep(nanoseconds: 10_000_000) }
        let firstAnswer = await first.value
        XCTAssertFalse(firstAnswer)
        let current = try XCTUnwrap(vm.pendingTransactionConsent)
        stale.respond(true)   // the outgoing prompt answering late
        XCTAssertEqual(vm.pendingTransactionConsent?.id, current.id, "the newer prompt is still showing")
        current.respond(true)
        let secondAnswer = await second.value
        XCTAssertTrue(secondAnswer)
    }

    /// A store whose read is held until released, to log out while the load is suspended.
    private final class DelayedLogStore: TransactionLogStore, @unchecked Sendable {
        private let sentinel = TransactionLogEntry(subject: TransactionLogSubject(transactionId: "SENTINEL", typeName: nil), verifier: "v", credential: "c", outcome: .consented)
        private var continuation: CheckedContinuation<Void, Never>?
        private let lock = NSLock()
        private var released = false
        func append(_ entries: [TransactionLogEntry]) async throws {}
        func entries() async -> [TransactionLogEntry] {
            await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                lock.lock()
                if released { lock.unlock(); c.resume(); return }
                continuation = c
                lock.unlock()
            }
            return [sentinel]
        }
        func release() { lock.lock(); released = true; let c = continuation; continuation = nil; lock.unlock(); c?.resume() }
    }

    /// First read slow, second read fast: the slow one must not overwrite the newer result.
    private final class TwoSpeedLogStore: TransactionLogStore, @unchecked Sendable {
        private let lock = NSLock()
        private var reads = 0
        private var slow: CheckedContinuation<Void, Never>?
        private func entry(_ id: String) -> TransactionLogEntry {
            TransactionLogEntry(subject: TransactionLogSubject(transactionId: id, typeName: nil), verifier: "v", credential: "c", outcome: .consented)
        }
        func append(_ entries: [TransactionLogEntry]) async throws {}
        func entries() async -> [TransactionLogEntry] {
            lock.lock(); reads += 1; let mine = reads; lock.unlock()
            if mine == 1 {
                await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in lock.lock(); slow = c; lock.unlock() }
                return [entry("OLD")]
            }
            return [entry("NEW")]
        }
        func releaseSlow() { lock.lock(); let c = slow; slow = nil; lock.unlock(); c?.resume() }
    }

    func testAnOlderLogReadDoesNotOverwriteANewerOne() async throws {
        let vm = WalletViewModel()
        vm.rebuildWalletIfNeeded()
        let store = TwoSpeedLogStore()
        try XCTUnwrap(vm.wallet).setTransactionLogStore(store)
        vm.openTransactionLog()                                   // read 1: suspended
        try await Task.sleep(nanoseconds: 100_000_000)
        vm.openTransactionLog()                                   // read 2: finishes at once
        try await Task.sleep(nanoseconds: 200_000_000)
        store.releaseSlow()                                       // the older read now returns
        try await Task.sleep(nanoseconds: 200_000_000)
        XCTAssertEqual(vm.transactionLog.first?.transactionId, "NEW")
    }

    func testALogLoadStartedBeforeLogoutDoesNotRepopulateTheNextSession() async throws {
        let vm = WalletViewModel()
        let store = DelayedLogStore()
        vm.rebuildWalletIfNeeded()          // a wallet exists only after a login/registration builds one
        let wallet = try XCTUnwrap(vm.wallet)
        wallet.setTransactionLogStore(store)
        vm.openTransactionLog()                       // the read is now suspended
        try await Task.sleep(nanoseconds: 100_000_000)
        vm.disconnect()                               // the session ends while it is suspended
        store.release()                               // the stale result now arrives
        try await Task.sleep(nanoseconds: 300_000_000)
        XCTAssertTrue(vm.transactionLog.isEmpty, "the previous session's entries were not published")
        XCTAssertFalse(vm.showTransactionLog)
    }

    func testADismissalForAnEarlierPromptDoesNotDeclineANewerOne() async throws {
        let vm = WalletViewModel()
        let first = Task { await vm.requestTransactionConsent(TransactionDataSettingsTests.sampleRequest()) }
        for _ in 0..<200 where vm.pendingTransactionConsent == nil { try await Task.sleep(nanoseconds: 10_000_000) }
        let earlier = try XCTUnwrap(vm.pendingTransactionConsent)
        let second = Task { await vm.requestTransactionConsent(TransactionDataSettingsTests.sampleRequest()) }
        for _ in 0..<200 where vm.pendingTransactionConsent?.id == earlier.id { try await Task.sleep(nanoseconds: 10_000_000) }
        _ = await first.value
        let current = try XCTUnwrap(vm.pendingTransactionConsent)
        earlier.respond(false)      // the earlier sheet's late dismissal callback
        XCTAssertEqual(vm.pendingTransactionConsent?.id, current.id, "the newer prompt is untouched")
        current.respond(true)
        let answer = await second.value
        XCTAssertTrue(answer)
    }

    /// An interactive dismissal clears the sheet binding before `onDisappear` runs; the sheet's own response must still decline.
    func testDismissingAfterTheBindingWasClearedStillDeclines() async throws {
        let vm = WalletViewModel()
        let request = Task { await vm.requestTransactionConsent(TransactionDataSettingsTests.sampleRequest()) }
        for _ in 0..<200 where vm.pendingTransactionConsent == nil { try await Task.sleep(nanoseconds: 10_000_000) }
        let pending = try XCTUnwrap(vm.pendingTransactionConsent)
        vm.pendingTransactionConsent = nil          // what SwiftUI does on a swipe, before onDisappear
        pending.respond(false)                      // what the sheet's onDisappear does
        let answer = await request.value
        XCTAssertFalse(answer)
    }

    func testEndingTheSessionClearsTheLogAndTheScreen() {
        let vm = WalletViewModel()
        vm.showTransactionLog = true
        vm.transactionLog = [TransactionLogEntry(subject: TransactionLogSubject(transactionId: "t", typeName: nil), verifier: "v", credential: "c", outcome: .consented)]
        vm.disconnect()
        XCTAssertFalse(vm.showTransactionLog)
        XCTAssertTrue(vm.transactionLog.isEmpty)
    }
}

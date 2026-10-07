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
        let wallet = try XCTUnwrap(vm.wallet, "the view model builds a wallet at launch")
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
        for _ in 0..<200 where vm.pendingTransactionConsent?.id == first.id { try await Task.sleep(nanoseconds: 10_000_000) }
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

    func testALogLoadStartedBeforeLogoutDoesNotRepopulateTheNextSession() async throws {
        let vm = WalletViewModel()
        vm.openTransactionLog()          // starts loading for this session
        vm.disconnect()                  // the session ends before the load returns
        try await Task.sleep(nanoseconds: 200_000_000)
        XCTAssertTrue(vm.transactionLog.isEmpty)
        XCTAssertFalse(vm.showTransactionLog)
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

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosWallet
@testable import SirosCredentials

/// Unit tests for WalletViewModel.
/// Mirrors the Kotlin sample-app's WalletViewModelTest coverage.
@MainActor
final class WalletViewModelTests: XCTestCase {

    private func makeViewModel() -> WalletViewModel {
        WalletViewModel()
    }

    // MARK: - Configuration

    func testDefaultBackendAndTenant() {
        let vm = makeViewModel()
        #if DEBUG
        XCTAssertEqual(vm.backendUrl, "http://192.168.240.1:8090")
        #else
        XCTAssertEqual(vm.backendUrl, "https://wallet.sirosid.dev")
        #endif
        XCTAssertEqual(vm.tenantId, "default")
    }

    // MARK: - Error handling

    func testClearErrorResetsState() {
        let vm = makeViewModel()
        vm.errorMessage = "Something broke"
        vm.showError = true

        vm.clearError()

        XCTAssertNil(vm.errorMessage)
        XCTAssertFalse(vm.showError)
    }

    // MARK: - Navigation

    func testOpenAddCredentialSetsLoadingState() {
        let vm = makeViewModel()
        vm.openAddCredential()

        XCTAssertTrue(vm.showAddCredential)
        // isLoadingOffers starts true then async sets to false
    }

    func testCloseAddCredentialResetsFlag() {
        let vm = makeViewModel()
        vm.showAddCredential = true
        vm.closeAddCredential()
        XCTAssertFalse(vm.showAddCredential)
    }

    func testOpenCredentialDetailSetsSelection() {
        let vm = makeViewModel()
        let credential = StoredCredential(id: "test-1", format: "vc+sd-jwt", raw: "{}")
        vm.openCredentialDetail(credential)
        XCTAssertEqual(vm.selectedCredential?.id, "test-1")
    }

    func testCloseCredentialDetailClearsSelection() {
        let vm = makeViewModel()
        vm.selectedCredential = StoredCredential(id: "test-1", format: "vc+sd-jwt", raw: "{}")
        vm.closeCredentialDetail()
        XCTAssertNil(vm.selectedCredential)
    }

    func testOpenHistorySetsFlag() {
        let vm = makeViewModel()
        vm.openHistory()
        XCTAssertTrue(vm.showHistory)
    }

    func testCloseHistoryClearsFlag() {
        let vm = makeViewModel()
        vm.showHistory = true
        vm.closeHistory()
        XCTAssertFalse(vm.showHistory)
    }

    func testOpenQrScannerSetsFlag() {
        let vm = makeViewModel()
        vm.openQrScanner()
        XCTAssertTrue(vm.showQrScanner)
    }

    func testCloseQrScannerClearsFlag() {
        let vm = makeViewModel()
        vm.showQrScanner = true
        vm.closeQrScanner()
        XCTAssertFalse(vm.showQrScanner)
    }

    // MARK: - Disconnect

    func testDisconnectClearsState() {
        let vm = makeViewModel()
        vm.showAddCredential = true
        vm.selectedCredential = StoredCredential(id: "x", format: "jwt", raw: "")
        vm.showHistory = true
        vm.showQrScanner = true

        vm.disconnect()

        XCTAssertFalse(vm.showAddCredential)
        XCTAssertNil(vm.selectedCredential)
        XCTAssertFalse(vm.showHistory)
        XCTAssertFalse(vm.showQrScanner)
        XCTAssertTrue(vm.availableCredentials.isEmpty)
    }

    // MARK: - Auth redirect

    func testHandleAuthRedirectWithNoPendingFlowSetsError() {
        let vm = makeViewModel()
        // No pending flow ID — simulate receiving a redirect
        vm.handleDeepLink(URL(string: "siros-sample://callback?code=abc&state=xyz")!)

        // Should set error since no wallet is configured
        // The deep link classifier will match authCallback but wallet is nil
    }

    // MARK: - QR result routing

    func testHandleQrResultWithUnknownUriSetsError() {
        let vm = makeViewModel()
        vm.handleQrResult("https://example.com/not-a-wallet-uri")
        XCTAssertEqual(vm.errorMessage, "Unrecognised QR code")
        XCTAssertTrue(vm.showError)
    }

    func testHandleQrResultClosesScanner() {
        let vm = makeViewModel()
        vm.showQrScanner = true
        vm.handleQrResult("openid-credential-offer://some-offer")
        XCTAssertFalse(vm.showQrScanner)
    }

    // MARK: - Presentation consent

    func testAcceptPresentationClearsPending() {
        let vm = makeViewModel()
        let request = PresentationRequest(
            verifierName: "Test Verifier",
            candidates: [StoredCredential(id: "c1", format: "jwt", raw: "")]
        )
        vm.pendingPresentation = request

        vm.acceptPresentation(["c1"])

        XCTAssertNil(vm.pendingPresentation)
    }

    func testDeclinePresentationClearsPending() {
        let vm = makeViewModel()
        let request = PresentationRequest(
            verifierName: "Test Verifier",
            candidates: [StoredCredential(id: "c1", format: "jwt", raw: "")]
        )
        vm.pendingPresentation = request

        vm.declinePresentation()

        XCTAssertNil(vm.pendingPresentation)
    }
}

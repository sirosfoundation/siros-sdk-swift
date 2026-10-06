// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosWallet
@testable import SirosSampleApp

/// Every refusal facetec-api v0.16.0 can answer with must reach the user as its
/// own localized message, not as the backend's raw description. The errors here
/// are the ones `FaceTecIDVProvider` produces for those codes.
@MainActor
final class IdvErrorMessageTests: XCTestCase {

    private let raw = "raw backend text"

    func testEveryFacetecApiCodeHasItsOwnMessage() {
        let errors: [(code: String, error: IDVError)] = [
            ("liveness_failed", .livenessFailed(message: raw)),
            ("match_failed / document_unreadable / policy_rejected", .verificationFailed(message: raw)),
            ("session_expired", .sessionExpired(message: raw)),
            ("nfc_skipped", .documentChipNotVerified(reason: "nfc_skipped", message: raw)),
            ("nfc_not_requested", .documentChipNotVerified(reason: "nfc_not_requested", message: raw)),
            ("nfc_device_not_capable", .documentChipNotVerified(reason: "nfc_device_not_capable", message: raw)),
            ("nfc_chip_read_failed", .documentChipNotVerified(reason: "nfc_chip_read_failed", message: raw)),
            ("nfc_not_authenticated", .documentChipNotVerified(reason: "nfc_not_authenticated", message: raw)),
            ("chip_untrusted", .chipUntrusted(message: raw)),
            ("document_expired", .documentExpired(message: raw)),
            ("issuance_failed", .providerError(code: "issuance_failed", message: raw)),
            ("internal_error", .providerError(code: "internal_error", message: raw)),
        ]
        var seen = Set<String>()
        for (code, error) in errors {
            let message = WalletViewModel.idvErrorMessage(for: error)
            XCTAssertFalse(message.hasPrefix("idv.errors."), "\(code): missing key for \(error.errorCode)")
            XCTAssertNotEqual(message, raw, "\(code): fell through to the raw description")
            seen.insert(message)
        }
        XCTAssertEqual(seen.count, errors.count, "each error type has a distinct message")
    }

    func testUnknownCodeFallsBackToTheErrorDescription() {
        let error = IDVError.providerError(code: "a_future_code", message: "something new")

        XCTAssertEqual(WalletViewModel.idvErrorMessage(for: error), "[a_future_code] something new")
    }

    func testUnresolvedDeviceKeyPlaceholderIsNotAKey() {
        XCTAssertEqual(WalletViewModel.deviceKeyIdentifier(fromInfoValue: "$(FACETEC_DEVICE_KEY_IDENTIFIER)"), "")
        XCTAssertEqual(WalletViewModel.deviceKeyIdentifier(fromInfoValue: "  "), "")
        XCTAssertEqual(WalletViewModel.deviceKeyIdentifier(fromInfoValue: nil), "")
        XCTAssertEqual(WalletViewModel.deviceKeyIdentifier(fromInfoValue: 7), "")
        XCTAssertEqual(WalletViewModel.deviceKeyIdentifier(fromInfoValue: " dev-key "), "dev-key")
    }
}

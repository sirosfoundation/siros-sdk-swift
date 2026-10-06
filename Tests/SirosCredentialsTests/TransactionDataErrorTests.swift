// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

final class TransactionDataErrorTests: XCTestCase {
    func testReasonSetMatchesTheSharedContract() {
        XCTAssertEqual(
            Set(TransactionDataError.Reason.allCases.map(\.rawValue)),
            ["disabled", "invalidEntry", "inconsistentWithOrchestrator", "unsupportedFormat",
             "notScaAttestation", "unsupportedType", "schemaViolation", "metadataUnavailable",
             "unsupportedHashAlgorithm", "insufficientAuthenticationFactors",
             "noConsentHandler", "declined"]
        )
    }

    func testDeclinedAnswersAccessDeniedEverythingElseInvalidTransactionData() {
        for reason in TransactionDataError.Reason.allCases {
            let expected = reason == .declined ? "access_denied" : "invalid_transaction_data"
            XCTAssertEqual(TransactionDataError(reason).verifierErrorCode, expected, reason.rawValue)
        }
    }

    func testIsPartOfTheSirosErrorFamily() {
        let error = SirosError.transactionData(TransactionDataError(.disabled, detail: "d"))
        XCTAssertEqual(error.errorCode, "transaction_data_disabled")
        XCTAssertTrue((error.errorDescription ?? "").contains("disabled"))
    }

    /// `detail` is developer-only: it must not reach `localizedDescription`.
    func testDeveloperDetailDoesNotReachTheLocalizedDescription() {
        let error = SirosError.transactionData(TransactionDataError(.schemaViolation, detail: "payload/amount: expected number"))
        XCTAssertFalse(error.localizedDescription.contains("payload/amount"))
        XCTAssertFalse((error.errorDescription ?? "").contains("expected number"))
        XCTAssertTrue(error.localizedDescription.contains("schemaViolation"))
        XCTAssertTrue(TransactionDataError(.schemaViolation, detail: "payload/amount").description.contains("payload/amount"), "diagnostics keep it")
    }
}

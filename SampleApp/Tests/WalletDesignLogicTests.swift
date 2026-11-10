// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosCredentials
@testable import SirosSampleApp

/// The decisions behind the designed screens that are not layout: which
/// credentials count as needing attention (Home's banner and the Manage
/// credentials filter), what the two search fields match, and which day
/// heading a history record falls under. Kotlin twin: `WalletDesignLogicTest`.
final class WalletDesignLogicTests: XCTestCase {

    private func entry(_ id: Int64, name: String? = "PID", _ instances: CredentialInstance...) -> CredentialWithInstances {
        CredentialWithInstances(
            credential: StoredCredential(
                id: id, format: "dc+sd-jwt", raw: "",
                metadata: name.map { CredentialMetadata(name: $0, backgroundColor: "#224488", textColor: "#FFFFFF") },
                batchId: id, instanceId: 0
            ),
            instances: instances
        )
    }

    private let unused = CredentialInstance(instanceId: 0, sigCount: 0)
    private let used = CredentialInstance(instanceId: 1, sigCount: 1)

    func testAUsableCredentialNeedsNoAttention() {
        XCTAssertFalse(entry(1, unused).needsAttention(statuses: [:]))
        XCTAssertFalse(entry(1, unused).needsAttention(statuses: [1: .valid]))
    }

    func testAStatusThatStopsUseNeedsAttention() {
        for status in [CredentialStatus.expired, .revoked, .suspended] {
            XCTAssertTrue(entry(1, unused).needsAttention(statuses: [1: status]), "\(status)")
        }
        // Another credential's status says nothing about this one.
        XCTAssertFalse(entry(1, unused).needsAttention(statuses: [2: .expired]))
    }

    func testACredentialWithNoCopyLeftNeedsAttention() {
        XCTAssertTrue(entry(1, used).needsAttention(statuses: [:]))
        XCTAssertFalse(entry(1, used, unused).needsAttention(statuses: [:]))
    }

    func testACredentialPastItsOwnExpiryNeedsAttentionBeforeTheSdkHasEvaluatedIt() {
        let now = Date(timeIntervalSince1970: 2_000_000_000)
        func expiring(_ expSeconds: Int64?) -> CredentialWithInstances {
            CredentialWithInstances(
                credential: StoredCredential(
                    id: 1, format: "dc+sd-jwt", raw: "", expiresAt: expSeconds, batchId: 1, instanceId: 0
                ),
                instances: [unused]
            )
        }
        XCTAssertTrue(expiring(1_999_999_999).needsAttention(statuses: [:], now: now))
        XCTAssertFalse(expiring(2_000_000_060).needsAttention(statuses: [:], now: now))
        XCTAssertFalse(expiring(nil).needsAttention(statuses: [:], now: now))
        // Once the SDK has an answer, that answer stands.
        XCTAssertFalse(expiring(1_999_999_999).needsAttention(statuses: [1: .valid], now: now))
    }

    func testCredentialSearchMatchesWhatTheCardShows() {
        // No display metadata: the card resolves a title of its own, and that title is what a user types.
        let bare = StoredCredential(
            id: 3, format: "dc+sd-jwt", raw: "", credentialConfigurationId: "diploma", batchId: 3, instanceId: 0
        )
        let meta = CredentialUtils.buildFallbackMetadata(bare)
        let labels = cardLabels(name: meta.name, format: bare.format, typeId: cardTypeId(metadata: meta, credential: bare))
        XCTAssertTrue(bare.matchesSearch(labels.title))
        if let badge = labels.typeBadge { XCTAssertTrue(bare.matchesSearch(badge)) }
        XCTAssertFalse(bare.matchesSearch("passport"))
    }

    func testCredentialSearchMatchesTheListedName() {
        let pid = entry(1, name: "Person Identification Data", unused).credential
        XCTAssertTrue(pid.matchesSearch(""))
        XCTAssertTrue(pid.matchesSearch("   "))
        XCTAssertTrue(pid.matchesSearch("identif"))
        XCTAssertTrue(pid.matchesSearch(" PERSON "))
        XCTAssertFalse(pid.matchesSearch("diploma"))
        // Without display metadata a credential is listed under its format.
        XCTAssertTrue(entry(2, name: nil, unused).credential.matchesSearch("sd-jwt"))
    }

    func testHistorySearchCoversVerifierAndCredentials() {
        func matches(_ query: String) -> Bool {
            matchesHistoryQuery(verifierName: "Example Bank", credentialNames: ["Photo ID"], query: query)
        }
        XCTAssertTrue(matches(""))
        XCTAssertTrue(matches("bank"))
        XCTAssertTrue(matches("photo"))
        XCTAssertFalse(matches("library"))
        XCTAssertFalse(matchesHistoryQuery(verifierName: nil, credentialNames: [], query: "bank"))
    }

    func testHistoryDayHeadingsFollowTheLocalCalendarDay() throws {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = try XCTUnwrap(TimeZone(identifier: "Europe/Stockholm"))
        let locale = Locale(identifier: "en_GB")
        // 2026-06-04 12:00 UTC = 14:00 in Stockholm.
        let nowMillis: Int64 = 1_780_574_400_000
        let now = Date(timeIntervalSince1970: TimeInterval(nowMillis) / 1000)
        let hour: Int64 = 3_600_000
        func label(_ timestamp: Int64) -> String {
            historyDayLabel(
                timestamp: timestamp, now: now, today: "Today", yesterday: "Yesterday",
                calendar: calendar, locale: locale
            )
        }
        XCTAssertEqual(label(nowMillis), "Today")
        // 00:30 local the same day is 22:30 UTC the day before: still today.
        XCTAssertEqual(label(nowMillis - 13 * hour - hour / 2), "Today")
        // 23:30 local the day before.
        XCTAssertEqual(label(nowMillis - 14 * hour - hour / 2), "Yesterday")
        XCTAssertEqual(label(nowMillis - 24 * hour), "Yesterday")
        XCTAssertEqual(label(nowMillis - 72 * hour), "1 June 2026")
    }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosWallet
@testable import SirosSampleApp

final class WmpJoinStoreTests: XCTestCase {

    func testJoinedGroupAndLatestTokenRoundTrip() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("wmp-join-store-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = JsonFileWmpJoinStore(directory: directory)
        let record = WmpJoinRecord(
            providerUrl: "https://relay.example.com",
            sendUrl: "https://relay.example.com/wmp",
            sseUrl: "https://relay.example.com/wmp/events",
            sessionId: "ses-group-1",
            resumptionToken: "token-1",
            groupId: "group-1",
            groupName: "Echo re-run"
        )
        store.save(record)

        let rotated = WmpJoinRecord(
            providerUrl: record.providerUrl,
            sendUrl: record.sendUrl,
            sseUrl: record.sseUrl,
            sessionId: record.sessionId,
            resumptionToken: "token-2",
            groupId: record.groupId,
            groupName: record.groupName
        )
        store.save(rotated)

        let loaded = JsonFileWmpJoinStore(directory: directory).load()
        XCTAssertEqual(loaded, [rotated])
        XCTAssertEqual(loaded.first?.resumptionToken, "token-2")
        XCTAssertEqual(loaded.first?.groupName, "Echo re-run")
    }
}

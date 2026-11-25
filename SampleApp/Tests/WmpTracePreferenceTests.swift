// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosSampleApp

final class WmpTracePreferenceTests: XCTestCase {

    func testTraceDefaultsOffAndPersistsPerBackend() throws {
        let suiteName = "WmpTracePreferenceTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        defer { defaults.removePersistentDomain(forName: suiteName) }
        let engine = "engine"
        let invited = "https://relay.example/wmp"

        XCTAssertEqual(WmpTracePreference.key(for: invited), "wmp.trace.\(invited)")
        XCTAssertFalse(WmpTracePreference.isEnabled(for: engine, defaults: defaults))
        XCTAssertFalse(WmpTracePreference.isEnabled(for: invited, defaults: defaults))

        WmpTracePreference.set(true, for: invited, defaults: defaults)

        XCTAssertTrue(WmpTracePreference.isEnabled(for: invited, defaults: defaults))
        XCTAssertFalse(WmpTracePreference.isEnabled(for: engine, defaults: defaults))

        WmpTracePreference.set(false, for: invited, defaults: defaults)
        XCTAssertFalse(WmpTracePreference.isEnabled(for: invited, defaults: defaults))
    }
}

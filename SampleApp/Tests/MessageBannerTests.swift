// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import Foundation
@testable import SirosSampleApp

/// Unit tests for the pure (non-SwiftUI) logic behind the sample app's
/// localization and non-blocking message banner:
///
/// - `BannerMessage.autoDismissDuration` - the only genuinely testable piece
///   of `MessageBanner.swift`; the SwiftUI view itself (`MessageBannerView`,
///   `MessageBannerModifier`) can't be meaningfully unit-tested for visual
///   behavior, matching this file's sibling `WalletViewModelTests`.
/// - `en.json`/`sv.json` key-parity - a translated string table with a
///   missing key silently falls back to English at runtime (see
///   `L10n.string`'s doc comment) rather than failing loudly, so nothing
///   else would catch a key added to one language and forgotten in the
///   other.
///
/// Both pieces of logic are plain Foundation (`String`, `TimeInterval`,
/// `JSONSerialization`) with no SwiftUI/CryptoKit/UIKit dependency, so -
/// unlike the rest of this sample app - they don't inherently require a real
/// device/Xcode build to verify; see this repo's "iOS CryptoKit
/// verification gap" note for why that distinction matters here.
final class MessageBannerTests: XCTestCase {

    // MARK: - BannerMessage.autoDismissDuration

    func testInfoMessageAutoDismissesSoonerThanError() {
        let info = BannerMessage(kind: .info, text: "Saved")
        let error = BannerMessage(kind: .error, text: "Failed")

        // Mirrors the Kotlin sample app's SnackbarDuration.Long for errors
        // vs the default (shorter) duration for routine info toasts - see
        // MessageBanner.swift's doc comment.
        XCTAssertLessThan(info.autoDismissDuration, error.autoDismissDuration)
        XCTAssertGreaterThan(info.autoDismissDuration, 0)
        XCTAssertGreaterThan(error.autoDismissDuration, 0)
    }

    func testEachMessageGetsADistinctIdentity() {
        // Two structurally-identical messages must still compare unequal -
        // MessageBannerView's `.task(id: message.id)` auto-dismiss timer
        // relies on a genuinely fresh id to restart its countdown for a
        // repeat message (e.g. the same error firing twice in a row).
        let first = BannerMessage(kind: .error, text: "Network error")
        let second = BannerMessage(kind: .error, text: "Network error")

        XCTAssertNotEqual(first.id, second.id)
        XCTAssertNotEqual(first, second)
        XCTAssertEqual(first, first)
    }

    // MARK: - Translation table completeness (en.json / sv.json)

    /// Recursively flattens a JSON object into dot-path keys (e.g.
    /// `"flow.steps.unknown"`), mirroring `L10n.string`'s own dot-path
    /// lookup so this test walks the exact same key space the app does at
    /// runtime.
    private func flattenKeys(_ object: [String: Any], prefix: String = "") -> Set<String> {
        var keys = Set<String>()
        for (key, value) in object {
            let path = prefix.isEmpty ? key : "\(prefix).\(key)"
            if let nested = value as? [String: Any] {
                keys.formUnion(flattenKeys(nested, prefix: path))
            } else {
                keys.insert(path)
            }
        }
        return keys
    }

    private func loadTable(named name: String) throws -> [String: Any] {
        // SampleApp/Tests/MessageBannerTests.swift -> SampleApp/Resources/i18n/<name>.json
        let thisFile = URL(fileURLWithPath: #filePath)
        let url = thisFile
            .deletingLastPathComponent() // Tests/
            .deletingLastPathComponent() // SampleApp/
            .appendingPathComponent("Resources/i18n/\(name).json")
        let data = try Data(contentsOf: url)
        return try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    func testEnglishAndSwedishTablesHaveIdenticalKeySets() throws {
        let en = try flattenKeys(loadTable(named: "en"))
        let sv = try flattenKeys(loadTable(named: "sv"))

        XCTAssertEqual(en, sv, "en.json and sv.json must declare exactly the same set of dot-path keys")
    }

    func testEnglishAndSwedishTablesShareThePlaceholderShapePerKey() throws {
        // Not just "same keys" - a key whose EN value has a `%1$@`/`%1$d`
        // placeholder must have the same placeholder in its SV translation,
        // or `L10n.string(_:_:)`'s `String(format:)` call crashes/misformats
        // at the call site regardless of which language is active.
        func placeholders(_ value: String) -> [String] {
            let pattern = #"%\d+\$[@ds]"#
            guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
            let range = NSRange(value.startIndex..., in: value)
            return regex.matches(in: value, range: range).compactMap {
                Range($0.range, in: value).map { String(value[$0]) }
            }.sorted()
        }

        func flattenValues(_ object: [String: Any], prefix: String = "") -> [String: String] {
            var result: [String: String] = [:]
            for (key, value) in object {
                let path = prefix.isEmpty ? key : "\(prefix).\(key)"
                if let nested = value as? [String: Any] {
                    result.merge(flattenValues(nested, prefix: path)) { _, new in new }
                } else if let stringValue = value as? String {
                    result[path] = stringValue
                }
            }
            return result
        }

        let en = try flattenValues(loadTable(named: "en"))
        let sv = try flattenValues(loadTable(named: "sv"))

        for (key, enValue) in en {
            guard let svValue = sv[key] else { continue } // covered by the key-parity test above
            XCTAssertEqual(
                placeholders(enValue),
                placeholders(svValue),
                "Key '\(key)' has mismatched format placeholders between en.json and sv.json"
            )
        }
    }

    /// Guards against the exact crash this app hit on a real device: Darwin
    /// Foundation's `String(format:arguments:)` cannot format a Swift
    /// `String` argument through a bare `%s` specifier (only `%@` works) -
    /// see `L10n.string(_:_:)`'s doc comment. `%d`/`%ld` etc. are unaffected
    /// and legitimately expected for integer arguments (e.g.
    /// `credentials.countOther`), so this only flags `%s`.
    func testNoTranslationKeyUsesRawStringFormatSpecifier() throws {
        // Matches both the positional form (`%1$s`) and the bare form
        // (`%s`) - `String(format:)` accepts either, and both crash
        // identically for a Swift `String` argument on Darwin.
        let pattern = #"%(\d+\$)?s"#
        let regex = try XCTUnwrap(try? NSRegularExpression(pattern: pattern))

        for name in ["en", "sv"] {
            let values = try flattenKeysAndValues(loadTable(named: name))
            for (key, value) in values {
                let range = NSRange(value.startIndex..., in: value)
                let matches = regex.matches(in: value, range: range)
                XCTAssertTrue(matches.isEmpty, "\(name).json key '\(key)' uses %s (crashes on Darwin for String args) - use %@ instead")
            }
        }
    }

    private func flattenKeysAndValues(_ object: [String: Any], prefix: String = "") -> [(String, String)] {
        var result: [(String, String)] = []
        for (key, value) in object {
            let path = prefix.isEmpty ? key : "\(prefix).\(key)"
            if let nested = value as? [String: Any] {
                result.append(contentsOf: flattenKeysAndValues(nested, prefix: path))
            } else if let stringValue = value as? String {
                result.append((path, stringValue))
            }
        }
        return result
    }
}

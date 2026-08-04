// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Minimal loader for the dotted-key JSON string tables bundled at
/// `Resources/i18n/<language>.json` (e.g. `flow.steps.parsingOffer`).
///
/// These tables previously shipped in the app bundle but nothing loaded
/// them - every UI string was a hardcoded English literal. This is the
/// first consumer, scoped to the flow-progress feature (step labels,
/// diagnostic label, batch-received confirmation) rather than a
/// wholesale rewrite of the app's existing hardcoded strings.
enum L10n {
    private static let currentTable: [String: Any] = loadTable(for: currentLanguageCode())
    private static let fallbackTable: [String: Any] = loadTable(for: "en")

    private static func currentLanguageCode() -> String {
        Locale.preferredLanguages.first.flatMap { Locale(identifier: $0).language.languageCode?.identifier } ?? "en"
    }

    private static func loadTable(for languageCode: String) -> [String: Any] {
        guard let url = Bundle.main.url(forResource: languageCode, withExtension: "json", subdirectory: "i18n"),
              let data = try? Data(contentsOf: url),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return [:]
        }
        return obj
    }

    private static func lookup(_ table: [String: Any], _ path: [String]) -> String? {
        var current: Any = table
        for segment in path {
            guard let dict = current as? [String: Any], let next = dict[segment] else { return nil }
            current = next
        }
        return current as? String
    }

    /// Look up a dot-path key (e.g. "flow.steps.unknown"), falling back to
    /// English, then to the key itself if genuinely missing from both -
    /// mirrors Android strings.xml's fallback-to-default-locale behavior.
    static func string(_ key: String) -> String {
        let path = key.split(separator: ".").map(String.init)
        return lookup(currentTable, path) ?? lookup(fallbackTable, path) ?? key
    }

    /// Substitutes `%1$s`/`%1$d`-style placeholders via `String(format:)`,
    /// matching the printf-style specifiers already used throughout the
    /// bundled i18n JSON.
    static func string(_ key: String, _ args: CVarArg...) -> String {
        String(format: string(key), arguments: args)
    }
}

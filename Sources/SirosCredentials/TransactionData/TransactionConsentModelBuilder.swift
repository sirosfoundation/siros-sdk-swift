// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Builds the consent model from validated transaction data and the
/// attestation's type metadata (TS12 v1.0.1 sections 3.3.1 to 3.3.3).
///
/// Fails closed: a parameter without a localised name, or a missing required
/// UI label, ends processing ("the Wallet Unit SHALL cease processing the
/// transaction and inform the User", section 3.3.1).
struct TransactionConsentModelBuilder: Sendable {
    let source: any TransactionMetadataSource
    let fetchTimeout: TimeInterval
    let maxResourceBytes: Int

    /// Maximum string lengths from section 3.3.3.
    static let maxLengths = ["affirmative_action_label": 30, "denial_action_label": 30,
                             "transaction_title": 50, "security_hint": 250]

    func build(
        validated: ValidatedTransactionData,
        request: TransactionDataRequest,
        verifier: String,
        credentialName: String,
        requestSigned: Bool?,
        locale: String
    ) async throws -> TransactionConsentRequest {
        var entries: [TransactionConsentEntry] = []
        for entry in validated.entries {
            guard let queryId = entry.credentialIds.first,
                  let typeEntry = entry.typeMetadata[queryId]?.objectValue,
                  let credential = request.credentials.first(where: { $0.queryId == queryId }) else {
                throw TransactionDataError(.metadataUnavailable, detail: "no display metadata for the transaction type")
            }
            let pinPrefix = "transaction_data_types['\(entry.type)']."
            let claims = try await resource(
                inline: typeEntry["claims"], uri: typeEntry["claims_uri"], name: "claims",
                pin: credential.integrityClaims[pinPrefix + "claims_uri#integrity"]
            )
            let labels = try await resource(
                inline: typeEntry["ui_labels"], uri: typeEntry["ui_labels_uri"], name: "ui_labels",
                pin: credential.integrityClaims[pinPrefix + "ui_labels_uri#integrity"]
            )
            let fields = try fields(payload: entry.payload, claims: claims, locale: locale)
            let ui = try uiLabels(labels, locale: locale)
            entries.append(TransactionConsentEntry(
                title: ui["transaction_title"],
                typeName: TransactionDataBuiltIns.displayName(forType: entry.type),
                fields: fields,
                affirmativeLabel: try requireLabel(ui["affirmative_action_label"]),
                denialLabel: ui["denial_action_label"],
                securityHint: ui["security_hint"]
            ))
        }
        return TransactionConsentRequest(
            verifier: verifier, credentialName: credentialName, entries: entries,
            requestSigned: requestSigned, locale: locale
        )
    }

    private func requireLabel(_ label: String?) throws -> String {
        guard let label, !label.isEmpty else {
            throw TransactionDataError(.metadataUnavailable, detail: "affirmative_action_label is not available")
        }
        return label
    }

    // MARK: Referenced documents

    /// An embedded document or one referenced by URI (never both).
    private func resource(inline: JSONValue?, uri: JSONValue?, name: String, pin: String?) async throws -> JSONValue {
        switch (inline, uri) {
        case (.some, .some):
            throw TransactionDataError(.metadataUnavailable, detail: "\(name) given both inline and by URI")
        case (.none, .none):
            throw TransactionDataError(.metadataUnavailable, detail: "\(name) not provided")
        case (.some(let value), .none):
            return value
        case (.none, .some(let uriValue)):
            guard let uri = uriValue.stringValue, !uri.isEmpty else {
                throw TransactionDataError(.metadataUnavailable, detail: "\(name) URI is not a string")
            }
            let source = self.source
            let data: Data? = await withDeadline(fetchTimeout, fallback: nil) { await source.fetchResource(uri: uri) }
            guard let data, data.count <= maxResourceBytes else {
                throw TransactionDataError(.metadataUnavailable, detail: "\(name) URI could not be fetched")
            }
            if let pin, !Integrity.matches(data, pin) {
                throw TransactionDataError(.metadataUnavailable, detail: "\(name) content does not match its #integrity")
            }
            guard let parsed = try? StrictJSON.parse(data) else {
                throw TransactionDataError(.metadataUnavailable, detail: "\(name) content is not JSON")
            }
            return parsed
        }
    }

    // MARK: Fields

    private struct ClaimMeta {
        let path: [String?]
        let level: Int
        let labels: [(lang: String, text: String)]
        let order: Int
    }

    private func claimMetadata(_ claims: JSONValue) throws -> [ClaimMeta] {
        guard let list = claims.arrayValue else {
            throw TransactionDataError(.metadataUnavailable, detail: "claims is not an array")
        }
        return try list.enumerated().map { index, item in
            guard let object = item.objectValue, let rawPath = object["path"]?.arrayValue else {
                throw TransactionDataError(.metadataUnavailable, detail: "claim metadata without a path")
            }
            let path: [String?] = try rawPath.map {
                switch $0 {
                case .string(let s): return s
                case .null: return nil
                default: throw TransactionDataError(.metadataUnavailable, detail: "claim path element is not a string or null")
                }
            }
            var level = 3 // TS12 3.3.1: the default when none is set
            if let v = object["visualisation"] {
                guard case .int(let n) = v, (1...4).contains(n) else {
                    throw TransactionDataError(.metadataUnavailable, detail: "visualisation is not an integer from 1 to 4")
                }
                level = Int(n)
            }
            let labels: [(String, String)] = (object["display"]?.arrayValue ?? []).compactMap { d in
                guard let lang = d["lang"]?.stringValue ?? d["locale"]?.stringValue, let label = d["label"]?.stringValue,
                      !label.isEmpty else { return nil }
                return (lang, label)
            }
            return ClaimMeta(path: path, level: level, labels: labels, order: index)
        }
    }

    private func fields(payload: JSONValue, claims: JSONValue, locale: String) throws -> [TransactionConsentField] {
        let metadata = try claimMetadata(claims)
        var result: [(order: Int, field: TransactionConsentField)] = []
        for (path, value) in try leaves(of: payload) {
            let full: [String?] = ["payload"] + path
            guard let meta = metadata.first(where: { $0.path == full }) else {
                throw TransactionDataError(.metadataUnavailable, detail: "no claim metadata for a payload parameter")
            }
            guard let label = LocaleMatcher.pick(meta.labels, preferred: locale) else {
                // Level 4 may be left out of the display, so its name is not required.
                if meta.level == 4 { continue }
                throw TransactionDataError(.metadataUnavailable, detail: "no localised name for a payload parameter")
            }
            result.append((meta.order, TransactionConsentField(label: label, value: value, level: meta.level, path: path)))
        }
        return result.sorted { ($0.field.level, $0.order) < ($1.field.level, $1.order) }.map(\.field)
    }

    /// Every leaf of the payload with its path (`nil` for an array element)
    /// and its value as text. Object keys are visited in sorted order so the
    /// result is deterministic; display order comes from the claim metadata.
    private func leaves(of value: JSONValue, path: [String?] = []) throws -> [([String?], String)] {
        switch value {
        case .object(let members):
            return try members.keys.sorted().flatMap { try leaves(of: members[$0]!, path: path + [$0]) }
        case .array(let items):
            return try items.flatMap { try leaves(of: $0, path: path + [nil]) }
        default:
            return [(path, try text(of: value))]
        }
    }

    private func text(of value: JSONValue) throws -> String {
        switch value {
        case .string(let s): return s
        case .bool(let b): return b ? "true" : "false"
        case .null: return "null"
        case .int(let i): return String(i)
        case .decimal(let text):
            // The number exactly as the verifier wrote it. Exponent notation is
            // not shown: it would not read as what was sent.
            guard !text.lowercased().contains("e") else {
                throw TransactionDataError(.invalidEntry, detail: "a number cannot be displayed exactly")
            }
            return text
        case .double:
            // Only a lossy source (never a parsed payload) yields a double.
            throw TransactionDataError(.invalidEntry, detail: "a number cannot be displayed exactly")
        default: throw TransactionDataError(.invalidEntry, detail: "unexpected container value")
        }
    }

    // MARK: UI labels

    private func uiLabels(_ catalogue: JSONValue, locale: String) throws -> [String: String] {
        guard let object = catalogue.objectValue else {
            throw TransactionDataError(.metadataUnavailable, detail: "ui_labels is not an object")
        }
        var result: [String: String] = [:]
        for (key, maxLength) in Self.maxLengths {
            guard let variants = object[key] else { continue }
            guard let list = variants.arrayValue else {
                throw TransactionDataError(.metadataUnavailable, detail: "\(key) is not an array")
            }
            let options: [(String, String)] = list.compactMap { v in
                guard let lang = v["lang"]?.stringValue, let value = v["value"]?.stringValue else { return nil }
                return (lang, value)
            }
            guard let chosen = LocaleMatcher.pick(options, preferred: locale) else { continue }
            guard chosen.unicodeScalars.count <= maxLength else {
                throw TransactionDataError(.metadataUnavailable, detail: "\(key) exceeds \(maxLength) characters")
            }
            result[key] = chosen
        }
        return result
    }
}

/// Picks the best localised string for a preferred BCP 47 tag: exact match,
/// then same primary language, then English, then the first offered.
enum LocaleMatcher {
    static func pick(_ options: [(lang: String, text: String)], preferred: String) -> String? {
        guard !options.isEmpty else { return nil }
        func norm(_ s: String) -> String { s.lowercased().replacingOccurrences(of: "_", with: "-") }
        func primary(_ s: String) -> String { String(norm(s).split(separator: "-").first ?? "") }
        let want = norm(preferred)
        if let exact = options.first(where: { norm($0.lang) == want }) { return exact.text }
        if let same = options.first(where: { primary($0.lang) == primary(want) }) { return same.text }
        if let english = options.first(where: { primary($0.lang) == "en" }) { return english.text }
        return options[0].text
    }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

#if canImport(CryptoKit)

extension JweKeystore {

    /// The credential's `S.credentials[].metadata` entries, each
    /// `{"type": String, "value": <any JSON>}`, or nil when it has none - or
    /// when the stored member is not a well-formed array of such objects
    /// (it is then still written back verbatim on export, just not
    /// interpreted).
    ///
    /// Values are JSON as `JSONSerialization` models it: strings, booleans,
    /// null, arrays and objects are exact; numbers are value-exact (integers
    /// within `Int64`, doubles as the nearest `Double`) but not byte-exact
    /// (`1.0` comes back `1`, big or high-precision decimals are not kept as
    /// written), and object key order is not kept.
    public func credentialMetadata(id: Int64) async -> [[String: Any]]? {
        mutex.lock()
        defer { mutex.unlock() }
        guard let raw = credentialMetadata[id] as? [Any], !raw.isEmpty else { return nil }
        var entries: [[String: Any]] = []
        for element in raw {
            guard let entry = element as? [String: Any],
                  let type = entry["type"] as? String, !type.isEmpty,
                  entry["value"] != nil else { return nil }
            entries.append(entry)
        }
        return entries
    }

    /// Replace the credential's `metadata` entries; nil or empty removes the
    /// member (it is never written as null or `[]`). Every entry needs a
    /// non-empty string `type` and a `value` (any JSON, null included),
    /// and the credential must exist. Written to `S.credentials[].metadata`
    /// by the next `exportEncryptedContainer`.
    public func setCredentialMetadata(id: Int64, _ entries: [[String: Any]]?) async throws {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        guard credentials[id] != nil else {
            throw KeystoreError.invalidParameter("no credential \(id)")
        }
        guard let entries, !entries.isEmpty else {
            credentialMetadata.removeValue(forKey: id)
            return
        }
        for entry in entries {
            guard let type = entry["type"] as? String, !type.isEmpty, entry["value"] != nil else {
                throw KeystoreError.invalidParameter("metadata entries need a non-empty string `type` and a `value`")
            }
        }
        guard JSONSerialization.isValidJSONObject(entries) else {
            throw KeystoreError.invalidParameter("metadata is not valid JSON")
        }
        credentialMetadata[id] = entries
    }
}

#endif

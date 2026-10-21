// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

/// How `S.credentials[]` and `S.keypairs[]` are rebuilt on export.
///
/// Both lists are driven by the keystore's in-memory state (that is the source
/// of truth once unlocked), but each entry starts from the entry the loaded
/// container carried, so that everything this build does not own is written back
/// with an identical value (privatedata-spec section 6: "unknown members and
/// metadata MUST be preserved"), and the array order is the loaded container's,
/// with new entries appended. Taking these as plain arguments, rather than as
/// `JweKeystore` members, keeps them free of the keystore's lock and testable
/// without one.
enum WalletStateEntries {

    // MARK: - Credentials

    static func credentialEntries(credentials: [Int64: String], existingS: [String: Any]?) -> [[String: Any]] {
        var originals: [Int64: [String: Any]] = [:]
        for case let entry as [String: Any] in (existingS?["credentials"] as? [Any]) ?? [] {
            if let id = int64(entry["credentialId"]) { originals[id] = entry }
        }
        let order = positions(of: existingS?["credentials"]) { int64($0["credentialId"]) }
        return credentials.keys.sorted { inOrder($0, $1, order) }.compactMap { id in
            credentials[id].map { credentialEntry(id: id, data: $0, original: originals[id]) }
        }
    }

    /// One entry. The eight members of section 6.0 come from the original entry
    /// when there is one, else from the credential's own saved JSON (a credential
    /// added THIS session has no entry in the loaded container yet; without that
    /// fallback its batchId/instanceId would reset to 0 on every export until the
    /// container is reloaded once). Every other member is the original's, as is.
    private static func credentialEntry(id: Int64, data: String, original: [String: Any]?) -> [String: Any] {
        let parsed = (try? JSONSerialization.jsonObject(with: Data(data.utf8))) as? [String: Any]
        var entry: [String: Any] = original ?? [:]
        entry["credentialId"] = id
        entry["format"] = (original?["format"] as? String) ?? (parsed?["format"] as? String) ?? ""
        entry["data"] = (original?["data"] as? String) ?? (parsed?["raw"] as? String) ?? data
        entry["kid"] = (original?["kid"] as? String) ?? (parsed?["kid"] as? String) ?? ""
        entry["instanceId"] = int(original?["instanceId"]) ?? int(parsed?["instance_id"]) ?? 0
        entry["batchId"] = int64(original?["batchId"]) ?? int64(parsed?["batch_id"]) ?? 0
        entry["credentialIssuerIdentifier"] = (original?["credentialIssuerIdentifier"] as? String)
            ?? (parsed?["credential_issuer_identifier"] as? String) ?? ""
        entry["credentialConfigurationId"] = (original?["credentialConfigurationId"] as? String)
            ?? (parsed?["credential_configuration_id"] as? String) ?? ""
        // `metadata: null` and `metadata: []` read as "no metadata", and a writer MUST NOT emit either.
        entry["metadata"] = WalletStateSchema.writableMetadata(entry["metadata"])
        return entry
    }

    // MARK: - Keypairs

    #if canImport(CryptoKit)
    static func keypairEntries(
        keys: [String: P256.Signing.PrivateKey],
        keyDids: [String: String],
        existingS: [String: Any]?
    ) -> [[String: Any]] {
        let existing = (existingS?["keypairs"] as? [Any])?.compactMap { $0 as? [String: Any] } ?? []
        func kid(_ entry: [String: Any]) -> String? { (entry["keypair"] as? [String: Any])?["kid"] as? String }
        // Existing entries stay where they were, rebuilt when this build loaded the
        // key and carried verbatim when it could not (not a P-256 JWK, say; nothing
        // removes keys, so such an entry is not dropped). Keys new this session
        // follow, by kid.
        var seen = Set<String>()
        var entries: [[String: Any]] = existing.map { entry in
            guard let k = kid(entry), let key = keys[k] else { return entry }
            seen.insert(k)
            return keypairEntry(kid: k, key: key, did: keyDids[k], original: entry)
        }
        for k in keys.keys.sorted() where !seen.contains(k) {
            if let key = keys[k] { entries.append(keypairEntry(kid: k, key: key, did: keyDids[k], original: nil)) }
        }
        return entries
    }

    private static func keypairEntry(
        kid: String, key: P256.Signing.PrivateKey, did: String?, original: [String: Any]?
    ) -> [String: Any] {
        let x963 = key.publicKey.x963Representation
        let x = EncryptedContainer.base64UrlEncode(Data(x963[1..<33]))
        let y = EncryptedContainer.base64UrlEncode(Data(x963[33..<65]))
        let originalKeypair = original?["keypair"] as? [String: Any]
        // A key generated this session knows its own DID; otherwise preserve
        // whatever the loaded container recorded. Never recomputed, so a wallet
        // reconfigured to a different `didKeyVersion` cannot re-identify a key.
        var keypair = originalKeypair ?? [:]
        keypair["kid"] = kid
        keypair["did"] = did ?? originalKeypair?["did"] as? String ?? ""
        keypair["alg"] = "ES256"
        keypair["publicKey"] = ["kty": "EC", "crv": "P-256", "x": x, "y": y]
        keypair["privateKey"] = [
            "kty": "EC", "crv": "P-256", "x": x, "y": y,
            "d": EncryptedContainer.base64UrlEncode(key.rawRepresentation),
        ]
        var entry = original ?? [:]
        entry["kid"] = kid
        entry["keypair"] = keypair
        return entry
    }
    #endif

    // MARK: - Order and number coercion

    /// Position of each keyed element of a JSON array, first occurrence winning.
    private static func positions<Key: Hashable>(of array: Any?, key: ([String: Any]) -> Key?) -> [Key: Int] {
        var result: [Key: Int] = [:]
        for (index, element) in ((array as? [Any]) ?? []).enumerated() {
            if let object = element as? [String: Any], let k = key(object), result[k] == nil { result[k] = index }
        }
        return result
    }

    /// Entries the container already had come first, in its order; new ones follow, by key.
    private static func inOrder<Key: Comparable & Hashable>(_ lhs: Key, _ rhs: Key, _ order: [Key: Int]) -> Bool {
        switch (order[lhs], order[rhs]) {
        case let (l?, r?): return l < r
        case (.some, nil): return true
        case (nil, .some): return false
        case (nil, nil): return lhs < rhs
        }
    }

    /// A JSON number, or a number-as-string (a not-yet-migrated container may
    /// still quote a privatedata-spec `number` field).
    private static func int64(_ value: Any?) -> Int64? {
        if let n = value as? NSNumber { return n.int64Value }
        if let s = value as? String { return Int64(s) }
        return nil
    }

    private static func int(_ value: Any?) -> Int? { int64(value).flatMap { Int(exactly: $0) } }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials

/// Persists the holder state a blind BBS credential cannot be presented
/// without.
///
/// # Why this exists at all
///
/// A JWP carries the issuer's claims and the signature. It deliberately does
/// not carry the holder's blinding factor, its committed values, or which
/// device key the credential is bound to - publishing those would undo the
/// point of blind issuance. So they live beside the credential, and without
/// them the credential is not degraded but *unusable*: there is no way to
/// reconstruct a blinding factor after the fact.
///
/// That is why this is written to the synchronised container rather than to
/// device-local storage. A credential issued on one device and restored on
/// another has to remain presentable.
///
/// # Where it lives
///
/// `S.extensions["org.siros.bbs"]`, keyed by credential id - privatedata-spec
/// §6.1. The key names one credential, never "bbs" or a subsystem, because
/// resolution is last-write-wins per entry: an aggregate entry would let two
/// devices storing different credentials' state overwrite each other.
///
/// The entry value is byte-compatible with siros-sdk-kotlin's
/// `BbsHolderStateVault`, so a credential issued by either SDK is presentable
/// by the other.
public final class BbsHolderStateVault: Sendable {

    /// privatedata-spec §6.1.6 registry entry.
    public static let namespace = "org.siros.bbs"

    private let keystore: any ExtensionStore

    /// - Parameter keystore: the container this state is stored in. Must be
    ///   unlocked. Typed as `ExtensionStore` rather than a concrete keystore
    ///   because both container owners qualify and this has no reason to
    ///   know which one it has.
    public init(keystore: any ExtensionStore) {
        self.keystore = keystore
    }

    /// Store the state produced by accepting an issued credential.
    ///
    /// - Parameter credentialId: identifies the credential this state belongs
    ///   to, and becomes the entry key. Must be the same value used to look
    ///   the state up at presentation time.
    public func put(credentialId: String, state: BbsHolderState) async throws {
        try await keystore.setExtensionEntry(namespace: Self.namespace, key: credentialId, value: Self.encode(state))
    }

    /// Look up the state for a credential, or `nil` if none is stored.
    ///
    /// A `nil` here means the credential cannot be presented - never that it
    /// can be presented without binding. An entry that does not decode reads
    /// the same way: the caller's contract is already "nil means this cannot
    /// be presented", and surfacing a decode failure as an error from a
    /// lookup would give it a second way to fail with the same meaning.
    public func get(credentialId: String) async -> BbsHolderState? {
        guard let raw = await keystore.extensionEntries(namespace: Self.namespace)[credentialId] else { return nil }
        return Self.decode(raw)
    }

    /// Drop the state for a credential.
    ///
    /// privatedata-spec §6.1.2 requires that deleting the entity an entry
    /// names deletes the entry, so this must be called when the credential
    /// is deleted. Left behind, the entry is a long-lived secret belonging to
    /// a credential that no longer exists.
    public func remove(credentialId: String) async throws {
        try await keystore.removeExtensionEntry(namespace: Self.namespace, key: credentialId)
    }

    /// Every credential id this container holds BBS state for.
    public func credentialIds() async -> Set<String> {
        Set(await keystore.extensionEntries(namespace: Self.namespace).keys)
    }

    // MARK: - Encoding

    // The stored shape - siros-sdk-kotlin's `BbsHolderStateVault.Stored`:
    //
    //   {"issuerPublicKey": "<b64url>", "secretProverBlind": "<b64url>",
    //    "committedMessages": ["<b64url>", ...], "keybindPublicKeys": ["<b64url>", ...]}
    //
    // Byte arrays are base64url (unpadded) because the entry value is a
    // string: §6.1 makes an entry an opaque *string* so that a client which
    // does not implement the namespace can still carry it without knowing
    // how to encode whatever is inside.
    //
    // Assembled by hand rather than through JSONEncoder so the output is
    // deterministic and identical to what Kotlin writes for the same state
    // (kotlinx.serialization emits fields in declaration order, with no
    // whitespace). That is safe here only because every value is base64url,
    // whose alphabet (A-Z a-z 0-9 - _) contains nothing JSON needs to escape.
    static func encode(_ state: BbsHolderState) -> String {
        func quoted(_ bytes: [UInt8]) -> String { "\"\(b64(bytes))\"" }
        func list(_ items: [[UInt8]]) -> String { "[" + items.map(quoted).joined(separator: ",") + "]" }
        return "{\"issuerPublicKey\":\(quoted(state.issuerPublicKey))"
            + ",\"secretProverBlind\":\(quoted(state.secretProverBlind))"
            + ",\"committedMessages\":\(list(state.committedMessages))"
            + ",\"keybindPublicKeys\":\(list(state.keybindPublicKeys))}"
    }

    // Unknown keys are ignored (Kotlin decodes with `ignoreUnknownKeys`);
    // a missing or mistyped field, or a value that is not base64url, reads
    // as undecodable.
    static func decode(_ raw: String) -> BbsHolderState? {
        guard let object = try? JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any],
              let issuerPublicKey = (object["issuerPublicKey"] as? String).flatMap(unb64),
              let secretProverBlind = (object["secretProverBlind"] as? String).flatMap(unb64),
              let committedMessages = (object["committedMessages"] as? [String]).flatMap(unb64List),
              let keybindPublicKeys = (object["keybindPublicKeys"] as? [String]).flatMap(unb64List) else {
            return nil
        }
        return BbsHolderState(
            issuerPublicKey: issuerPublicKey,
            secretProverBlind: secretProverBlind,
            committedMessages: committedMessages,
            keybindPublicKeys: keybindPublicKeys
        )
    }

    private static func b64(_ bytes: [UInt8]) -> String {
        EncryptedContainer.base64UrlEncode(Data(bytes))
    }

    private static func unb64(_ value: String) -> [UInt8]? {
        var base64 = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder != 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        return Data(base64Encoded: base64).map { [UInt8]($0) }
    }

    private static func unb64List(_ values: [String]) -> [[UInt8]]? {
        var result: [[UInt8]] = []
        result.reserveCapacity(values.count)
        for value in values {
            guard let bytes = unb64(value) else { return nil }
            result.append(bytes)
        }
        return result
    }
}

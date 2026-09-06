// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Namespaced client-defined state in the synchronised container -
/// privatedata-spec §6.1 `S.extensions`.
///
/// # Why this is a protocol rather than three more methods on a keystore
///
/// Two classes own a container: `JweKeystore` directly, and
/// `WscdKeystoreAdapter` through the `JweKeystore` it keeps for credentials
/// while the WSCD holds the signing keys. A caller that wants to store
/// extension state has one of them, does not know which, and must not care -
/// `setCredentialRefreshToken` is already reached by casting to each concrete
/// class in turn, which is one more call site to forget every time another
/// container owner appears.
///
/// # The contract
///
/// A namespace is a reverse-DNS string; an entry key MUST name a single
/// entity the wallet already tracks - a credential id, a kid, a batch id -
/// and MUST NOT name a subsystem or a plugin (§6.1.1). Resolution between two
/// devices is last-write-wins per entry, so an entry keyed by subsystem makes
/// one device's write discard the other's.
///
/// Values are opaque strings, and that is the point: a client that has never
/// heard of a namespace can still carry it faithfully, which is what makes
/// staggered adoption across clients safe.
public protocol ExtensionStore: AnyObject, Sendable {

    /// One namespace's entries.
    ///
    /// An absent namespace reads as an empty dictionary rather than an error:
    /// a namespace only exists once something writes to it. A locked store
    /// reads the same way, since it holds no entries and the caller's
    /// contract for an empty answer already covers "not available".
    func extensionEntries(namespace: String) async -> [String: String]

    /// Write one entry, so it survives to the next unlock on this device or
    /// any other sharing this account.
    ///
    /// - Parameter key: MUST name a single entity (§6.1.1) - see the protocol
    ///   doc.
    /// - Throws: `KeystoreError.locked` if the store is locked. The write
    ///   would have nowhere to land, and an entry whose value cannot be
    ///   recomputed must not be lost silently.
    func setExtensionEntry(namespace: String, key: String, value: String) async throws

    /// Remove one entry.
    ///
    /// §6.1.2 requires that deleting the entity an entry names deletes the
    /// entry; this is how a caller honours that.
    ///
    /// - Throws: `KeystoreError.locked` if the store is locked - a deletion
    ///   that appears to succeed would leave the entry in the container.
    func removeExtensionEntry(namespace: String, key: String) async throws
}

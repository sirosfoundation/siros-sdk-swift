// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

// The wallet's MLS crypto (issue #77 + the wmp-mls spec, RFC 9420):
// in-process OpenMLS via the UniFFI bindings — the same Rust `wmp-mls`
// crate the engine runs, one crypto everywhere (wmp-mls.md §5: the relay
// is the Delivery Service; it routes and queues ciphertext, it never
// holds plaintext).
//
// The FFI dependency is iOS-conditioned (the XCFramework ships iOS
// slices only): the whole file self-gates on `canImport`, so the module
// compiles empty everywhere the framework is absent (the generated
// bindings' own pattern). Kotlin parity:
// `org.siros.sdk.transport.wmp.WmpMlsCrypto` — the JVM loads the .so at
// runtime instead, so the Kotlin surface is unconditional.
#if canImport(engine_adapter_sdkFFI)
import engine_adapter_sdkFFI

/// The wallet's MLS member crypto: ONE provider per identity (one
/// identity, one key store), the groups it belongs to.
public final class WmpMlsCrypto: @unchecked Sendable {

    private let inner: WmpMls

    /// A provider for the member `identity`.
    public init(identity: String) throws {
        self.inner = try WmpMls(identity: identity)
    }

    /// The member's identity (the string the constructor took).
    public var identity: String { inner.identity() }

    /// A fresh KeyPackage (spec §2.3) for the suite: publish it on the
    /// member's well-known for the add flows.
    public func generateKeyPackage(cipherSuite: Int64) throws -> MlsKeyPackage {
        let it = try inner.generateKeyPackage(cipherSuite: cipherSuite)
        return MlsKeyPackage(id: it.id, cipherSuite: it.cipherSuite, keyPackage: it.keyPackage)
    }

    /// Create a group (spec §3.1): THIS member's group, epoch 0. The
    /// members join by the add flow (`addMember`) once their
    /// KeyPackages are at hand.
    public func createGroup(cipherSuite: Int64) throws -> MlsGroupCreated {
        let it = try inner.createGroup(cipherSuite: cipherSuite)
        return MlsGroupCreated(groupId: it.groupId, epoch: it.epoch)
    }

    /// Process a Welcome (spec §3.2): the member joins the group, the
    /// epoch it joined at. The Welcome rides the invitation or the
    /// group's message passing (out of band).
    public func processWelcome(welcome: String) throws -> MlsJoined {
        let it = try inner.processWelcome(welcome: welcome)
        return MlsJoined(groupId: it.groupId, epoch: it.epoch)
    }

    /// Stage an add (spec §3.3): the commit for the group (merged into
    /// this member's copy), the Welcome for the added member.
    public func addMember(groupId: String, keyPackage: String) throws -> MlsAddStaged {
        let it = try inner.addMember(groupId: groupId, keyPackage: keyPackage)
        return MlsAddStaged(commit: it.commit, welcome: it.welcome)
    }

    /// Stage a removal (spec §3.4): the commit (merged here) that
    /// cryptographically excludes the participant.
    public func removeMember(groupId: String, participant: String) throws -> String {
        try inner.removeMember(groupId: groupId, participant: participant)
    }

    /// Process a commit (a staged add/remove/update this member
    /// receives): the epoch it advanced to (the commit is merged).
    public func processCommit(groupId: String, commit: String) throws -> Int64 {
        try inner.processCommit(groupId: groupId, commit: commit)
    }

    /// A self-update commit (spec §3.5): the post-compromise rotation,
    /// merged here. Hand the commit to the group's other members.
    public func selfUpdate(groupId: String) throws -> String {
        try inner.selfUpdate(groupId: groupId)
    }

    /// Encrypt a message body to the group's current epoch key
    /// (spec §4.1): the base64url MLSMessage + the epoch. The relay
    /// carries this ciphertext opaque.
    public func encrypt(groupId: String, plaintext: [UInt8]) throws -> MlsEncrypted {
        // The v0.3.8-generated bindings take Data (the regenerated
        // surface — the [UInt8] form was the pre-#98 bindgen's).
        let it = try inner.encrypt(groupId: groupId, plaintext: Data(plaintext))
        return MlsEncrypted(ciphertext: it.ciphertext, epoch: it.epoch)
    }

    /// Decrypt the group's ciphertext (spec §4.1): the plaintext + the
    /// epoch. A message this member sent itself refuses (MLS ratchets —
    /// the recipient's provider answers).
    public func decrypt(groupId: String, ciphertext: String) throws -> MlsDecrypted {
        let it = try inner.decrypt(groupId: groupId, ciphertext: ciphertext)
        return MlsDecrypted(plaintext: it.plaintext, epoch: it.epoch)
    }
}

#endif  // canImport(engine_adapter_sdkFFI)

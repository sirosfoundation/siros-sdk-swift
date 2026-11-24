// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
#if canImport(engine_adapter_sdkFFI)
import engine_adapter_sdkFFI
import EngineAdapterSdk

/// The wallet's MLS crypto, round-tripped (the wmp-mls spec, RFC 9420):
/// two members, one group, the messages between them — the same
/// functions the Kotlin test drives (`WmpMlsCryptoTest`) and the Rust
/// FFI test (`engine-adapter-sdk/tests/mls_ffi.rs`), against the same
/// native library the app ships.
///
/// The FFI is iOS-only (the XCFramework): this suite runs where the
/// framework loads (the iOS CI). The Kotlin suite holds the executed
/// proof on the JVM (`WALLET_CORE_NATIVE` names the wallet-core target).
final class WmpMlsCryptoTests: XCTestCase {

    /// The X25519 suite (0x0001, the MUST).
    private let suite: Int64 = 1

    private func memberLoadable() -> Bool {
        (try? WmpMlsCrypto(identity: "probe").identity) != nil
    }

    private func member(_ identity: String) throws -> WmpMlsCrypto {
        try WmpMlsCrypto(identity: identity)
    }

    func testACreateAddsAMemberWhoJoinsAndSharesTheGroupId() throws {
        try XCTSkipUnless(memberLoadable(), "the native MLS library is not loaded")
        let alice = try member("alice")
        let bob = try member("bob")

        // The group (spec §3.1): the create mints alone, epoch 0.
        let group = try alice.createGroup(cipherSuite: suite)
        XCTAssertEqual(group.epoch, 0)

        // Bob's KeyPackage (spec §2.3) — the add flow's input.
        let keyPackage = try bob.generateKeyPackage(cipherSuite: suite)
        XCTAssertGreaterThan(keyPackage.keyPackage.count, 32)

        // The add (spec §3.3): the commit + the Welcome for Bob.
        let staged = try alice.addMember(groupId: group.groupId, keyPackage: keyPackage.keyPackage)
        XCTAssertFalse(staged.commit.isEmpty)
        XCTAssertFalse(staged.welcome.isEmpty)

        // Bob joins (spec §3.2): the SAME group id (the MLS GroupId from
        // the shared GroupContext), the post-add epoch.
        let joined = try bob.processWelcome(welcome: staged.welcome)
        XCTAssertEqual(joined.groupId, group.groupId, "the join answers the creator's group id")
        XCTAssertGreaterThanOrEqual(joined.epoch, 1, "the join answers the post-add epoch")
    }

    func testTwoMembersRoundTripAMessage() throws {
        try XCTSkipUnless(memberLoadable(), "the native MLS library is not loaded")
        let alice = try member("alice")
        let bob = try member("bob")
        let group = try alice.createGroup(cipherSuite: suite)
        let keyPackage = try bob.generateKeyPackage(cipherSuite: suite)
        let staged = try alice.addMember(groupId: group.groupId, keyPackage: keyPackage.keyPackage)
        _ = try bob.processWelcome(welcome: staged.welcome)

        // The message (spec §4.1): Alice encrypts to the epoch key, Bob
        // decrypts. MLS ratchets: Alice's own provider refuses her own
        // ciphertext (the recipient's provider answers).
        let plaintext = Data("hello from alice, under the epoch key".utf8)
        let sent = try alice.encrypt(groupId: group.groupId, plaintext: plaintext)
        XCTAssertGreaterThanOrEqual(sent.epoch, 1)
        XCTAssertFalse(sent.ciphertext.isEmpty)

        let received = try bob.decrypt(groupId: group.groupId, ciphertext: sent.ciphertext)
        XCTAssertEqual(received.plaintext, plaintext)
        XCTAssertEqual(received.epoch, sent.epoch)

        XCTAssertThrowsError(
            try alice.decrypt(groupId: group.groupId, ciphertext: sent.ciphertext),
            "own ciphertexts do not decrypt (MLS ratchets)"
        )
    }

    func testARemovalAdvancesTheEpoch() throws {
        try XCTSkipUnless(memberLoadable(), "the native MLS library is not loaded")
        let alice = try member("alice")
        let bob = try member("bob")
        let group = try alice.createGroup(cipherSuite: suite)
        let keyPackage = try bob.generateKeyPackage(cipherSuite: suite)
        let staged = try alice.addMember(groupId: group.groupId, keyPackage: keyPackage.keyPackage)
        let joined = try bob.processWelcome(welcome: staged.welcome)

        // The removal (spec §3.4): the commit excludes Bob cryptographically;
        // the merge advances the epoch.
        let commit = try alice.removeMember(groupId: group.groupId, participant: "bob")
        let advanced = try bob.processCommit(groupId: joined.groupId, commit: commit)
        XCTAssertGreaterThan(advanced, joined.epoch, "the epoch advanced")
    }

    func testUnknownGroupOperationsRefuse() throws {
        try XCTSkipUnless(memberLoadable(), "the native MLS library is not loaded")
        let alice = try member("alice")
        XCTAssertThrowsError(try alice.encrypt(groupId: "grp-none", plaintext: [1, 2, 3])) { error in
            let text = String(describing: error)
            XCTAssertTrue(
                text.contains("unknown group"),
                "the refusal names the cause (the wallets' logs need it): \(text)"
            )
        }
    }

    func testTheIdentityAnswersItsConstructor() throws {
        try XCTSkipUnless(memberLoadable(), "the native MLS library is not loaded")
        XCTAssertEqual(try member("alice@example").identity, "alice@example")
    }
}
#endif  // canImport(engine_adapter_sdkFFI)

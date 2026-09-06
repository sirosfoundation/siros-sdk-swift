// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

// iOS-only, like everything else BBS here - see BbsIssuanceParticipant.swift.
// Nothing below touches the native library; the gate is only because the
// types it constructs live behind one.
#if os(iOS)

import Foundation
import XCTest
@testable import SirosCredentials

/// The encoding contract at the boundary between
/// `ZkIssuancePreparation.credentialRequestFields` and the transport.
///
/// The map's values are pre-encoded JSON *strings*, deliberately: they are
/// covered by the commitment proof, and re-encoding a value a signature
/// covers is how the two ends stop agreeing about what was signed. The
/// wallet therefore parses them rather than building them again - which
/// only works if every value really is well-formed JSON, including for
/// claim names the wallet did not choose.
///
/// These construct the preparation directly rather than through
/// `prepare`, so they need no commitment from the native library: the
/// encoding under test is pure Swift either way.
///
/// Mirrors Kotlin's `BbsCredentialRequestFieldsTest`.
final class BbsCredentialRequestFieldsTests: XCTestCase {

    private func preparation(
        pointers: [String],
        keybindPublicKeys: [[UInt8]] = [],
        suiteId: BbsSuiteId = .schnorr
    ) -> BbsIssuancePreparation {
        BbsIssuancePreparation(
            suiteId: suiteId,
            commitmentWithProof: (0..<48).map { UInt8($0) },
            holderPointers: pointers,
            committedMessages: pointers.map { Array($0.utf8) },
            secretProverBlind: [UInt8](repeating: 7, count: 32),
            keybindPublicKeys: keybindPublicKeys
        )
    }

    /// Parses one pre-encoded member; a value that is not JSON fails the
    /// test right here, which is the assertion.
    private func parse(_ encoded: String) throws -> Any {
        try JSONSerialization.jsonObject(with: Data(encoded.utf8), options: [.fragmentsAllowed])
    }

    private func field(_ fields: [String: String], _ name: String) throws -> String {
        try XCTUnwrap(fields[name], "\(name) missing from the credential request fields")
    }

    func testEveryFieldIsWellFormedJson() throws {
        let fields = preparation(pointers: ["/device_pin_hash", "/recovery_secret"]).credentialRequestFields

        XCTAssertEqual(Set(fields.keys), [
            BbsIssuanceParticipant.commitmentField,
            BbsIssuanceParticipant.pointersField,
            BbsIssuanceParticipant.keyBindingField,
            BbsIssuanceParticipant.suiteField,
        ])
        for (member, encoded) in fields {
            XCTAssertFalse(encoded.isEmpty, "\(member) must not be empty")
            XCTAssertNoThrow(try parse(encoded), "\(member) must be well-formed JSON: \(encoded)")
        }
    }

    /// The wire names are the contract with the issuer, so they are pinned
    /// here as literals rather than read back off the constants.
    func testTheWireNamesAreExactlyWhatTheIssuerReads() {
        XCTAssertEqual(BbsIssuanceParticipant.commitmentField, "bbs_commitment")
        XCTAssertEqual(BbsIssuanceParticipant.pointersField, "bbs_committed_claims")
        XCTAssertEqual(BbsIssuanceParticipant.keyBindingField, "bbs_key_binding")
        XCTAssertEqual(BbsIssuanceParticipant.suiteField, "bbs_suite")
    }

    func testTheCommitmentIsBase64UrlWithoutPadding() throws {
        let fields = preparation(pointers: ["/a"]).credentialRequestFields
        let commitment = try XCTUnwrap(
            try parse(try field(fields, BbsIssuanceParticipant.commitmentField)) as? String
        )

        XCTAssertFalse(commitment.contains(where: { $0 == "+" || $0 == "/" }),
                       "must be base64url, not base64: \(commitment)")
        XCTAssertFalse(commitment.hasSuffix("="), "must be unpadded: \(commitment)")
    }

    func testPointersSurviveInOrder() throws {
        let pointers = ["/z_last", "/a_first", "/m_middle"]
        let fields = preparation(pointers: pointers).credentialRequestFields
        let decoded = try parse(try field(fields, BbsIssuanceParticipant.pointersField)) as? [String]

        XCTAssertEqual(decoded, pointers)
    }

    /// A claim name the wallet did not choose must not be able to break the
    /// encoding.
    ///
    /// The pointers come from the holder's own claims object, which a host
    /// app may build from data it did not author. A name carrying a quote
    /// or a control character would, without escaping, produce a member the
    /// transport cannot parse - or, worse, one it parses into something
    /// other than what the commitment covers.
    func testAHostileClaimNameIsEscapedRatherThanBreakingTheEncoding() throws {
        let nasty = [#"/he said "hi""#, #"/back\slash"#, "/new\nline", "/tab\there"]
        let fields = preparation(pointers: nasty).credentialRequestFields
        let decoded = try parse(try field(fields, BbsIssuanceParticipant.pointersField)) as? [String]

        XCTAssertEqual(decoded, nasty)
    }

    /// The key binding flag must follow the commitment, since that is what
    /// the issuer checks it against.
    ///
    /// The issuer cannot see inside the commitment and this picks the
    /// message layout the credential is signed under. Getting it wrong does
    /// not produce a subtly different credential - it produces a failed
    /// issuance, because the signer refuses a mismatch. Which is the right
    /// outcome, and why this must not be a value the wallet guesses at.
    func testTheKeyBindingFlagFollowsWhetherAnyKeyWasCommitted() throws {
        let unbound = try field(
            preparation(pointers: ["/a"]).credentialRequestFields,
            BbsIssuanceParticipant.keyBindingField
        )
        XCTAssertEqual(unbound, "false")

        let bound = try field(
            preparation(pointers: ["/a"], keybindPublicKeys: [[UInt8](repeating: 0, count: 48)])
                .credentialRequestFields,
            BbsIssuanceParticipant.keyBindingField
        )
        XCTAssertEqual(bound, "true")

        // And it is a JSON boolean on the wire, not a quoted string - the
        // issuer decodes it into a bool.
        let parsed = try XCTUnwrap(try parse(bound) as? NSNumber)
        XCTAssertEqual(parsed, NSNumber(value: true))
    }

    /// The suite has to travel, because the issuer cannot infer it.
    ///
    /// It selects the domain separation the commitment was built under, so
    /// an issuer building its side under the other one gets a commitment
    /// that verifies against nothing - reported as "does not verify", which
    /// is also what a corrupt commitment and a wrong issuer key say. Both
    /// suites are first-class; neither is a default.
    func testTheSuiteTravelsUnderItsWireName() throws {
        for (suite, wire) in [(BbsSuiteId.schnorr, "schnorr"), (BbsSuiteId.plain, "plain")] {
            let encoded = try field(
                preparation(pointers: ["/a"], suiteId: suite).credentialRequestFields,
                BbsIssuanceParticipant.suiteField
            )
            XCTAssertEqual(try parse(encoded) as? String, wire)
            XCTAssertEqual(BbsIssuanceParticipant.wireName(suite), wire)
        }
    }

    /// The suite is independent of key binding, and must not be derived
    /// from it.
    ///
    /// `schnorr` with no committed key binding keys is the ordinary unbound
    /// issuance - the case an issuer deriving the suite from key binding
    /// would get wrong for every credential this SDK issues today.
    func testAnUnboundIssuanceStillNamesItsSuite() throws {
        let fields = preparation(pointers: ["/a"], keybindPublicKeys: []).credentialRequestFields
        XCTAssertEqual(try field(fields, BbsIssuanceParticipant.keyBindingField), "false")
        XCTAssertEqual(try parse(try field(fields, BbsIssuanceParticipant.suiteField)) as? String, "schnorr")
    }
}

#endif

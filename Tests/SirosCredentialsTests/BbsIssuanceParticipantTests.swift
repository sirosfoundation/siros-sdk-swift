// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

// iOS-only, like everything else BBS here - see BbsIssuanceParticipant.swift.
#if os(iOS)

import Foundation
import XCTest
@testable import SirosCredentials

/// The wallet's half of blind BBS issuance.
///
/// Mirrors Kotlin's `BbsIssuanceParticipantTest`, which runs the same
/// fixture through the same calls on a real Pixel.
///
/// # What this can and cannot run
///
/// It cannot issue. Blind-signing is deliberately absent from the wallet's
/// UniFFI surface - a wallet has no business holding an issuer key, and
/// exposing the call would put one within reach of application code. So the
/// two halves are tested against different things:
///
/// - `prepare` runs for real. Its outputs are fresh per call, so what is
///   checked is their shape, their ordering, and that they are fresh.
/// - `accept` is checked against the fixture, whose commitment and
///   credential were produced together by the crate. That is a real
///   issuer's output, not a stand-in.
///
/// The full commit-then-issue loop is covered where both halves are
/// reachable: the crate's own tests.
final class BbsIssuanceParticipantTests: XCTestCase {

    private let holderClaims = #"{"device_pin_hash":"0f1e2d3c","recovery_code":"xyz"}"#

    /// Fails the test if it is ever called.
    private let refusingSigner: ZkWitnessSigner = { algorithm, _ in
        XCTFail("the authenticator was asked for a \(algorithm) signature with no key binding keys")
        return []
    }

    private func participant() -> BbsIssuanceParticipant {
        BbsIssuanceParticipant(systemId: BbsProofSystem.systemIdentifier, suiteId: .plain)
    }

    // MARK: - Fixture

    private func fixture() throws -> [String: Any] {
        let url = try XCTUnwrap(
            Bundle.module.url(forResource: "bbs_jwp_fixture", withExtension: "json"),
            "bbs_jwp_fixture.json missing from test resources"
        )
        let root = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any]
        let cases = try XCTUnwrap(root?["cases"] as? [String: Any])
        return try XCTUnwrap(cases["plain"] as? [String: Any])
    }

    private static func unhex(_ s: String) -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(s.count / 2)
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            out.append(UInt8(s[i..<j], radix: 16)!)
            i = j
        }
        return out
    }

    /// The preparation as it stood when the fixture's credential was
    /// issued, reconstructed from the commitment the crate recorded.
    ///
    /// This is why the fixture carries the commitment: `prepare` produces a
    /// fresh one every call, so nothing generated here could ever match a
    /// credential issued earlier.
    private func preparationFromFixture(_ c: [String: Any]) throws -> BbsIssuancePreparation {
        BbsIssuancePreparation(
            suiteId: .plain,
            commitmentWithProof: Self.unhex(try XCTUnwrap(c["commitment"] as? String)),
            holderPointers: try XCTUnwrap(c["holder_pointers"] as? [String]),
            committedMessages: (c["committed_messages"] as? [String] ?? []).map(Self.unhex),
            secretProverBlind: Self.unhex(try XCTUnwrap(c["secret_prover_blind"] as? String)),
            keybindPublicKeys: []
        )
    }

    // MARK: - Tests

    /// Accepting a real credential yields exactly the state needed to
    /// present it - which closes the loop between the two halves of this
    /// feature.
    ///
    /// A wallet that stored the wrong state here would find out only at the
    /// first presentation, against a verifier, in front of a user.
    func testAcceptYieldsTheStateNeededToPresent() async throws {
        let c = try fixture()
        let issuerPk = Self.unhex(try XCTUnwrap(c["issuer_pk"] as? String))
        let issuedJwp = try XCTUnwrap(c["issued_jwp"] as? String)
        let vct = try XCTUnwrap(c["vct"] as? String)

        let state = try preparationFromFixture(c).accept(issuedJwp: issuedJwp, issuerPublicKey: issuerPk)
        XCTAssertEqual(state.issuerPublicKey, issuerPk)

        let system = BbsProofSystem(holderState: { _ in state }, supportedVcts: [vct], suiteId: .plain)
        let result = try await system.generateProof(
            spec: ZkSystemSpec(
                id: "t",
                system: BbsProofSystem.systemIdentifier,
                params: ["nonce": "n", "aud": "https://verifier.test"]
            ),
            document: .jwp(issuedJwp),
            sessionTranscript: Array("transcript".utf8),
            requestedClaims: ["/given_name"],
            verifierIdentity: nil,
            signer: refusingSigner,
            priorState: nil
        )
        let verified = try jwpVerify(
            suiteId: .plain,
            presentedJwp: String(bytes: result.proofBytes, encoding: .utf8)!,
            issuerPublicKey: Data(issuerPk)
        )
        XCTAssertEqual(verified.disclosed.count, 1)
        XCTAssertEqual(verified.disclosed[0].pointer, "/given_name")
    }

    /// What `prepare` produces, and in what order.
    ///
    /// The ordering is the substance: the wallet commits knowing nothing
    /// about the issuer's claims, and the issuer assigns message indices
    /// afterwards. If the two sides ordered the holder's claims
    /// differently, the credential's map would name one claim while the
    /// signature covered another.
    func testPrepareCommitsInTheOrderTheIssuerWillIndex() async throws {
        let prepared = try await participant().prepareBbs(
            holderClaimsJson: holderClaims, keybindPublicKeys: [], signer: refusingSigner
        )
        XCTAssertEqual(prepared.holderPointers, ["/device_pin_hash", "/recovery_code"],
                       "sorted by pointer, not by document order")
        XCTAssertEqual(prepared.committedMessages.count, 2)
        XCTAssertEqual(String(bytes: prepared.committedMessages[0], encoding: .utf8), "\"0f1e2d3c\"",
                       "the message is the claim's JSON value")
        XCTAssertFalse(prepared.commitmentWithProof.isEmpty)
        XCTAssertEqual(prepared.secretProverBlind.count, 32, "the prover blind is a scalar")
    }

    /// The credential request must carry the commitment and the claim
    /// names, as JSON a request builder can drop straight in.
    func testTheCredentialRequestFieldsAreWellFormedJson() async throws {
        let prepared = try await participant().prepareBbs(
            holderClaimsJson: holderClaims, keybindPublicKeys: [], signer: refusingSigner
        )
        let fields = prepared.credentialRequestFields
        XCTAssertEqual(Set(fields.keys),
                       [BbsIssuanceParticipant.commitmentField, BbsIssuanceParticipant.pointersField])

        let commitment = try XCTUnwrap(fields[BbsIssuanceParticipant.commitmentField])
        let decodedCommitment = try JSONSerialization.jsonObject(
            with: Data(commitment.utf8), options: [.fragmentsAllowed]
        ) as? String
        let encoded = try XCTUnwrap(decodedCommitment)
        XCTAssertFalse(encoded.contains(where: { $0 == "+" || $0 == "/" || $0 == "=" }),
                       "base64url, unpadded")

        let pointers = try JSONSerialization.jsonObject(
            with: Data(try XCTUnwrap(fields[BbsIssuanceParticipant.pointersField]).utf8)
        ) as? [String]
        XCTAssertEqual(pointers, ["/device_pin_hash", "/recovery_code"])
    }

    /// A claim name containing JSON syntax must survive intact.
    ///
    /// A name with a quote in it is exactly what turns a request into
    /// malformed JSON - or, worse, into valid JSON naming a different
    /// claim.
    func testHostileClaimNamesAreEscaped() async throws {
        let prepared = try await participant().prepareBbs(
            holderClaimsJson: #"{"a\"b":1,"c\\d":2}"#, keybindPublicKeys: [], signer: refusingSigner
        )
        let raw = try XCTUnwrap(prepared.credentialRequestFields[BbsIssuanceParticipant.pointersField])
        let pointers = try JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String]
        XCTAssertEqual(pointers, prepared.holderPointers, "both names must round-trip through the request")
        XCTAssertTrue(try XCTUnwrap(pointers).contains { $0.contains("\"") }, "the quote must survive")
    }

    /// Two wallets committing to the same claims must not produce the same
    /// commitment.
    ///
    /// The blinding factor is fresh per credential. If it were not, two
    /// credentials issued to the same holder would be linkable by their
    /// commitments alone - before any presentation happens at all.
    func testEveryCommitmentIsFresh() async throws {
        let first = try await participant().prepareBbs(
            holderClaimsJson: holderClaims, keybindPublicKeys: [], signer: refusingSigner
        )
        let second = try await participant().prepareBbs(
            holderClaimsJson: holderClaims, keybindPublicKeys: [], signer: refusingSigner
        )
        XCTAssertNotEqual(first.commitmentWithProof, second.commitmentWithProof,
                          "two commitments to the same claims must differ")
        XCTAssertNotEqual(first.secretProverBlind, second.secretProverBlind,
                          "the prover blind must be fresh per credential")
        // The claim names are not secret and must NOT vary.
        XCTAssertEqual(first.holderPointers, second.holderPointers)
        XCTAssertEqual(first.committedMessages, second.committedMessages)
    }

    /// Accepting is the wallet's only chance to notice the issuer signed
    /// something other than what was asked for.
    func testAcceptRejectsACredentialThatIsNotWhatWasCommitted() throws {
        let c = try fixture()
        let issuerPk = Self.unhex(try XCTUnwrap(c["issuer_pk"] as? String))
        let issuedJwp = try XCTUnwrap(c["issued_jwp"] as? String)
        let prepared = try preparationFromFixture(c)

        // Sanity: it does accept the real thing.
        _ = try prepared.accept(issuedJwp: issuedJwp, issuerPublicKey: issuerPk)

        var otherKey = issuerPk
        otherKey[0] ^= 0x01
        XCTAssertThrowsError(try prepared.accept(issuedJwp: issuedJwp, issuerPublicKey: otherKey))

        // Different committed messages: the credential is real, but not
        // over what this wallet committed.
        let mismatched = BbsIssuancePreparation(
            suiteId: .plain,
            commitmentWithProof: prepared.commitmentWithProof,
            holderPointers: prepared.holderPointers,
            committedMessages: prepared.committedMessages.map { m in var m = m; m[0] = 0x41; return m },
            secretProverBlind: prepared.secretProverBlind,
            keybindPublicKeys: []
        )
        XCTAssertThrowsError(try mismatched.accept(issuedJwp: issuedJwp, issuerPublicKey: issuerPk))

        // A different blinding factor: someone else's credential.
        var otherBlind = prepared.secretProverBlind
        otherBlind[31] ^= 0x01
        let wrongBlind = BbsIssuancePreparation(
            suiteId: .plain,
            commitmentWithProof: prepared.commitmentWithProof,
            holderPointers: prepared.holderPointers,
            committedMessages: prepared.committedMessages,
            secretProverBlind: otherBlind,
            keybindPublicKeys: []
        )
        XCTAssertThrowsError(try wrongBlind.accept(issuedJwp: issuedJwp, issuerPublicKey: issuerPk))

        XCTAssertThrowsError(try prepared.accept(issuedJwp: "not.a.jwp", issuerPublicKey: issuerPk))
    }

    func testClaimsThatCannotBeCommittedAreRejected() async throws {
        for bad in ["{}", #"["not","an","object"]"#, "{", "\"scalar\""] {
            do {
                _ = try await participant().prepareBbs(
                    holderClaimsJson: bad, keybindPublicKeys: [], signer: refusingSigner
                )
                XCTFail("prepared a commitment from \(bad)")
            } catch {
                // expected
            }
        }
    }

    /// A wallet finds the participant through the registry, without naming
    /// a proof system - and gets nothing for the credential types where no
    /// system takes part in issuance, which is most of them.
    func testTheRegistryRoutesIssuanceWithoutNamingASystem() throws {
        let vct = try XCTUnwrap(try fixture()["vct"] as? String)
        let bbs = BbsProofSystem(holderState: { _ in nil }, supportedVcts: [vct], suiteId: .plain)
        let registry = ZkProofSystemRegistry(systems: [bbs])

        XCTAssertEqual(
            registry.issuanceParticipant(credentialType: CredentialTypeRef(format: .jwp, typeId: vct))?.systemId,
            BbsProofSystem.systemIdentifier
        )
        XCTAssertNil(
            registry.issuanceParticipant(
                credentialType: CredentialTypeRef(format: .msoMdoc, typeId: "org.iso.18013.5.1.mDL")),
            "an mdoc needs no wallet contribution at issuance"
        )
        XCTAssertNil(
            registry.issuanceParticipant(
                credentialType: CredentialTypeRef(format: .jwp, typeId: "https://other.test/x")),
            "nor does a vct this wallet holds no BBS credentials for"
        )
    }
}

#endif

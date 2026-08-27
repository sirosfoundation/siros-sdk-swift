// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

// iOS-only for the same reason the rest of the BBS code is: the native
// library ships iOS slices only. The import sits INSIDE the gate - one
// above it compiles on every platform regardless of what it guards.
#if os(iOS)

/// The wallet's side of blind BBS issuance.
///
/// # Why the wallet has to be here at all
///
/// Every other credential this SDK handles is signed by an issuer and
/// handed over; the wallet's first involvement is storing it. Blind BBS is
/// not like that. The holder commits to messages the issuer never sees, and
/// to the public key of a device-held key binding key, and the issuer signs
/// *that commitment*. So a BBS credential cannot be issued without the
/// wallet having spoken first, and cannot be retrofitted onto one that was.
///
/// # It is still one round trip
///
/// The commit challenge is pure wallet-local Fiat-Shamir - derived from the
/// commitment itself, with no issuer nonce and no server input. So
/// `commitInit` → the authenticator signs → `commitFinalize` all happen
/// inside the wallet, before the credential request is sent, and the
/// commitment rides along in that one request.
///
/// Freshness still comes from the existing `c_nonce`-bound key proof. The
/// commitment's own proof is a proof of *knowledge*, not of freshness, and
/// asking it to carry freshness would be a mistake.
///
/// # Order of operations
///
/// The wallet commits before it knows anything about the issuer's own
/// claims - it cannot know how many there will be. That works because the
/// committed message octets are just the claim values; the *indices* live
/// in the credential header's map, which the issuer builds. `prepare` and
/// `BbsIssuancePreparation.accept` are the two halves either side of that
/// gap.
public struct BbsIssuanceParticipant: ZkIssuanceParticipant {

    /// Credential-request member carrying the holder's commitment,
    /// base64url-encoded.
    ///
    /// Structurally analogous to `proofs` in an OID4VCI credential request:
    /// the wallet-local device signature over the commit challenge plays
    /// the same role for the key binding key that a `proof.jwt` plays for
    /// the proof-of-possession key.
    public static let commitmentField = "bbs_commitment"

    /// Credential-request member naming the committed claims, as a JSON
    /// array of RFC 6901 pointers.
    ///
    /// The issuer needs these: it must place the holder's messages in the
    /// credential's map, and it never sees their values so it cannot name
    /// them itself. It checks the count against the commitment rather than
    /// taking the wallet's word for it.
    public static let pointersField = "bbs_committed_claims"

    public let systemId: String
    private let suiteId: BbsSuiteId

    /// - Parameter suiteId: which key binding construction to issue under.
    ///   Must match what the issuer will sign with; it selects the domain
    ///   separation, and a mismatch produces a credential that verifies
    ///   against nothing.
    public init(systemId: String = BbsProofSystem.systemIdentifier, suiteId: BbsSuiteId = .schnorr) {
        self.systemId = systemId
        self.suiteId = suiteId
    }

    public func prepare(
        holderClaimsJson: String,
        keybindPublicKeys: [[UInt8]],
        signer: @escaping ZkWitnessSigner
    ) async throws -> ZkIssuancePreparation {
        try await prepareBbs(
            holderClaimsJson: holderClaimsJson,
            keybindPublicKeys: keybindPublicKeys,
            signer: signer
        )
    }

    /// The same call, typed to the concrete result.
    ///
    /// The protocol requirement above must return the existential so a
    /// registry-driven caller can use it without naming BBS; a caller that
    /// already knows it is holding a BBS participant wants `accept`, which
    /// only exists on the concrete type.
    public func prepareBbs(
        holderClaimsJson: String,
        keybindPublicKeys: [[UInt8]],
        signer: @escaping ZkWitnessSigner
    ) async throws -> BbsIssuancePreparation {
        // The issuer will index these by sorted pointer, so the wallet has
        // to commit in that order too - which is why this is a native call
        // and not a sort here. Same code the issuer runs.
        let derived = try jwpCommittedMessages(claimsJson: holderClaimsJson)

        let commit = try commitInit(
            suiteId: suiteId,
            committedMessages: derived.messages,
            keybindPublicKeys: keybindPublicKeys.map { Data($0) }
        )

        // One authenticator signature per key binding key, each over the
        // SAME commit challenge - the device proving it holds the key the
        // credential is about to be bound to. An issuer that could not
        // check this would be binding credentials to keys nobody controls.
        //
        // An unbound credential has no keys and so no signatures, and the
        // loop below correctly does nothing.
        var signatures: [Data] = []
        signatures.reserveCapacity(keybindPublicKeys.count)
        for _ in keybindPublicKeys {
            signatures.append(Data(try await signer(coseAlgBls12381G1Schnorr, [UInt8](commit.challenge))))
        }

        let commitment = try commitFinalize(suiteId: suiteId, state: commit.state, keybindSignatures: signatures)

        return BbsIssuancePreparation(
            suiteId: suiteId,
            commitmentWithProof: [UInt8](commitment),
            holderPointers: derived.pointers,
            committedMessages: derived.messages.map { [UInt8]($0) },
            secretProverBlind: [UInt8](commit.secretProverBlind),
            keybindPublicKeys: keybindPublicKeys
        )
    }
}

/// Everything the wallet must send, and everything it must remember,
/// between committing and receiving the credential.
///
/// **`secretProverBlind` is long-lived.** It is generated here and required
/// for every presentation for the life of the credential. Losing it makes
/// the credential unusable; leaking it undoes the blinding. It must reach
/// client-side encrypted storage and never a backend.
public struct BbsIssuancePreparation: ZkIssuancePreparation {
    private let suiteId: BbsSuiteId

    /// The `commitment_with_proof` blob the issuer verifies and signs.
    public let commitmentWithProof: [UInt8]
    /// RFC 6901 pointers naming the committed claims, in message order.
    public let holderPointers: [String]
    /// The committed message octets, in the same order.
    public let committedMessages: [[UInt8]]
    /// See the type's own doc: long-lived, secret, client-side only.
    public let secretProverBlind: [UInt8]
    /// The key binding public keys the credential is being bound to.
    public let keybindPublicKeys: [[UInt8]]

    init(
        suiteId: BbsSuiteId,
        commitmentWithProof: [UInt8],
        holderPointers: [String],
        committedMessages: [[UInt8]],
        secretProverBlind: [UInt8],
        keybindPublicKeys: [[UInt8]]
    ) {
        self.suiteId = suiteId
        self.commitmentWithProof = commitmentWithProof
        self.holderPointers = holderPointers
        self.committedMessages = committedMessages
        self.secretProverBlind = secretProverBlind
        self.keybindPublicKeys = keybindPublicKeys
    }

    public var credentialRequestFields: [String: String] {
        // JSONSerialization rather than hand-rolled escaping: these values
        // include claim names, which a hostile issuer or a careless schema
        // can put anything in, and a request that is not valid JSON is the
        // better outcome only if it is never produced in the first place.
        [
            BbsIssuanceParticipant.commitmentField: Self.jsonEncoded(base64Url(commitmentWithProof)),
            BbsIssuanceParticipant.pointersField: Self.jsonEncoded(holderPointers),
        ]
    }

    /// Check what the issuer returned, and produce the state to store
    /// beside it.
    ///
    /// **Not optional.** This is the wallet's only chance to find out that
    /// the issuer signed something other than what was asked for, or that
    /// the credential is not actually bound to the key that was committed.
    /// Both otherwise surface much later, as a presentation that will not
    /// verify with nothing pointing at the cause.
    ///
    /// - Parameters:
    ///   - issuedJwp: the credential as issued, in JWP Compact
    ///     Serialization.
    ///   - issuerPublicKey: the issuer's BBS public key, from its published
    ///     metadata.
    /// - Returns: the state `BbsProofSystem` needs to present this
    ///   credential, which the caller must persist alongside it.
    /// - Throws: if the credential does not validate against what was
    ///   committed.
    public func accept(issuedJwp: String, issuerPublicKey: [UInt8]) throws -> BbsHolderState {
        _ = try jwpAccept(
            suiteId: suiteId,
            issuedJwp: issuedJwp,
            issuerPublicKey: Data(issuerPublicKey),
            committedMessages: committedMessages.map { Data($0) },
            keybindPublicKeys: keybindPublicKeys.map { Data($0) },
            secretProverBlind: Data(secretProverBlind)
        )
        return BbsHolderState(
            issuerPublicKey: issuerPublicKey,
            secretProverBlind: secretProverBlind,
            committedMessages: committedMessages,
            keybindPublicKeys: keybindPublicKeys
        )
    }

    private func base64Url(_ data: [UInt8]) -> String {
        Data(data).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Encodes a value as a JSON fragment.
    ///
    /// `.fragmentsAllowed` is what lets a bare string be encoded; without
    /// it JSONSerialization insists on a top-level array or object.
    private static func jsonEncoded(_ value: Any) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed]),
              let text = String(data: data, encoding: .utf8) else {
            // Unreachable for a String or [String]; returning a valid JSON
            // null beats a crash or a malformed request body.
            return "null"
        }
        return text
    }
}

#endif

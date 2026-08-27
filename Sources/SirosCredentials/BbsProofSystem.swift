// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

// The whole implementation is iOS-only because the native library is: the
// zk-cred-bbs XCFramework ships iOS slices only, and the generated bindings
// carry the same gate. Same arrangement as LongfellowZkProofSystem.
#if os(iOS)

// INSIDE the gate, not above it. CryptoKit does not exist on Linux, and
// this package's CI builds SirosCredentials there - an import above the
// `#if` compiles on every platform regardless of what it guards, so it
// fails the Linux build even though nothing that uses it is reachable.
// swift-crypto's `Crypto` is not the answer either: Package.swift scopes
// that product to Linux only, so it is unavailable here. ZkProofSystem.swift
// needs the `#if canImport(CryptoKit)` dance because its code really does
// run on both; this file's does not.
import CryptoKit

/// The holder-side state a BBS credential needs that its container does not
/// carry.
///
/// A JWP holds the issuer's claims and the signature. It deliberately does
/// not hold the holder's own committed values, the blinding factor tying
/// them to the signature, or which device key the credential is bound to -
/// publishing those would undo the point of blind issuance. So they live
/// beside the credential, and every presentation needs them.
///
/// `secretProverBlind` in particular is long-lived: generated once at
/// issuance and required for every presentation for the life of the
/// credential. Losing it makes the credential unusable, and it must never
/// leave the wallet.
public struct BbsHolderState: Sendable, Equatable {
    /// The issuer's BBS public key, as a compressed G2 point.
    public let issuerPublicKey: [UInt8]
    /// The blinding factor from issuance. See the type's own doc comment.
    public let secretProverBlind: [UInt8]
    /// The holder's own messages, in the order the credential's header maps
    /// them - they occupy the tail of the message vector, after the
    /// issuer's.
    public let committedMessages: [[UInt8]]
    /// The key binding public keys this credential is bound to. Empty for a
    /// credential with no device binding.
    public let keybindPublicKeys: [[UInt8]]

    public init(
        issuerPublicKey: [UInt8],
        secretProverBlind: [UInt8],
        committedMessages: [[UInt8]],
        keybindPublicKeys: [[UInt8]]
    ) {
        self.issuerPublicKey = issuerPublicKey
        self.secretProverBlind = secretProverBlind
        self.committedMessages = committedMessages
        self.keybindPublicKeys = keybindPublicKeys
    }
}

/// Where `BbsProofSystem` looks up a credential's ``BbsHolderState``.
///
/// A closure rather than a field on the stored credential because that
/// belongs to the issuance path, and to a format shared with other wallet
/// clients: the state has to reach the encrypted `privatedata` container,
/// and what that container carries is not this type's decision to make.
///
/// Returning `nil` means "cannot present" - never "present without
/// binding".
public typealias BbsHolderStateStore = @Sendable (String) async throws -> BbsHolderState?

/// What went wrong presenting a BBS credential.
public enum BbsProofError: Error, CustomStringConvertible {
    /// The document handed over was not a JWP.
    case wrongDocumentFormat(String)
    /// No holder state is stored for this credential.
    case missingHolderState
    /// The verifier asked for claims this credential does not have.
    case unknownClaims([String], available: [String])
    /// A BBS presentation needs an audience and none was supplied.
    case missingAudience

    public var description: String {
        switch self {
        case let .wrongDocumentFormat(got):
            return "BbsProofSystem needs a JWP credential, got \(got)"
        case .missingHolderState:
            return "no holder state stored for this credential; it cannot be presented without the blinding factor from issuance"
        case let .unknownClaims(missing, available):
            return "credential has no claim at \(missing.joined(separator: ", ")); it maps \(available.joined(separator: ", "))"
        case .missingAudience:
            return "a BBS presentation needs an audience: supply 'aud' in the spec params or a VerifierIdentity"
        }
    }
}

/// Blind BBS presentation, backed by the `zk-cred-bbs` native crate.
///
/// # How this differs from the other proof systems
///
/// Longfellow and Vega prove a statement *about* a credential to a circuit
/// compiled in advance. BBS is not a circuit at all: the signature scheme
/// itself supports revealing a chosen subset of the signed messages, and
/// the "proof" is a re-randomised signature. Three consequences show up
/// here, each noted where it lands:
///
/// - ``matchingSpec(_:numAttributes:)`` ignores `numAttributes`, because
///   there is no fixed attribute count to match.
/// - `pseudonymOutcome` is always `.notSupportedBySystem` - BBS has a
///   pseudonym construction (`draft-irtf-cfrg-bbs-per-verifier-linkability`)
///   but it is not implemented, and it needs a reserved message slot
///   decided at issuance.
/// - There is no `nextState`: nothing is cached between presentations, and
///   caching would be the wrong thing anyway, since re-randomising afresh
///   each time is what keeps presentations unlinkable.
///
/// # What the verifier receives
///
/// `ZkProofResult.proofBytes` is the UTF-8 of a presented JWP - four
/// dot-separated parts, self-contained. Unlike the other systems' opaque
/// proof blobs it carries the disclosed claims and both headers, so a
/// verifier needs nothing from this SDK but the issuer's public key.
public struct BbsProofSystem: ZkProofSystem {

    /// This system's identifier in a verifier's `zk_system_type` list.
    ///
    /// Names the cipher suite rather than a version, because unlike a
    /// circuit there is no artifact to version - two wallets agreeing on
    /// this string agree on everything that matters.
    public static let systemIdentifier = "bbs-mod-bls12381-schnorr-kb-v0"

    /// Spec param carrying the verifier's nonce.
    public static let nonceParam = "nonce"

    /// Spec param carrying the intended audience.
    public static let audienceParam = "aud"

    /// Presentation-header parameter carrying the session transcript's
    /// SHA-256. Private to this profile - the JWP drafts have no parameter
    /// for a transport session binding.
    public static let sessionTranscriptParam = "sth"

    public let systemId = BbsProofSystem.systemIdentifier
    public let supportedCredentialTypes: Set<CredentialTypeRef>

    private let holderState: BbsHolderStateStore
    private let suiteId: BbsSuiteId

    /// - Parameters:
    ///   - holderState: where to find the secrets that are not in the
    ///     container.
    ///   - supportedVcts: the credential types this wallet actually holds
    ///     BBS credentials for. Unlike a circuit-based system, BBS
    ///     constrains no type whatsoever - the honest answer to "what can
    ///     you prove over" is "anything issued this way", which the
    ///     registry's fixed-set matching cannot express, so the wallet
    ///     supplies the set it has.
    ///   - suiteId: which key binding construction these credentials use.
    ///     Must match what they were issued under; it selects the domain
    ///     separation, and a mismatch verifies against nothing.
    public init(
        holderState: @escaping BbsHolderStateStore,
        supportedVcts: Set<String>,
        suiteId: BbsSuiteId = .schnorr
    ) {
        self.holderState = holderState
        self.suiteId = suiteId
        self.supportedCredentialTypes = Set(
            supportedVcts.map { CredentialTypeRef(format: .jwp, typeId: $0) }
        )
    }

    /// Matches on the system identifier alone.
    ///
    /// **`numAttributes` is deliberately ignored**, which is the opposite of
    /// what `ZkProofSystem.matchingSpec` requires of a circuit-based system,
    /// so it is worth being explicit about why. That requirement exists
    /// because a real ZK circuit is compiled for a fixed attribute count and
    /// proving against the wrong one yields a structurally invalid proof. A
    /// BBS presentation has no circuit and no compiled-in count: the
    /// generator list is derived from the credential's own message count at
    /// proving time, and the disclosed subset is chosen per presentation.
    /// Filtering on an attribute count here would reject specs that this
    /// system can satisfy perfectly well.
    public func matchingSpec(_ requestedSpecs: [ZkSystemSpec], numAttributes: Int) -> ZkSystemSpec? {
        requestedSpecs.first { $0.system == BbsProofSystem.systemIdentifier }
    }

    /// BBS is the one system here that needs the wallet at issuance.
    ///
    /// Longfellow and Vega prove things about a credential someone else
    /// already signed; a blind BBS credential does not exist unless the
    /// wallet committed first. See `BbsIssuanceParticipant`.
    public var issuanceParticipant: ZkIssuanceParticipant? {
        BbsIssuanceParticipant(systemId: BbsProofSystem.systemIdentifier, suiteId: suiteId)
    }

    public func generateProof(
        spec: ZkSystemSpec,
        document: CredentialDocument,
        sessionTranscript: [UInt8],
        requestedClaims: [String],
        verifierIdentity: VerifierIdentity?,
        signer: @escaping ZkWitnessSigner,
        priorState: [UInt8]?
    ) async throws -> ZkProofResult {
        // A caller that bypassed the registry could hand over any case.
        guard let jwp = document.jwpCompact else {
            throw BbsProofError.wrongDocumentFormat(document.formatName)
        }
        guard let state = try await holderState(jwp) else {
            throw BbsProofError.missingHolderState
        }

        // Fail before touching the authenticator if the credential cannot
        // answer the request anyway - a user prompt that leads nowhere is
        // worse than an error.
        let info = try jwpInspect(issuedJwp: jwp)
        let unknown = requestedClaims.filter { !info.pointers.contains($0) }
        guard unknown.isEmpty else {
            throw BbsProofError.unknownClaims(unknown, available: info.pointers)
        }

        let presentationHeader = try jwpBuildPresentationHeader(
            nonce: nonce(for: spec, sessionTranscript: sessionTranscript),
            aud: try audience(for: spec, verifierIdentity: verifierIdentity),
            // Binds the transport's own session transcript, which the JWP
            // drafts have no parameter for. Without it this proof would be
            // bound only to a nonce, and every other presentation path in
            // this SDK binds the full transcript.
            extraJson: #"{"\#(BbsProofSystem.sessionTranscriptParam)":"\#(base64Url(sha256(sessionTranscript)))"}"#
        )

        let initResult = try jwpPresentInit(
            suiteId: suiteId,
            issuedJwp: jwp,
            issuerPublicKey: Data(state.issuerPublicKey),
            presentationHeader: Data(presentationHeader),
            requestedPointers: requestedClaims,
            committedMessages: state.committedMessages.map { Data($0) },
            keybindPublicKeys: state.keybindPublicKeys.map { Data($0) },
            secretProverBlind: Data(state.secretProverBlind)
        )

        // One authenticator signature per key binding key. Each challenge
        // is already prehashed to 32 octets by the crate, because the
        // prototype firmware caps its signing input - see the crate's
        // PROFILE.md, DELTA 3.
        var signatures: [Data] = []
        signatures.reserveCapacity(initResult.keybindChallenges.count)
        for challenge in initResult.keybindChallenges {
            let signature = try await signer(coseAlgBls12381G1Schnorr, [UInt8](challenge))
            signatures.append(Data(signature))
        }

        let presented = try jwpPresentFinalize(
            suiteId: suiteId,
            state: initResult.state,
            keybindSignatures: signatures
        )

        return ZkProofResult(
            proofBytes: Array(presented.utf8),
            // No reuse path: re-randomising afresh is what keeps
            // presentations unlinkable.
            nextState: nil,
            pseudonym: nil,
            pseudonymOutcome: .notSupportedBySystem,
            publicValues: ["vct": info.vct]
        )
    }

    /// The verifier's nonce, which a presentation is replay-bound to.
    ///
    /// Taken from the spec's params when the verifier supplied one, as
    /// OpenID4VP always does. Falling back to the session transcript's hash
    /// rather than erroring keeps transports that carry no separate nonce
    /// usable, and it is still unique per session.
    private func nonce(for spec: ZkSystemSpec, sessionTranscript: [UInt8]) -> String {
        spec.getParam(BbsProofSystem.nonceParam) ?? base64Url(sha256(sessionTranscript))
    }

    /// Who the presentation is for.
    ///
    /// `aud` is required by the JWP draft, so there is no "omit it" option.
    /// The verifier's own `client_id` is the right value and is what a
    /// verifier checks against itself.
    private func audience(for spec: ZkSystemSpec, verifierIdentity: VerifierIdentity?) throws -> String {
        if let aud = spec.getParam(BbsProofSystem.audienceParam) { return aud }
        if let clientId = verifierIdentity?.clientId { return clientId }
        throw BbsProofError.missingAudience
    }

    private func sha256(_ data: [UInt8]) -> [UInt8] {
        Array(SHA256.hash(data: Data(data)))
    }

    private func base64Url(_ data: [UInt8]) -> String {
        Data(data).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

#endif

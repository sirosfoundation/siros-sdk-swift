// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
// swift-crypto's `Crypto` module mirrors CryptoKit's API 1:1 (including the
// `SHA256` type used below) - it exists purely so this file compiles and
// runs identically on Linux, where CryptoKit itself isn't available at all.
// Package.swift scopes the `Crypto` product to Linux only, so this import
// must be mutually exclusive with CryptoKit's, not unconditional - an
// unconditional `import Crypto` fails to resolve on macOS/iOS, where the
// product isn't linked at all (only surfaced once this file was actually
// built on the Mac mini for the first time, matching ZkCircuitClient.swift's
// own already-correct `#if canImport(CryptoKit) ... #else ... #endif` gating).
import Crypto
#endif

/// The requested-claim name a verifier uses to ask for a ZK pseudonym,
/// regardless of which underlying `ZkProofSystem` produces it - confirmed
/// via the `feat/longfellow-zk` reference implementation, which always
/// lists it alongside real disclosed claims (e.g. `["age_over_18",
/// "pairwise_pseudonym"]`), not as a separate side-channel-only concept the
/// circuit is unaware of. Lives here (platform-agnostic `SirosCredentials`),
/// not on a specific concrete system like `LongfellowZkProofSystem` (iOS-only,
/// wraps a native XCFramework), so wallet-facing code that must run on every
/// platform can reference it unconditionally.
public let zkPseudonymClaim = "pairwise_pseudonym"

/// A verifier's request for one ZK proof system, mirroring multipaz's own
/// `ZkSystemSpec`/`ZkSystemRepository` design: a generic id/system/params bag
/// rather than a fixed typed shape, so each proof system (Longfellow today,
/// Vega/BBS later) defines its own matching semantics without forcing every
/// implementation to understand every other system's parameters.
///
/// `id` and `system` mirror `ZkCircuitDescriptor.id`/`.system` (this SDK's
/// own circuit catalog, see `ZkCircuitClient`) closely enough that a
/// `ZkProofSystem.matchingSpec` implementation can usually resolve a request
/// straight to a catalog entry, but this type is wire-shaped (what a verifier
/// asked for), not catalog-shaped (what we have available) - the two only
/// coincide when the requested system is one we actually support.
public struct ZkSystemSpec: Sendable, Equatable {
    public let id: String
    public let system: String
    public let params: [String: String]

    public init(id: String, system: String, params: [String: String] = [:]) {
        self.id = id
        self.system = system
        self.params = params
    }

    public func getParam(_ key: String) -> String? { params[key] }
}

/// Identifies who a pseudonym is being bound to, and any secondary
/// verifier-supplied binding context - the two inputs to the real wire-format
/// pseudonym derivation (see `ZkPseudonymDeriver`). Named for its role at the
/// SDK boundary (verifier's presentation request); doubles as the "pseudonym
/// requested at all" signal in `ZkProofSystem.generateProof` (a `nil` value
/// there means no pseudonym was requested).
public struct VerifierIdentity: Sendable, Equatable {
    /// The verifier's OpenID4VP `client_id` (e.g.
    /// `x509_san_dns:verifier.example.com`) - the fallback `verifier_id`
    /// derivation input when `sessionId` is unavailable.
    public let clientId: String
    /// The DCQL credential query's `meta.ppid_context` string, if the
    /// verifier supplied one - a second, independent binding value a
    /// verifier can use to further scope pseudonyms (e.g. per-session, not
    /// just per-verifier). `nil` when absent, which is a normal, common case.
    public let ppidContext: String?
    /// The verifier-assigned session id for this specific presentation
    /// (parsed from the `request_uri`'s `?sessionId=` query parameter by
    /// go-wallet-backend, the only hop that ever sees the raw request_uri) -
    /// the REAL `verifier_id` derivation input, confirmed 2026-08-17 via
    /// direct report from zk-cred-longfellow's V8/PPID author: a real
    /// reference implementation derives `verifier_context` from the
    /// presentation SESSION's id, not the verifier's static identity,
    /// precisely so a captured proof can't be replayed against a different
    /// session. `clientId` is only a fallback for callers that don't have a
    /// session id available.
    public let sessionId: String?

    public init(clientId: String, ppidContext: String? = nil, sessionId: String? = nil) {
        self.clientId = clientId
        self.ppidContext = ppidContext
        self.sessionId = sessionId
    }
}

/// Whether a proof system honored a pseudonym request. Not every ZK system
/// has a pseudonym concept (Vega, researched 2026-08-14, has none at all) - a
/// system that can't produce one must say so explicitly rather than silently
/// dropping the request or fabricating a value that isn't actually bound to
/// anything.
public enum PseudonymOutcome: Sendable {
    case provided
    case notSupportedBySystem
}

/// The result of `ZkProofSystem.generateProof`.
public struct ZkProofResult: Sendable {
    /// The opaque proof, in whatever encoding the issuing system uses -
    /// never interpreted outside that system's own verifier.
    public let proofBytes: [UInt8]
    /// Updated `generateProof` `priorState` to feed the next call for this
    /// same credential+system, for systems that support a
    /// rerandomizable-witness reuse path (e.g. Vega's `prep_prove` cache -
    /// see plan §2.4.1 item 3). `nil` for systems (Longfellow today) that
    /// don't have or need this.
    public let nextState: [UInt8]?
    /// The derived pseudonym bytes, present only when `pseudonymOutcome` is
    /// `.provided`.
    public let pseudonym: [UInt8]?
    public let pseudonymOutcome: PseudonymOutcome
    /// Whatever output values this system's verify-equivalent asserts (not
    /// assumed to be a fixed "success/claims" shape - some systems, e.g.
    /// Vega, recompute and return public values rather than taking expected
    /// ones as input).
    public let publicValues: [String: String]
    /// The exact timestamp string passed to the native prover call, if this
    /// system used one - a caller wrapping `proofBytes` into a wire envelope
    /// (see `MdocDeviceResponseBuilder.buildZkDeviceResponse`) must echo this
    /// exact same value, since it's part of what the proof attests to.
    public let timestamp: String

    public init(
        proofBytes: [UInt8],
        nextState: [UInt8]? = nil,
        pseudonym: [UInt8]? = nil,
        pseudonymOutcome: PseudonymOutcome = .notSupportedBySystem,
        publicValues: [String: String] = [:],
        timestamp: String = ""
    ) {
        self.proofBytes = proofBytes
        self.nextState = nextState
        self.pseudonym = pseudonym
        self.pseudonymOutcome = pseudonymOutcome
        self.publicValues = publicValues
        self.timestamp = timestamp
    }
}

/// What a credential *is*: a format plus the type identifier that format
/// uses - an mdoc's doctype, an SD-JWT VC's `vct`.
///
/// Replaces the bare doctype string this protocol used to match on. That
/// only worked while every proof system was mdoc-only: a doctype alone
/// cannot distinguish an mdoc mDL from an SD-JWT VC one, so a request for
/// the latter would have been silently routed to an mdoc-only
/// implementation and failed somewhere deep inside a native prover.
///
/// Reuses `CredentialFormat`, the enum the credential store already keys
/// on, rather than introducing a second notion of "format" alongside it.
public struct CredentialTypeRef: Hashable, Sendable {
    public let format: CredentialFormat
    public let typeId: String

    public init(format: CredentialFormat, typeId: String) {
        self.format = format
        self.typeId = typeId
    }
}

/// A credential's stored bytes, tagged with how to read them.
///
/// Deliberately still bytes rather than a parsed model. The bytes are a
/// private witness fed to a local prover and never sent to the verifier
/// (see `ZkProofSystem.generateProof`), and each proof system's native
/// crate parses them itself - so a shared parsed representation here would
/// be a translation layer that every implementation immediately undoes.
///
/// Only the formats something actually stores today. A JWP case for blind
/// BBS is deliberately absent until a proof system consumes one; the enum
/// is the extension point, so adding it later is additive and every
/// `switch` over it stays exhaustiveness-checked.
public enum CredentialDocument: Sendable {
    /// A DeviceResponse-shaped CBOR envelope, matching
    /// `MdocDeviceResponseBuilder`'s own constructor input.
    case mdoc([UInt8])

    /// A `~`-delimited SD-JWT VC, as issued.
    case sdJwtVc([UInt8])

    public var bytes: [UInt8] {
        switch self {
        case let .mdoc(b): return b
        case let .sdJwtVc(b): return b
        }
    }

    /// The case name alone, for diagnostics.
    ///
    /// Interpolating the enum itself would print the associated `[UInt8]`
    /// too - and those bytes are the credential, so an error message about
    /// the wrong format would spill the whole thing into logs and crash
    /// reports. Always use this in anything user- or log-facing.
    public var formatName: String {
        switch self {
        case .mdoc: return "mdoc"
        case .sdJwtVc: return "sdJwtVc"
        }
    }
}

/// COSE algorithm identifier for ES256 (RFC 8152 §8.1).
public let coseAlgES256: Int64 = -7

/// Signs raw bytes with a credential's device key, mid-proof-generation.
///
/// Replaces the bare `([UInt8]) async throws -> [UInt8]` this protocol used
/// to take. The reason is the algorithm parameter: Longfellow needs an
/// ES256 signature over a witness DeviceResponse, while a BBS key binding
/// key signs with Schnorr over BLS12-381 G1 - a different key, on a
/// different curve, that only some authenticators can produce at all. A
/// bare closure cannot say which it wants, so the wallet had to guess, and
/// guessing wrong yields a signature that fails verification with nothing
/// to point at.
///
/// Implementations must return a raw (not DER) signature, and must throw
/// rather than substitute another algorithm - a wallet that quietly signs
/// with the wrong key produces a credential that cannot be presented.
public typealias ZkWitnessSigner = @Sendable (Int64, [UInt8]) async throws -> [UInt8]

/// One pluggable zero-knowledge proof system, backing a specific credential
/// presentation mode (selective disclosure + optional pseudonym, today;
/// whatever a future BBS/Vega implementation supports). Mirrors this org's
/// existing WSCD plugin framework (`siros-wscd-manager`'s plugin
/// architecture, `WscdSelectionPolicy`) - same shape of problem (multiple
/// interchangeable backends behind one wallet-facing API, selected per
/// declared capability), same organization already has the pattern working
/// end-to-end.
///
/// Each new proof system is a new implementation of this protocol plus its
/// own Rust/native crate - never a change to wallet-facing code. See
/// `~/.claude/plans/silver-drifting-heron.md` §3 for the full design
/// rationale (including why `priorState`/`nextState` and the pseudonym
/// outcome exist - both are Vega-driven additions, backward-compatible
/// no-ops for Longfellow's own implementation).
public protocol ZkProofSystem: Sendable {
    /// This system's identifier, e.g. `"longfellow-libzk-v1_8_2_4307_2945"`.
    var systemId: String { get }

    /// mdoc doctypes this system can generate a ZK proof over, e.g. `{"org.iso.18013.5.1.mDL"}`.
    /// The credential types this system can prove over, e.g.
    /// `[CredentialTypeRef(format: .msoMdoc, typeId: "org.iso.18013.5.1.mDL")]`.
    ///
    /// Was `supportedDocTypes: Set<String>`. Carrying the format means a
    /// request for an SD-JWT VC or JWP credential finds no match today
    /// rather than being routed to an mdoc-only implementation on a
    /// doctype-string collision.
    var supportedCredentialTypes: Set<CredentialTypeRef> { get }

    /// Returns whichever of `requestedSpecs` (a verifier's own list, in
    /// priority order) this system can satisfy, or `nil` if none match -
    /// the extension point `ZkProofSystemRegistry` uses to resolve "does any
    /// registered system satisfy this verifier's ZK request."
    ///
    /// `numAttributes` is the number of claims actually being disclosed for
    /// this request - a circuit is compiled for a FIXED attribute count
    /// (e.g. `..._8_2_...` proves exactly 2), so a matching implementation
    /// must also compare this against a candidate spec's own `num_attributes`
    /// param, not just its `system`/`id` string. Picking a circuit variant
    /// for the wrong attribute count fails opaquely at the native prover/
    /// verifier boundary (`MDOC_VERIFIER_HASH_PARSING_FAILURE`), not here.
    func matchingSpec(_ requestedSpecs: [ZkSystemSpec], numAttributes: Int) -> ZkSystemSpec?

    /// Generate a ZK proof of possession (and, if `verifierIdentity` is
    /// non-nil, a pseudonym bound to it) over the credential in
    /// `credentialBytes`.
    ///
    /// **Why this takes raw credential bytes + a signer, not a pre-assembled
    /// DeviceResponse**: confirmed 2026-08-14 by reading `wallet-frontend`'s
    /// `feat/longfellow-zk` branch (`MdocProverService.ts`, by the same
    /// author as `zk-cred-longfellow`'s V8/PPID work) plus the Rust crate's
    /// own `parse_device_response` - the native prover's `device_response`
    /// parameter is "the mdoc's DeviceResponse, as CBOR data" **including a
    /// real, normally-computed device signature** over `sessionTranscript`
    /// (via the exact same `DeviceAuthentication`/`deviceSigned`
    /// construction any non-ZK mdoc presentation already uses -
    /// `parse_device_response` requires
    /// `device_signed.device_auth.device_signature` to be present and errors
    /// otherwise). The ZK proof does not replace the device signature; it
    /// proves knowledge of a *valid* one (among other things) without
    /// revealing it. This locally-assembled DeviceResponse bytes are a
    /// private witness fed only to the local prover - unlike a normal
    /// presentation's output, they are never sent to the verifier (only
    /// `ZkProofResult.proofBytes` is) - so it should be built with full
    /// disclosure (no claim filtering): the circuit itself, not this SDK,
    /// selects which claims `requestedClaims` actually reveals.
    ///
    /// - Parameters:
    ///   - spec: the specific `ZkSystemSpec` to prove against - normally
    ///     whatever `matchingSpec` just returned for this same request.
    ///   - credentialBytes: the credential's raw stored bytes (a full
    ///     DeviceResponse-shaped envelope, matching
    ///     `MdocDeviceResponseBuilder`'s own constructor input in
    ///     `Sources/SirosKeystore`).
    ///   - sessionTranscript: the OpenID4VP/DC-API/proximity session
    ///     transcript this proof must be bound to (mirrors every non-ZK mdoc
    ///     presentation's own session-transcript binding) - already
    ///     computed by the caller for whichever transport is in play; this
    ///     call is transport-agnostic.
    ///   - requestedClaims: element identifiers the verifier asked to have
    ///     selectively disclosed within the proof.
    ///   - verifierIdentity: non-nil to also derive and include a pseudonym
    ///     bound to this verifier; `nil` for a plain proof of possession
    ///     with no pseudonym.
    ///   - signer: signs raw bytes with the device key for the (private,
    ///     never-transmitted) witness DeviceResponse's own device signature;
    ///     must return a raw (not DER) signature - same contract as
    ///     `MdocDeviceResponseBuilder`'s own `signer` parameter.
    ///   - priorState: opaque prover-side cache from a previous call to this
    ///     same credential+system (see `ZkProofResult.nextState`) - systems
    ///     without a reuse path (Longfellow) ignore it.
    func generateProof(
        spec: ZkSystemSpec,
        document: CredentialDocument,
        sessionTranscript: [UInt8],
        requestedClaims: [String],
        verifierIdentity: VerifierIdentity?,
        signer: @escaping ZkWitnessSigner,
        priorState: [UInt8]?
    ) async throws -> ZkProofResult
}

/// Derives the wire-format `verifier_context` a `ZkProofSystem` pseudonym
/// derivation binds to a specific verifier - a policy decision independent
/// of which proof system produced the pseudonym, so it's pluggable
/// separately from `ZkProofSystem` itself.
///
/// **This is the real wire-format formula**, confirmed 2026-08-14 by reading
/// `balfanz/multipaz`'s `ppid` branch (`verifier.kt`) directly - NOT a naive
/// single hash of one combined value:
///
/// ```
/// pairwise_pseudonym = SHA256(pseudonym_seed || SHA256(SHA256(verifier_id) || SHA256(ppid_context)))
/// ```
///
/// i.e. `verifier_id` and `ppid_context` are each independently SHA-256'd
/// first, concatenated, and SHA-256'd again to produce the 32-byte value fed
/// to the underlying proof system as its own `verifier_context` parameter
/// (see e.g. `zk-cred-longfellow`'s `proveWithPpid`) - that system's own
/// `SHA256(pseudonym_seed || verifier_context)` is the OUTER hash in the
/// formula above, not a separate/different formula. Getting this derivation
/// wrong produces pseudonyms that silently fail to match any real verifier's
/// expectation, even though proof generation itself succeeds.
public protocol ZkPseudonymDeriver: Sendable {
    func deriveVerifierContext(_ verifierIdentity: VerifierIdentity) -> [UInt8]
}

/// The default, spec-faithful `ZkPseudonymDeriver` - implements the formula
/// documented on that protocol exactly. Stateless; safe to share/reuse
/// across proof systems and requests.
public struct DefaultZkPseudonymDeriver: ZkPseudonymDeriver {
    public init() {}

    public func deriveVerifierContext(_ verifierIdentity: VerifierIdentity) -> [UInt8] {
        let verifierIdSource = verifierIdentity.sessionId ?? verifierIdentity.clientId
        let verifierIdHash = SHA256.hash(data: Array(verifierIdSource.utf8))
        // The real fallback for an absent ppid_context is 32 raw zero
        // bytes, not SHA256("") - confirmed against the verifier's own
        // reconstruction (multipaz's `LongfellowZkSystem.kt`), which never
        // hashes a missing context, it substitutes the zero bytes directly.
        let ppidContextHash: [UInt8]
        if let ppidContext = verifierIdentity.ppidContext {
            ppidContextHash = Array(SHA256.hash(data: Array(ppidContext.utf8)))
        } else {
            ppidContextHash = [UInt8](repeating: 0, count: 32)
        }
        var combined = [UInt8]()
        combined.append(contentsOf: verifierIdHash)
        combined.append(contentsOf: ppidContextHash)
        return Array(SHA256.hash(data: combined))
    }
}

/// Holds every `ZkProofSystem` compiled into this wallet and resolves "does
/// any registered system satisfy this verifier's ZK request" - mirrors
/// `WscdSelectionPolicy`'s registry role: matching declared capabilities
/// (doc type + system spec) against the request, not a hardcoded
/// single-system assumption, even though Longfellow is the only real
/// implementation on day one.
public final class ZkProofSystemRegistry: Sendable {
    private let systems: [ZkProofSystem]

    public init(systems: [ZkProofSystem]) {
        self.systems = systems
    }

    /// The first registered system (in registration order) that supports
    /// `credentialType` and can satisfy one of `requestedSpecs`, paired with the
    /// matched spec - or `nil` if none qualify. `numAttributes` is the
    /// number of claims actually being disclosed - see
    /// `ZkProofSystem.matchingSpec`'s doc comment for why it must be
    /// threaded through rather than matched on `system`/`id` alone.
    public func resolve(credentialType: CredentialTypeRef, requestedSpecs: [ZkSystemSpec], numAttributes: Int) -> (ZkProofSystem, ZkSystemSpec)? {
        for system in systems {
            guard system.supportedCredentialTypes.contains(credentialType) else { continue }
            guard let matched = system.matchingSpec(requestedSpecs, numAttributes: numAttributes) else { continue }
            return (system, matched)
        }
        return nil
    }

    /// Every registered system's `systemId`, for diagnostics/settings UI.
    public var registeredSystemIds: [String] { systems.map { $0.systemId } }
}

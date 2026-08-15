// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

// The native `zk-cred-longfellow` XCFramework only ships iOS slices (see
// Package.swift's `zk_cred_longfellowFFI` binary target, and
// `Generated/zk_cred_longfellow.swift`'s own `#if os(iOS)` gating) - this
// entire concrete implementation is correspondingly iOS-only, matching
// `NfcCtap2Transport.swift`'s precedent in this same target. The abstract
// `ZkProofSystem` protocol itself (in `SirosCredentials`) has no such
// restriction - only this real backend does.
#if os(iOS)

import Foundation
import CryptoKit
import SwiftCBOR
import libzstd
import SirosCredentials

/// `ZkProofSystem` implementation wrapping the `zk-cred-longfellow` native
/// crate (V8 circuit + PPID support - see
/// `~/.claude/plans/silver-drifting-heron.md` for the full design/provenance
/// history). Fetches circuits on demand from `zkCircuitClient` (Phase 1),
/// caches initialized `MdocZkProver` instances per (circuit id, attribute
/// count) since circuit loading is expensive, and derives pseudonyms via
/// `pseudonymDeriver` (defaults to the real spec-faithful formula).
///
/// An `actor` (not a plain class): the prover cache is the only mutable
/// state, and `MdocZkProver` is itself `@unchecked Sendable` (from the
/// vendored UniFFI bindings), so actor isolation gives correct
/// cross-request/cross-task cache sharing without a manual lock.
///
/// **How the witness DeviceResponse is built** (confirmed 2026-08-14 via
/// `wallet-frontend`'s `feat/longfellow-zk` reference implementation
/// (`MdocProverService.ts`) and the crate's own `parse_device_response`):
/// the native prover needs a REAL, fully-signed DeviceResponse - the ZK
/// proof proves knowledge of a valid device signature, it doesn't replace
/// the signing mechanism. This is built locally via
/// `MdocDeviceResponseBuilder` (the exact same builder every non-ZK
/// presentation already uses) with `disclosedClaims: nil` (full disclosure)
/// since these bytes are a private witness never transmitted to the
/// verifier - the circuit itself selects which claims
/// `ZkProofSystem.generateProof`'s `requestedClaims` actually reveals in the
/// proof.
public actor LongfellowZkProofSystem: ZkProofSystem {

    /// Included in `requestedClaims` (and thus asserted/disclosed by the
    /// proof) whenever a pseudonym is requested - confirmed via the
    /// `feat/longfellow-zk` reference implementation, which always lists it
    /// alongside real disclosed claims (e.g. `["age_over_18",
    /// "pairwise_pseudonym"]`), not as a separate side-channel-only concept
    /// the circuit is unaware of.
    public static let pseudonymClaim = "pairwise_pseudonym"

    nonisolated public let systemId = "longfellow-libzk-v1"

    nonisolated public let supportedDocTypes: Set<String> = [
        "org.iso.18013.5.1.mDL",
        "eu.europa.ec.eudi.pid.1",
    ]

    /// The single namespace Longfellow proving takes claims from, per
    /// supported docType. Deliberately NOT derived generically from
    /// `document.issuerSigned.nameSpaces.keys.first` (that key set's
    /// iteration order is unspecified, and a real mDL can carry a SECOND,
    /// jurisdiction-specific namespace alongside this primary one - e.g. an
    /// AAMVA-extension US mDL - so picking "the first key" is not just
    /// non-deterministic, it can pick the wrong namespace entirely).
    /// Hardcoded per-docType, matching `supportedDocTypes`/`pseudonymClaim`
    /// above already being a closed, hardcoded set rather than a generic
    /// derivation.
    private static let namespaceByDocType: [String: String] = [
        "org.iso.18013.5.1.mDL": "org.iso.18013.5.1",
        "eu.europa.ec.eudi.pid.1": "eu.europa.ec.eudi.pid.1",
    ]

    private let zkCircuitClient: ZkCircuitClient
    private let pseudonymDeriver: ZkPseudonymDeriver

    /// Cache key: (circuit id, attribute count) - a circuit is compiled for
    /// a FIXED number of attributes (e.g. `..._8_2_...` proves exactly 2),
    /// so two requests against the same circuit id but different claim
    /// counts are genuinely different prover instances, not a cache hit.
    private struct ProverCacheKey: Hashable {
        let circuitId: String
        let numAttributes: Int
    }
    private var proverCache: [ProverCacheKey: MdocZkProver] = [:]

    public init(
        zkCircuitClient: ZkCircuitClient,
        pseudonymDeriver: ZkPseudonymDeriver = DefaultZkPseudonymDeriver()
    ) {
        self.zkCircuitClient = zkCircuitClient
        self.pseudonymDeriver = pseudonymDeriver
    }

    /// Matches any requested spec declaring `system == "longfellow"` -
    /// mirrors `WscdSelectionPolicy`'s "nominal capability" convention (a
    /// static declaration, not a live probe): whether the specific circuit
    /// `ZkSystemSpec.id` names is actually fetchable is only verified
    /// lazily, in `generateProof` - `matchingSpec` itself can't do network
    /// I/O (it's a plain, synchronous, non-isolated function, used during
    /// request-vs-capability matching before any proof generation is
    /// committed to).
    nonisolated public func matchingSpec(_ requestedSpecs: [ZkSystemSpec]) -> ZkSystemSpec? {
        requestedSpecs.first { $0.system == "longfellow" }
    }

    public func generateProof(
        spec: ZkSystemSpec,
        credentialBytes: [UInt8],
        sessionTranscript: [UInt8],
        requestedClaims: [String],
        verifierIdentity: VerifierIdentity?,
        signer: @Sendable @escaping ([UInt8]) async throws -> [UInt8],
        priorState: [UInt8]?
    ) async throws -> ZkProofResult {
        // A caller that explicitly lists `pairwise_pseudonym` in
        // `requestedClaims` without also supplying `verifierIdentity` has an
        // inconsistent request: below, a nil `verifierIdentity` always takes
        // the non-PPID `prove` path, which would silently drop the
        // pseudonym request rather than honor or reject it. Reject it here
        // instead of producing a proof that doesn't match what was asked.
        if verifierIdentity == nil && requestedClaims.contains(Self.pseudonymClaim) {
            throw MdocError.malformed(
                "requestedClaims includes '\(Self.pseudonymClaim)' but verifierIdentity is nil - " +
                "a pseudonym was requested without specifying who it should be bound to"
            )
        }

        var effectiveClaims = requestedClaims
        if verifierIdentity != nil && !effectiveClaims.contains(Self.pseudonymClaim) {
            effectiveClaims.append(Self.pseudonymClaim)
        }

        let document = try MdocCbor.parseStoredCredential(credentialBytes)
        guard let expectedNamespace = Self.namespaceByDocType[document.docType] else {
            throw MdocError.malformed("mdoc credential has unsupported docType '\(document.docType)'")
        }
        guard document.issuerSigned.nameSpaces[expectedNamespace] != nil else {
            throw MdocError.malformed(
                "mdoc credential '\(document.docType)' has no disclosed '\(expectedNamespace)' namespace"
            )
        }
        let namespace = expectedNamespace

        let prover = try await getOrInitProver(spec: spec, numAttributes: effectiveClaims.count)

        // Private witness only - see this actor's doc comment for why this
        // must be a REAL, fully-signed DeviceResponse, and why it's built
        // with full disclosure rather than pre-filtered to requestedClaims.
        // buildForProximity is transport-agnostic despite its name: it just
        // takes a pre-computed session transcript directly, which is exactly
        // what's needed here regardless of which real transport the caller
        // is presenting over.
        let witnessDeviceResponse = try await MdocDeviceResponseBuilder(credentialBytes: credentialBytes)
            .buildForProximity(sessionTranscriptBytes: Data(sessionTranscript), disclosedClaims: nil, signer: { data in
                Data(try await signer([UInt8](data)))
            })

        let time = ISO8601DateFormatter().string(from: Date())

        guard let verifierIdentity else {
            let proofBytes = try prove(
                prover: prover,
                deviceResponse: witnessDeviceResponse,
                namespace: namespace,
                requestedClaims: effectiveClaims,
                sessionTranscript: Data(sessionTranscript),
                time: time
            )
            return ZkProofResult(proofBytes: [UInt8](proofBytes))
        }

        let verifierContext = pseudonymDeriver.deriveVerifierContext(verifierIdentity)
        let proofBytes = try proveWithPpid(
            prover: prover,
            deviceResponse: witnessDeviceResponse,
            namespace: namespace,
            requestedClaims: effectiveClaims,
            sessionTranscript: Data(sessionTranscript),
            time: time,
            verifierContext: Data(verifierContext)
        )

        // The native API returns only proof bytes - the pseudonym itself
        // (SHA256(pseudonym_seed || verifier_context), the same formula the
        // circuit itself asserts) is computed locally so the caller can
        // display/track it, mirroring the feat/longfellow-zk reference's own
        // separate computePPID() step.
        //
        // A missing/undecodable seed here is NOT this system reporting "no
        // pseudonym support" - this system supports pseudonyms (that's why
        // we're in this branch at all); `.notSupportedBySystem` would
        // misrepresent a malformed credential as a system limitation. Since
        // `proveWithPpid` above already succeeded (the circuit itself
        // asserted this claim's presence to produce the proof), a missing
        // seed here means the credential is malformed, not that the
        // pseudonym is legitimately absent.
        let seedItem = document.issuerSigned.nameSpaces[namespace]?.first {
            $0.item.elementIdentifier == Self.pseudonymClaim
        }
        guard case .byteString(let seed)? = seedItem?.item.elementValue else {
            throw MdocError.malformed(
                "mdoc credential '\(document.docType)' has no decodable '\(Self.pseudonymClaim)' " +
                "element in namespace '\(namespace)', but a pseudonym was requested and the proof succeeded"
            )
        }
        let pseudonym = Array(SHA256.hash(data: seed + verifierContext))

        return ZkProofResult(
            proofBytes: [UInt8](proofBytes),
            pseudonym: pseudonym,
            pseudonymOutcome: .provided
        )
    }

    private func getOrInitProver(spec: ZkSystemSpec, numAttributes: Int) async throws -> MdocZkProver {
        // `initializeProver`'s native signature takes `numAttributes` as a
        // `UInt8` (circuits are compiled for a small, fixed attribute
        // count) - `UInt8(numAttributes)` below traps on any value outside
        // 0...255, which a verifier could otherwise trigger simply by
        // requesting a lot of claims. Validate first and fail with a
        // catchable error instead of crashing the process.
        guard numAttributes <= Int(UInt8.max) else {
            throw MdocError.malformed(
                "circuit '\(spec.id)' cannot prove \(numAttributes) attributes - the native prover " +
                "supports at most \(UInt8.max)"
            )
        }

        let cacheKey = ProverCacheKey(circuitId: spec.id, numAttributes: numAttributes)
        if let cached = proverCache[cacheKey] {
            return cached
        }

        let descriptor = try await zkCircuitClient.fetchCircuit(id: spec.id)
        let compressedBytes = try await zkCircuitClient.downloadArtifact(descriptor)
        let circuitBytes = try Self.decompress(compressedBytes, descriptor: descriptor)
        let circuitVersion = try Self.circuitVersion(of: descriptor)

        let prover = try initializeProver(
            circuit: circuitBytes,
            circuitVersion: circuitVersion,
            numAttributes: UInt8(numAttributes)
        )

        // Actor-isolated: no concurrent-init race to guard against here,
        // unlike a lock-based implementation - only one task body runs at a
        // time within this actor, so a second concurrent caller simply
        // awaits its turn and then hits the cache above instead of racing
        // to initialize its own duplicate (multi-hundred-MB) prover.
        proverCache[cacheKey] = prover
        return prover
    }

    /// Decompresses `compressedBytes` (zstd-compressed, per the catalog's
    /// `ZkArtifact.compression` field) using the zstd frame's own embedded
    /// content size when available (`ZSTD_getFrameContentSize`), falling
    /// back to the catalog's `uncompressed.size` metadata, and finally to a
    /// generous fixed multiplier if neither is available.
    private static func decompress(_ compressedBytes: Data, descriptor: ZkCircuitDescriptor) throws -> Data {
        // ZSTD_getFrameContentSize's two sentinel returns are defined in
        // zstd.h as `(0ULL - 1)`/`(0ULL - 2)` (ZSTD_CONTENTSIZE_UNKNOWN/
        // _ERROR) - computed directly rather than relying on the Swift
        // Clang importer resolving those object-like macros, which isn't
        // guaranteed for expression-valued `#define`s.
        let contentSizeUnknown = UInt64.max
        let contentSizeError = UInt64.max - 1
        let frameSize = compressedBytes.withUnsafeBytes { (src: UnsafeRawBufferPointer) -> UInt64 in
            ZSTD_getFrameContentSize(src.baseAddress, src.count)
        }
        let outputSize: Int
        if frameSize != contentSizeUnknown, frameSize != contentSizeError, frameSize > 0 {
            outputSize = Int(frameSize)
        } else if let uncompressedSize = descriptor.artifact?.uncompressed?.size, uncompressedSize > 0 {
            #if canImport(os)
            logger.warning("Circuit '\(descriptor.id)' zstd frame has no embedded content size; using catalog metadata")
            #endif
            outputSize = Int(uncompressedSize)
        } else {
            #if canImport(os)
            logger.warning("Circuit '\(descriptor.id)' has no known uncompressed size; guessing buffer size")
            #endif
            // These circuits compress at roughly 300-400x (a 319KB real V8
            // 2-attribute circuit decompresses to ~104MB, confirmed via
            // `zstd -l`) - only reached if BOTH the frame's own embedded
            // content size AND the catalog's uncompressed.size are absent.
            outputSize = compressedBytes.count * 400
        }

        var output = Data(count: outputSize)
        let writtenOrError = output.withUnsafeMutableBytes { (dst: UnsafeMutableRawBufferPointer) -> Int in
            compressedBytes.withUnsafeBytes { (src: UnsafeRawBufferPointer) -> Int in
                ZSTD_decompress(dst.baseAddress, dst.count, src.baseAddress, src.count)
            }
        }
        guard ZSTD_isError(writtenOrError) == 0 else {
            throw MdocError.malformed("zstd decompression failed for circuit '\(descriptor.id)'")
        }
        if writtenOrError != outputSize {
            output = output.prefix(writtenOrError)
        }
        return output
    }

    private static func circuitVersion(of descriptor: ZkCircuitDescriptor) throws -> CircuitVersion {
        switch descriptor.systemVersion {
        case "6": return .v6
        case "7": return .v7
        case "8": return .v8
        default:
            throw MdocError.malformed(
                "Longfellow circuit '\(descriptor.id)' has unsupported systemVersion '\(descriptor.systemVersion)'"
            )
        }
    }
}

#if canImport(os)
import os
private let logger = Logger(subsystem: "org.siros.sdk", category: "LongfellowZkProofSystem")
#endif

#endif // os(iOS)

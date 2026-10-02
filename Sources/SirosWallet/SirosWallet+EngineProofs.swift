// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
import SirosKeystore
import SirosTransport
#if canImport(CryptoKit)
import CryptoKit
#else
// swift-crypto's `Crypto` module mirrors CryptoKit's API 1:1, including
// SHA256 - see Package.swift's SirosWallet dependencies. Used only for
// `extractProofKeyId`'s RFC 7638 thumbprint, which must work on every
// platform this SDK builds for, unlike `DCAPIResponseEncryption` (entirely
// CryptoKit-gated, Apple-only).
import Crypto
#endif

/// `generate_proof` sign-request handling - split out of
/// `SirosWallet+Engine.swift` (review finding: that file crossed SwiftLint's
/// `file_length` error threshold) since this is already a coherent,
/// self-contained unit: proof-type selection, the actual `jwt`/`attestation`
/// generation `generateProofs` shares across both transports, and the
/// `jwt`-proof key-id recovery `activeAttestedKeyIds` depends on.
extension SirosWallet {
    /// Select the proof type to generate, shared by both transports (WMP and
    /// the legacy WS engine) so a real external issuer that lists only
    /// "attestation" in proof_types_supported gets the same treatment
    /// regardless of which transport carried the request. `proofTypesSupported`
    /// (from the issuer's metadata) takes precedence when present; `proofTypeHint`
    /// is a fallback for WMP, whose wire format only carries a single hint string,
    /// not the full supported-types set the legacy engine path receives.
    private func selectProofType(proofTypesSupported: [String: AnyCodable]?, proofTypeHint: String?) -> String {
        if let supported = proofTypesSupported, !supported.isEmpty {
            if supported["jwt"] != nil { return "jwt" }
            if supported["attestation"] != nil { return "attestation" }
            return supported.keys.first ?? "jwt"
        }
        if let hint = proofTypeHint, !hint.isEmpty { return hint }
        return "jwt"
    }

    /// Internal counterpart to the wire-format `ProofObject`, additionally
    /// carrying the device key IDs backing an `attestation` proof's
    /// `attested_keys` (in submission order) - `nil` when unavailable (the
    /// self-signed-fallback path doesn't currently expose the keys it
    /// generated internally). See `activeAttestedKeyIds`'s doc comment for
    /// why this ordering matters for per-credential key selection at signing
    /// time.
    // Internal (not private) - see `requestBackendKeyAttestation`'s doc
    // comment on why that function itself is internal for testability; the
    // fallback-keystore-bypass regression test needs to drive `generateProofs`
    // directly, which needs this to be visible to `@testable import` too.
    struct GeneratedProofData {
        var proofType: String
        var jwt: String?
        var attestation: String?
        var attestedKeyIds: [String]?
    }

    // Internal (not private) - see `requestBackendKeyAttestation`'s doc
    // comment on why that function itself is internal for testability.
    struct BackendAttestationResult {
        var jwt: String
        var keyIds: [String]
    }

    /// Generate proofs for a `generate_proof` sign request - shared by both
    /// transports so proof generation (including real backend Key Attestation
    /// with a self-signed fallback) behaves identically regardless of which
    /// transport carried the request.
    // Internal (not private) so `@testable import` can exercise the
    // backend-attestation-fails-so-fall-back-to-self-signed path directly
    // (see `SirosWalletWscdSelectionTests.testFallbackAfterFailedBackendAttestationUsesResolvedKeystoreNotDefault`),
    // matching `requestBackendKeyAttestation`'s existing testability precedent.
    func generateProofs(
        audience: String,
        nonce: String,
        count: Int,
        proofTypesSupported: [String: AnyCodable]?,
        proofTypeHint: String?
    ) async throws -> [GeneratedProofData] {
        let chosen = selectProofType(proofTypesSupported: proofTypesSupported, proofTypeHint: proofTypeHint)
        if chosen == "attestation" {
            let (backendAttestation, effectiveKeystore) = try await requestBackendKeyAttestation(audience: audience, nonce: nonce, count: count)
            let attestationJwt: String
            if let backendAttestation {
                attestationJwt = backendAttestation.jwt
            } else {
                // Must fall back on the SAME resolved keystore
                // `requestBackendKeyAttestation` picked for this call (e.g.
                // a `WscdSelectionPolicy`-resolved plugin), never
                // unconditionally `self.keystore` - otherwise a resolved
                // higher-tier plugin would be silently bypassed on fallback,
                // generating a lower-tier self-signed attestation instead.
                attestationJwt = try await effectiveKeystore.generateKeyAttestation(nonce: nonce, count: count)
            }
            return [GeneratedProofData(
                proofType: "attestation",
                attestation: attestationJwt,
                attestedKeyIds: backendAttestation?.keyIds
            )]
        }
        var proofs: [GeneratedProofData] = []
        for _ in 0..<count {
            // `audience` is the credential issuer, which is what decides
            // whether this proof names the holder key by did:jwk (DIIP) or
            // carries it (HAIP) - negotiated from that issuer's own metadata.
            let jwt = try await keystore.generateProof(
                audience: audience,
                nonce: nonce,
                freshKey: count > 1,
                holderBinding: holderBinding(for: audience)
            )
            let keyId = Self.extractProofKeyId(jwt: jwt)
            proofs.append(GeneratedProofData(proofType: "jwt", jwt: jwt, attestedKeyIds: keyId.map { [$0] }))
        }
        return proofs
    }

    /// Recover the signing key's `kid` from a `jwt`-proof-type proof-of-possession
    /// JWT's embedded `jwk` header claim, since `KeystoreManager.generateProof`
    /// doesn't return it directly. Without this, `activeAttestedKeyIds` stayed
    /// nil for every credential issued via the (preferred, common) `jwt` proof
    /// path - a real bug found via live proximity-presentation testing on the
    /// Kotlin SDK (confirmed to share the identical architecture here): with
    /// `credential.kid` nil, `WscdKeystoreAdapter.selectSigningKey` falls back
    /// to "first available key" among ALL WSCD keys, which is only correct by
    /// chance whenever more than one key exists - `deviceSignature` verification
    /// then fails unpredictably depending on `signer.listKeys()`'s ordering.
    private static func extractProofKeyId(jwt: String) -> String? {
        guard let headerPart = jwt.split(separator: ".", maxSplits: 1).first else { return nil }
        guard let headerData = CredentialUtils.base64UrlDecode(String(headerPart)) else { return nil }
        guard let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any] else { return nil }
        // A DIIP proof names the key with a `kid` header and carries no `jwk`
        // at all; a HAIP one embeds the key, by value. The embedded `jwk` as
        // actually built by `JweKeystore`/`WscdKeystoreAdapter` carries only
        // `kty`/`crv`/`x`/`y` - no `jwk.kid` member of its own - so a
        // conformant producer never hits the `jwk["kid"]` branch below; it
        // stays only for a `KeystoreManager` that does embed one. Absent
        // that, the id is the RFC 7638 thumbprint of the embedded key - the SAME
        // value `KeypairIdentity.matches` already falls back to when looking
        // up a HAIP-bound credential's key, so `activeAttestedKeyIds` staying
        // nil here for every `jwk`-proof credential (review finding) would
        // have left HAIP exactly as broken as DIIP was before this method
        // existed, just for the opposite proof shape.
        if let kid = header["kid"] as? String { return kid }
        guard let jwk = header["jwk"] as? [String: Any] else { return nil }
        if let kid = jwk["kid"] as? String { return kid }
        return Self.jwkThumbprint(jwk)
    }

    /// RFC 7638 JWK Thumbprint of an EC public JWK: SHA-256 over
    /// `{"crv":...,"kty":...,"x":...,"y":...}` in lexicographic member order
    /// with no insignificant whitespace, base64url-encoded.
    ///
    /// Duplicates `DCAPIResponseEncryption.jwkThumbprint` rather than calling
    /// it: that one is entirely `#if canImport(CryptoKit)`-gated (Apple-only -
    /// see its own doc comment), but this file - and `extractProofKeyId`'s
    /// caller, `generateProofs` - builds and runs on every platform this SDK
    /// targets, Linux included.
    private static func jwkThumbprint(_ jwk: [String: Any]) -> String? {
        guard let crv = jwk["crv"] as? String,
              let kty = jwk["kty"] as? String,
              let x = jwk["x"] as? String,
              let y = jwk["y"] as? String else {
            return nil
        }
        let canonical = "{\"crv\":\"\(crv)\",\"kty\":\"\(kty)\",\"x\":\"\(x)\",\"y\":\"\(y)\"}"
        let digest = Data(SHA256.hash(data: Data(canonical.utf8)))
        return digest.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

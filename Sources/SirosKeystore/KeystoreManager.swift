// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Manages encrypted credential key storage.
///
/// The keystore is unlocked using a PRF-derived key (from WebAuthn)
/// and contains private keys for credential signing operations.
/// The encrypted container is synchronized with the backend for
/// cross-device portability.
public protocol KeystoreManager: AnyObject, Sendable {
    /// Whether the keystore is currently unlocked and usable.
    var isUnlocked: Bool { get }

    /// Unlock the keystore using PRF-derived key material.
    ///
    /// - Parameters:
    ///   - prfOutput: raw PRF output from the WebAuthn authenticator (32 bytes).
    ///   - encryptedContainer: the encrypted container (may be empty for first-time setup).
    ///   - hkdfSalt: HKDF extraction salt (32 bytes).
    ///   - hkdfInfo: HKDF expansion info (e.g. "eDiplomas PRF").
    func unlock(
        prfOutput: Data,
        encryptedContainer: Data,
        hkdfSalt: Data,
        hkdfInfo: Data
    ) async throws

    /// Lock the keystore, clearing key material from memory.
    func lock()

    /// Generate a new keypair and return the key ID.
    func generateKey(algorithm: String) async throws -> String

    /// Sign a payload with the specified key.
    func sign(keyId: String, payload: Data, algorithm: String) async throws -> Data

    /// Generate a proof JWT for credential issuance (c_nonce binding).
    /// When `freshKey` is true, a new key is generated for this proof (batch issuance).
    func generateProof(audience: String, nonce: String, freshKey: Bool) async throws -> String

    /// Sign a verifiable presentation for OID4VP.
    ///
    /// - Parameter kid: the key ID bound to the credential(s) being
    ///   presented (see `StoredCredential.kid`) - when non-nil, signing MUST
    ///   use exactly this key (throwing if it isn't available) rather than
    ///   an arbitrary one, since a wallet holding more than one key (e.g.
    ///   after a batch issuance where each credential instance is bound to
    ///   its own device key) would otherwise silently sign with the wrong
    ///   key for every credential except whichever one happens to be first.
    ///   nil (the legacy no-credential-context call shape) preserves the old
    ///   first-available-key behavior.
    func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String

    /// Build a complete SD-JWT VP token with Key Binding JWT.
    ///
    /// - Parameter kid: the key ID bound to this credential (see
    ///   `signPresentation`'s doc comment for why this must be the exact
    ///   key, not an arbitrary available one).
    func signVpToken(
        credential: String,
        disclosedClaims: [String]?,
        nonce: String,
        audience: String,
        kid: String?
    ) async throws -> String

    /// Build an mDoc DeviceResponse (ISO 18013-5) for OID4VP presentation.
    ///
    /// - Parameter kid: the key ID bound to this credential (see
    ///   `signPresentation`'s doc comment) - the DeviceResponse's
    ///   `deviceSignature` MUST be produced with the exact device key this
    ///   credential's MSO `deviceKeyInfo.deviceKey` embeds.
    func signMdocPresentation(
        credentialBytes: Data,
        disclosedClaims: [String]?,
        nonce: String,
        audience: String,
        responseUri: String,
        verifierJwkThumbprint: String?,
        kid: String?
    ) async throws -> Data

    /// Build an mDoc DeviceResponse (ISO 18013-5) for OID4VP presentation via
    /// the W3C Digital Credentials API, using the `OpenID4VPDCAPIHandover`
    /// session transcript (OpenID4VP 1.0 Appendix B.2.6) instead of
    /// ``signMdocPresentation(credentialBytes:disclosedClaims:nonce:audience:responseUri:verifierJwkThumbprint:)``'s
    /// redirect-flow `OpenID4VPHandover`.
    ///
    /// - Parameters:
    ///   - credentialBytes: Raw CBOR bytes of the IssuerSigned structure.
    ///   - disclosedClaims: Claim names to disclose (nil = all).
    ///   - nonce: Verifier-provided nonce.
    ///   - origin: The verified browser/page origin that called `navigator.credentials.get()`.
    ///   - encryptionPublicJwkThumbprint: JWK thumbprint of the verifier's
    ///     response-encryption key (present when `response_mode=dc_api.jwt`), nil otherwise.
    ///   - kid: the key ID bound to this credential (see `signMdocPresentation`'s doc comment).
    /// - Returns: Base64url-encoded DeviceResponse CBOR bytes.
    func signMdocPresentationForDCAPI(
        credentialBytes: Data,
        disclosedClaims: [String]?,
        nonce: String,
        origin: String,
        encryptionPublicJwkThumbprint: String?,
        kid: String?
    ) async throws -> Data

    /// Export the encrypted container for backend sync.
    func exportEncryptedContainer() async throws -> Data

    /// List all key IDs in the keystore.
    func listKeys() -> [KeyInfo]

    // MARK: - Credential storage

    /// Store a credential's raw JSON inside the encrypted container.
    func saveCredential(id: Int64, json: String) async throws

    /// Get a stored credential's raw JSON by ID.
    func getCredential(id: Int64) async throws -> String?

    /// Get all stored credential JSON blobs.
    func getAllCredentials() async throws -> [Int64: String]

    /// Remove a credential by ID.
    func deleteCredential(id: Int64) async throws

    /// Remove all stored credentials.
    func clearCredentials() async throws

    // MARK: - Presentation history storage

    /// Store a presentation record's raw JSON inside the encrypted container.
    func savePresentationRecord(id: Int64, json: String) async throws

    /// Get all stored presentation record JSON blobs.
    func getAllPresentationRecords() async throws -> [Int64: String]

    /// Remove all stored presentation records.
    func clearPresentationRecords() async throws

    /// Generate `count` keypairs and return their public JWKs.
    /// Used for key attestation requests.
    func generateKeypairs(count: Int) async throws -> [KeypairInfo]

    /// Get the security properties for this keystore's signing keys.
    /// Used to populate KA JWT claims (CS-04 §7.1.3, Annex C §C.3.1).
    /// Returns nil if security properties are not available.
    func securityProperties() async -> SignerSecurityProperties?

    /// Get the security properties for a specific key, as reported by the
    /// underlying WSCD/signer. Used to populate a real backend-issued Key
    /// Attestation request's `security_properties` (CS-04 §7.1.3, Annex C
    /// §C.3.1) with the properties of the actual freshly-generated
    /// attestation keys, rather than the batch-agnostic [securityProperties]
    /// above. Returns nil if not available.
    func securityProperties(keyId: String) async -> SignerSecurityProperties?

    /// Generate `count` fresh keypairs and build a single OID4VCI `attestation`
    /// proof-type Key Attestation JWT (spec: "Key Attestation in JWT format",
    /// proof type Appendix "attestation Proof Type") covering all of them via
    /// the `attested_keys` claim.
    ///
    /// Unlike the `jwt` proof type (one proof of possession per credential in
    /// the batch), the spec requires exactly one Key Attestation JWT per
    /// request regardless of `count` - the issuer is expected to mint one
    /// credential per entry in `attested_keys`.
    ///
    /// Default implementation throws so existing implementations continue to
    /// compile without attestation support.
    func generateKeyAttestation(nonce: String, count: Int) async throws -> String

    /// Build a self-signed JWT proof for an existing key: header `{typ, jwk =
    /// that key's own public JWK}`, claims `{iss, aud, iat, exp, jti, ...extraClaims}`.
    ///
    /// Used for OAuth Client Attestation PoP JWTs
    /// (draft-ietf-oauth-attestation-based-client-auth-10 §3.1) - both the
    /// one-time proof sent to this wallet's own backend to obtain a Wallet
    /// Instance Attestation (WIA) (`audience` = the wallet provider/backend,
    /// `extraClaims = ["nonce": <challenge>]`), and the per-issuance-flow
    /// proof sent (via the backend, forwarded as an HTTP header) to a
    /// credential issuer's authorization server alongside that WIA
    /// (`audience` = the issuer's AS, `extraClaims = ["challenge": ...]` when
    /// the AS publishes a `challenge_endpoint`).
    ///
    /// `issuer` is the caller's choice, not derived from the key - per the
    /// spec, `iss` should be the same OAuth `client_id` this wallet uses in
    /// the flow (matching the WIA's own `sub` claim, see
    /// `BackendApiClient.generateWIA`'s `clientId` param), not an instance
    /// identifier (that's what `cnf.jkt`, computed server-side from this
    /// proof's `jwk` header, is for).
    ///
    /// Deliberately takes an existing `keyId` rather than managing "the
    /// instance key" internally - callers are responsible for generating one
    /// persistent key (via `generateKey`) and remembering its ID across app
    /// restarts (the backend's WIA tracks/revokes wallet instances by this
    /// key's JWK thumbprint, so reusing a different key each time would
    /// silently register a new "instance" every call).
    ///
    /// Default implementation throws so existing implementations continue to
    /// compile without attestation support.
    func generateKeyProof(
        keyId: String,
        typ: String,
        issuer: String,
        audience: String,
        extraClaims: [String: String]
    ) async throws -> String
}

/// Default implementation for optional methods.
public extension KeystoreManager {
    /// Default: freshKey=false for backward compatibility.
    func generateProof(audience: String, nonce: String) async throws -> String {
        try await generateProof(audience: audience, nonce: nonce, freshKey: false)
    }

    func securityProperties() async -> SignerSecurityProperties? { nil }
    func securityProperties(keyId: String) async -> SignerSecurityProperties? { nil }
    func signMdocPresentation(
        credentialBytes: Data,
        disclosedClaims: [String]?,
        nonce: String,
        audience: String,
        responseUri: String,
        verifierJwkThumbprint: String?,
        kid: String?
    ) async throws -> Data {
        throw KeystoreError.invalidParameter("mDoc presentation not supported by this keystore")
    }

    func signMdocPresentationForDCAPI(
        credentialBytes: Data,
        disclosedClaims: [String]?,
        nonce: String,
        origin: String,
        encryptionPublicJwkThumbprint: String?,
        kid: String?
    ) async throws -> Data {
        throw KeystoreError.invalidParameter("mDoc DC API presentation not supported by this keystore")
    }

    func generateKeyAttestation(nonce: String, count: Int) async throws -> String {
        throw KeystoreError.invalidParameter("generateKeyAttestation not supported by this keystore")
    }

    func generateKeyProof(
        keyId: String,
        typ: String,
        issuer: String,
        audience: String,
        extraClaims: [String: String]
    ) async throws -> String {
        throw KeystoreError.invalidParameter("generateKeyProof not supported by this keystore")
    }
}

/// Result of a generateKeypairs call.
public struct KeypairInfo: @unchecked Sendable {
    public let keyId: String
    public let publicKeyJWK: [String: Any]

    public init(keyId: String, publicKeyJWK: [String: Any]) {
        self.keyId = keyId
        self.publicKeyJWK = publicKeyJWK
    }
}

/// Information about a key in the keystore.
public struct KeyInfo: Sendable, Equatable {
    public let keyId: String
    public let algorithm: String
    public let createdAt: Int64

    public init(keyId: String, algorithm: String, createdAt: Int64 = 0) {
        self.keyId = keyId
        self.algorithm = algorithm
        self.createdAt = createdAt
    }
}

/// Keystore-related errors.
public enum KeystoreError: Error, Sendable {
    case locked
    case keyNotFound(String)
    case containerMissing(String)
    case cryptoError(String)
    case invalidContainer(String)
    case invalidParameter(String)
}

extension KeystoreError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .locked: return "Keystore is locked"
        case .keyNotFound(let id): return "Key not found: \(id)"
        case .containerMissing(let id): return "Container missing: \(id)"
        case .cryptoError(let msg): return "Crypto error: \(msg)"
        case .invalidContainer(let msg): return "Invalid container: \(msg)"
        case .invalidParameter(let msg): return "Invalid parameter: \(msg)"
        }
    }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// A minimal signing interface for raw key operations.
///
/// This protocol represents the cryptographic backend (WSCD) layer
/// that performs key generation, signing, and attestation.
/// Implementations may use software keys, hardware tokens (FIDO2/CTAP2),
/// or remote HSMs (R2PS/PKCS#11).
public protocol Signer: AnyObject, Sendable {
    /// Generate a new keypair.
    /// - Parameter algorithm: Algorithm identifier (e.g. "ES256", "EdDSA").
    /// - Returns: The key ID of the generated key.
    func generateKey(algorithm: String) async throws -> String

    /// Sign raw data with the specified key.
    /// - Parameters:
    ///   - keyId: ID of the key to use.
    ///   - data: Raw bytes to sign.
    /// - Returns: The signature bytes.
    func sign(keyId: String, data: Data) async throws -> Data

    /// List all keys managed by this signer.
    func listKeys() async throws -> [SignerKeyInfo]

    /// Delete a key by ID.
    func deleteKey(keyId: String) async throws

    /// Return the attestation certificate chain for a key, if available.
    ///
    /// For hardware-backed keys (FIDO2, CTAP2), this returns the
    /// attestation statement certificate chain proving key provenance.
    /// For software keys, returns `nil`.
    func attestationChain(keyId: String) async throws -> [Data]?

    /// Export the public key in JWK format (JSON-encoded).
    func exportPublicKey(keyId: String) async throws -> Data

    /// Migrate a key from one WSCD plugin to another.
    ///
    /// Returns the migration result indicating whether the key was
    /// successfully migrated or whether re-enrollment is required.
    func migrateKey(keyId: String, targetPlugin: String) async throws -> MigrationResult

    /// Return the security properties for a key.
    ///
    /// Reports key storage type, certification level, user authentication
    /// methods, and AMR values. The `amr` field reflects the authentication
    /// methods used in the most recent `sign()` operation.
    func securityProperties(keyId: String) async throws -> SignerSecurityProperties
}

/// Result of a key migration operation.
public enum MigrationResult: Sendable {
    /// Key migrated successfully; contains the new key ID.
    case migrated(newKeyId: String)
    /// Migration requires full re-enrollment with the issuer.
    case reEnrollmentRequired(oldKeyId: String)
}

/// Key metadata returned by a `Signer`.
public struct SignerKeyInfo: Sendable, Equatable {
    public let keyId: String
    public let algorithm: String

    public init(keyId: String, algorithm: String) {
        self.keyId = keyId
        self.algorithm = algorithm
    }
}

/// Key storage type classification per CS-04 §7.1.3.
public enum KeyStorageType: String, Sendable {
    case software
    case hardware
    case remoteHsm = "remote_hsm"
    case trustedExecution = "trusted_execution"
}

/// Certification level for the WSCD.
public enum CertificationLevel: String, Sendable {
    case none
    case baseline
    case substantial
    case high
}

/// Security properties reported by a `Signer` for a given key.
public struct SignerSecurityProperties: Sendable {
    /// How the key material is stored.
    public let keyStorage: KeyStorageType
    /// User authentication methods supported.
    public let userAuthentication: [String]
    /// Certification level of the key storage.
    public let certification: CertificationLevel
    /// Authentication Method Reference values from the last sign operation.
    public let amr: [String]

    public init(
        keyStorage: KeyStorageType,
        userAuthentication: [String] = [],
        certification: CertificationLevel = .none,
        amr: [String] = []
    ) {
        self.keyStorage = keyStorage
        self.userAuthentication = userAuthentication
        self.certification = certification
        self.amr = amr
    }
}

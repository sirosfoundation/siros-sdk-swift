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
    func generateProof(audience: String, nonce: String) async throws -> String

    /// Sign a verifiable presentation for OID4VP.
    func signPresentation(nonce: String, audience: String, credentialIds: [String]) async throws -> String

    /// Build a complete SD-JWT VP token with Key Binding JWT.
    func signVpToken(
        credential: String,
        disclosedClaims: [String]?,
        nonce: String,
        audience: String
    ) async throws -> String

    /// Export the encrypted container for backend sync.
    func exportEncryptedContainer() async throws -> Data

    /// List all key IDs in the keystore.
    func listKeys() -> [KeyInfo]

    // MARK: - Credential storage

    /// Store a credential's raw JSON inside the encrypted container.
    func saveCredential(id: String, json: String) async throws

    /// Get a stored credential's raw JSON by ID.
    func getCredential(id: String) async throws -> String?

    /// Get all stored credential JSON blobs.
    func getAllCredentials() async throws -> [String: String]

    /// Remove a credential by ID.
    func deleteCredential(id: String) async throws

    /// Remove all stored credentials.
    func clearCredentials() async throws

    /// Generate `count` keypairs and return their public JWKs.
    /// Used for key attestation requests.
    func generateKeypairs(count: Int) async throws -> [KeypairInfo]
}

/// Result of a generateKeypairs call.
public struct KeypairInfo: Sendable {
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
}

extension KeystoreError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .locked: return "Keystore is locked"
        case .keyNotFound(let id): return "Key not found: \(id)"
        case .containerMissing(let id): return "Container missing: \(id)"
        case .cryptoError(let msg): return "Crypto error: \(msg)"
        case .invalidContainer(let msg): return "Invalid container: \(msg)"
        }
    }
}

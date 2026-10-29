// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Low-level access to Apple's Secure Enclave for the `apple-se` WSCD
/// plugin (siros-wscd-manager's `SecureEnclaveCallback` host side).
///
/// Extracted as a protocol - mirroring `AppAttestServiceProviding`'s role
/// for `AppAttestProvider` - so `SecureEnclaveWscdCallbackBridge` can be
/// unit-tested with a fake instead of needing a real Secure Enclave:
/// `SecureEnclave.isAvailable` is `false` in CI/Simulator, the same
/// limitation `AppAttestServiceProviding`'s doc comment already notes for
/// App Attest.
///
/// This is deliberately separate from, and does not touch,
/// `NativeAttestationProvider`/`AppAttestProvider` (the existing WIA path):
/// App Attest is a single non-repeatable per-install attestation ceremony
/// over one special-purpose key, not a general-purpose signer, so it has
/// no twin to port here - this protocol and its real implementation
/// (`SystemSecureEnclaveKeyStore`) are genuinely new.
public protocol SecureEnclaveKeystoreBackend: Sendable {
    /// Whether this device has a Secure Enclave available right now.
    var isAvailable: Bool { get }

    /// Generate a new P-256 signing key in the Secure Enclave, persisted
    /// so a later `sign`/`deleteKey` call for the same `keyTag` finds the
    /// same key.
    ///
    /// - Returns: The public key's raw (x, y) coordinates, 32 bytes each -
    ///   `CryptoKit.P256.Signing.PublicKey.rawRepresentation`, confirmed on
    ///   real Xcode 26.6 / iOS 26.5 SDK headers (2026-10-29) to be exactly
    ///   `x || y` with no leading format byte (unlike `x963Representation`,
    ///   which has a leading `0x04`).
    func generateKey(keyTag: String) throws -> (x: Data, y: Data)

    /// Sign `data` with the Secure Enclave key stored under `keyTag`.
    ///
    /// `SecureEnclave.P256.Signing.PrivateKey.signature(for:)` hashes its
    /// input with SHA-256 internally, so `data` is the exact signing
    /// input here, not pre-hashed - matches
    /// `siros-wscd-manager`'s `Algorithm::ES256` contract
    /// (`Algorithm::signs_prehashed_input`).
    /// - Returns: A raw `r || s` ECDSA signature, 64 bytes -
    ///   `P256.Signing.ECDSASignature.rawRepresentation`.
    func sign(keyTag: String, data: Data) throws -> Data

    /// Delete the Secure Enclave key stored under `keyTag`.
    /// - Throws: `SecureEnclaveKeystoreError.keyNotFound` if no key is
    ///   stored under `keyTag` - callers must be able to tell "deleted"
    ///   from "was never there", which a bare Keychain delete can't do on
    ///   its own.
    func deleteKey(keyTag: String) throws
}

/// Errors specific to `SecureEnclaveKeystoreBackend` operations.
public enum SecureEnclaveKeystoreError: Error, Sendable {
    case notAvailable
    case keyNotFound(String)
    /// A raw Keychain `OSStatus` code (`Security.framework`'s `OSStatus` IS
    /// `Int32` - a typealias, not a distinct type - so this stays portable:
    /// `SecureEnclaveKeystoreBackend`/this error type are referenced from
    /// cross-platform code like `WscdManager.swift`, which must still
    /// compile on Linux, where `Security` (and the real `OSStatus` name)
    /// doesn't exist at all).
    case keychainError(Int32)
    case keyGenerationFailed(String)
    case signingFailed(String)
}

extension SecureEnclaveKeystoreError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .notAvailable:
            return "Secure Enclave is not available on this device"
        case .keyNotFound(let tag):
            return "Secure Enclave key not found: \(tag)"
        case .keychainError(let status):
            return "Keychain error: \(status)"
        case .keyGenerationFailed(let message):
            return "Secure Enclave key generation failed: \(message)"
        case .signingFailed(let message):
            return "Secure Enclave signing failed: \(message)"
        }
    }
}

#if canImport(CryptoKit)
import CryptoKit
import Security

/// Real Secure-Enclave-backed implementation of `SecureEnclaveKeystoreBackend`.
///
/// Generates a `SecureEnclave.P256.Signing.PrivateKey` per `generateKey`
/// call and persists its `dataRepresentation` - an opaque Keychain-wrapped
/// blob, NOT raw key material, and the only way CryptoKit allows this key
/// to be reconstructed later - as a `kSecClassGenericPassword` Keychain
/// item keyed by `keyTag`, mirroring `KeychainSessionStore`'s existing
/// read/write pattern (SecItemDelete-then-SecItemAdd on write).
///
/// Confirmed against the real iOS 26.5 SDK's CryptoKit swiftinterface
/// (2026-10-29): `SecureEnclave.P256.Signing.PrivateKey` has no "find by
/// tag" lookup of its own - its only two initializers are "generate a new
/// key" (`init(compactRepresentable:accessControl:authenticationContext:)`)
/// and "reconstruct from a previously-saved `dataRepresentation`"
/// (`init(dataRepresentation:authenticationContext:)`). Persisting that
/// blob ourselves, the way this class does, is the only way to use the
/// same Secure Enclave key across calls or process restarts.
///
/// Also confirmed on the same SDK: `SecKeyCreateAttestation` does not
/// exist in `Security/SecKey.h` on this Xcode/SDK version, and no
/// CryptoKit type exposes any attestation-shaped API - see
/// `SecureEnclaveCallback`'s doc comment on the Rust side (siros-wscd-manager)
/// for why this class reports no per-key attestation chain.
public final class SystemSecureEnclaveKeyStore: SecureEnclaveKeystoreBackend, @unchecked Sendable {
    private let service: String
    private let accessGroup: String?
    private let lock = NSLock()

    /// - Parameters:
    ///   - service: Keychain service identifier scoping this store's
    ///     items, deliberately separate from `KeychainSessionStore`'s own
    ///     default service so the two never collide on `(service, account)`.
    ///   - accessGroup: Optional Keychain access group for sharing across apps.
    public init(service: String = "org.siros.wscd.apple-se", accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }

    public var isAvailable: Bool {
        SecureEnclave.isAvailable
    }

    public func generateKey(keyTag: String) throws -> (x: Data, y: Data) {
        guard isAvailable else { throw SecureEnclaveKeystoreError.notAvailable }
        let accessControl = try Self.userPresenceAccessControl()
        let key: SecureEnclave.P256.Signing.PrivateKey
        do {
            // `.userPresence` (not `.biometryCurrentSet`, matching
            // `LocalAuthProvider.register`'s exact precedent/reasoning): a
            // bare `SecureEnclave.P256.Signing.PrivateKey()` uses CryptoKit's
            // own default access control, which has NO authentication
            // requirement at all (confirmed on the real iOS 26.5 SDK
            // swiftinterface - the default flags are empty) - every sign
            // would otherwise succeed unconditionally, with zero
            // device-authentication guarantee, unlike every other hardware
            // WSCD plugin (FIDO2 requires a PIN/UV by the CTAP2 protocol
            // itself). `.userPresence` isn't invalidated by biometry
            // re-enrollment and still allows passcode fallback.
            key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl)
        } catch {
            throw SecureEnclaveKeystoreError.keyGenerationFailed(String(describing: error))
        }
        try writeDataRepresentation(key.dataRepresentation, forTag: keyTag, accessControl: accessControl)
        let raw = key.publicKey.rawRepresentation
        precondition(raw.count == 64, "P-256 rawRepresentation must be x || y, 64 bytes")
        return (x: raw.prefix(32), y: raw.suffix(32))
    }

    /// `.userPresence`-gated access control, shared by the Secure Enclave
    /// key itself and the Keychain item wrapping its `dataRepresentation` -
    /// see `generateKey`'s doc comment for why both need it, not just the
    /// key.
    private static func userPresenceAccessControl() throws -> SecAccessControl {
        var acError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .userPresence,
            &acError
        ) else {
            throw SecureEnclaveKeystoreError.keyGenerationFailed(
                "failed to create access control: \(String(describing: acError))"
            )
        }
        return accessControl
    }

    public func sign(keyTag: String, data: Data) throws -> Data {
        guard isAvailable else { throw SecureEnclaveKeystoreError.notAvailable }
        let key = try loadKey(forTag: keyTag)
        do {
            return try key.signature(for: data).rawRepresentation
        } catch {
            throw SecureEnclaveKeystoreError.signingFailed(String(describing: error))
        }
    }

    public func deleteKey(keyTag: String) throws {
        // Checked via `keyExists` (an attributes-only query), not
        // `readDataRepresentation`/`loadKey` - now that the wrapper item is
        // `.userPresence`-gated (see `writeDataRepresentation`'s doc
        // comment), requesting the actual VALUE would prompt for
        // biometry/passcode just to check presence. An attributes-only
        // query never touches the protected value, so it needs no
        // authentication - confirmed Apple Keychain behavior: access
        // control only gates `kSecReturnData`, not existence/attribute
        // queries.
        guard keyExists(forTag: keyTag) else {
            throw SecureEnclaveKeystoreError.keyNotFound(keyTag)
        }
        try deleteDataRepresentation(forTag: keyTag)
    }

    // MARK: - Reconstructing a key from its persisted `dataRepresentation`

    private func loadKey(forTag tag: String) throws -> SecureEnclave.P256.Signing.PrivateKey {
        guard let data = readDataRepresentation(forTag: tag) else {
            throw SecureEnclaveKeystoreError.keyNotFound(tag)
        }
        do {
            return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data)
        } catch {
            // Not `.keyNotFound` - the Keychain item exists but CryptoKit
            // rejected it (corrupt blob, wrong device/Secure Enclave,
            // biometry/access-control failure) - a different failure mode
            // the caller should not treat as "retry generate instead".
            throw SecureEnclaveKeystoreError.signingFailed(String(describing: error))
        }
    }

    // MARK: - Keychain storage of `dataRepresentation`

    /// Whether a Keychain item exists under `tag`, without ever requesting
    /// its (access-control-gated) value - see `deleteKey`'s doc comment.
    private func keyExists(forTag tag: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: tag,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    private func readDataRepresentation(forTag tag: String) -> Data? {
        lock.lock(); defer { lock.unlock() }
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: tag,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return data
    }

    /// `accessControl` is required (not defaulted to plain
    /// `kSecAttrAccessible`, the way `KeychainSessionStore` stores its own
    /// items): a SonarCloud finding on this PR flagged the earlier
    /// no-authentication version of this exact line ("This keychain item
    /// will not require authentication to be used") - this wrapper item
    /// holds the handle to a Secure Enclave key, not an arbitrary token, so
    /// it is gated the same way the key itself now is (`generateKey`'s
    /// `.userPresence` access control), not left open.
    private func writeDataRepresentation(_ data: Data, forTag tag: String, accessControl: SecAccessControl) throws {
        lock.lock(); defer { lock.unlock() }
        var deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: tag,
        ]
        if let accessGroup { deleteQuery[kSecAttrAccessGroup as String] = accessGroup }
        SecItemDelete(deleteQuery as CFDictionary)

        var addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: tag,
            kSecValueData as String: data,
            kSecAttrAccessControl as String: accessControl,
        ]
        if let accessGroup { addQuery[kSecAttrAccessGroup as String] = accessGroup }
        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw SecureEnclaveKeystoreError.keychainError(status)
        }
    }

    private func deleteDataRepresentation(forTag tag: String) throws {
        lock.lock(); defer { lock.unlock() }
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: tag,
        ]
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SecureEnclaveKeystoreError.keychainError(status)
        }
    }
}
#endif

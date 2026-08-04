// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

#if canImport(DeviceCheck)
import DeviceCheck
import Foundation
import CryptoKit

/// The subset of `DCAppAttestService`'s API `AppAttestProvider` uses,
/// extracted as a protocol so tests can inject a fake instead of the real
/// service - `DCAppAttestService` itself requires a real device + valid
/// entitlement and can't be exercised in CI/Simulator (`isSupported` is
/// `false` there), so this is the only way to unit-test the key-exists/
/// key-doesn't-exist branching logic in `generateEvidence` at all.
public protocol AppAttestServiceProviding: Sendable {
    var isSupported: Bool { get }
    func generateKey() async throws -> String
    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data
    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data
}

@available(iOS 14.0, macOS 12.0, *)
extension DCAppAttestService: AppAttestServiceProviding {}

/// Provides Apple App Attest attestation for wallet instance authentication.
///
/// This provider generates and validates App Attest keys, producing attestation
/// evidence that the backend can verify to issue platform-attested WIA JWTs.
///
/// Usage:
/// ```swift
/// let provider = AppAttestProvider()
/// let keyId = try await provider.generateKey()
/// let attestation = try await provider.attest(keyId: keyId, challenge: challengeData)
/// ```
@available(iOS 14.0, macOS 12.0, *)
public final class AppAttestProvider: NativeAttestationProvider, @unchecked Sendable {

    /// Errors specific to App Attest operations.
    public enum AppAttestError: Error, Sendable {
        case notSupported
        case keyGenerationFailed(Error)
        case attestationFailed(Error)
        case assertionFailed(Error)
        /// An App Attest key already exists for this install. Re-attesting
        /// an existing key isn't meaningful (App Attest keys are generated
        /// exactly once per install and reused forever after) and isn't
        /// backend-verifiable today anyway (only the initial attestation
        /// object is verified server-side, not repeat assertions) - callers
        /// of `generateEvidence` treat this like any other best-effort
        /// failure and omit `native_attestation`.
        case alreadyAttested
    }

    private let service: AppAttestServiceProviding
    /// Loads this install's persisted App Attest key ID, if one was already
    /// generated - injected so `SirosWallet` can back it with
    /// `SessionStoreProtocol.appAttestKeyId` (Keychain-backed) without this
    /// type needing to know about session storage.
    private let loadPersistedKeyId: @Sendable () -> String?
    /// Persists a newly-generated App Attest key ID for reuse on every
    /// subsequent call, for the same reason.
    private let savePersistedKeyId: @Sendable (String) -> Void

    public init(
        loadPersistedKeyId: @escaping @Sendable () -> String? = { nil },
        savePersistedKeyId: @escaping @Sendable (String) -> Void = { _ in }
    ) {
        self.service = DCAppAttestService.shared
        self.loadPersistedKeyId = loadPersistedKeyId
        self.savePersistedKeyId = savePersistedKeyId
    }

    /// Test-only constructor: injects a fake `AppAttestServiceProviding` in
    /// place of the real `DCAppAttestService.shared`.
    init(
        service: AppAttestServiceProviding,
        loadPersistedKeyId: @escaping @Sendable () -> String? = { nil },
        savePersistedKeyId: @escaping @Sendable (String) -> Void = { _ in }
    ) {
        self.service = service
        self.loadPersistedKeyId = loadPersistedKeyId
        self.savePersistedKeyId = savePersistedKeyId
    }

    /// Whether App Attest is supported on this device.
    public var isSupported: Bool {
        service.isSupported
    }

    /// `NativeAttestationProvider` conformance - `isSupported` remains the
    /// primary, documented API; this just satisfies the shared contract.
    public var isAvailable: Bool { isSupported }

    /// Generate a new App Attest key.
    /// - Returns: The key identifier (used for attestation and assertions).
    public func generateKey() async throws -> String {
        guard isSupported else { throw AppAttestError.notSupported }
        do {
            return try await service.generateKey()
        } catch {
            throw AppAttestError.keyGenerationFailed(error)
        }
    }

    /// Generate an attestation for a key, binding it to a server challenge.
    ///
    /// The attestation statement proves this key was generated on a genuine
    /// Apple device running an unmodified app. The backend verifies this against
    /// Apple's App Attest root CA.
    ///
    /// - Parameters:
    ///   - keyId: The App Attest key ID from `generateKey()`.
    ///   - challenge: The challenge nonce from the backend's `/wia/challenge` endpoint.
    /// - Returns: Raw attestation object (caller must Base64-encode for transport).
    public func attest(keyId: String, challenge: Data) async throws -> Data {
        guard isSupported else { throw AppAttestError.notSupported }

        // App Attest requires clientDataHash = SHA256(challenge)
        let clientDataHash = Data(SHA256.hash(data: challenge))

        do {
            return try await service.attestKey(keyId, clientDataHash: clientDataHash)
        } catch {
            throw AppAttestError.attestationFailed(error)
        }
    }

    /// Generate an assertion for a previously-attested key.
    ///
    /// Assertions prove that a request comes from the same genuine device
    /// that originally attested the key. Use for ongoing WIA refresh.
    ///
    /// - Parameters:
    ///   - keyId: The App Attest key ID (must have been attested first).
    ///   - challenge: The challenge nonce to sign.
    /// - Returns: Raw assertion data (caller must Base64-encode for transport).
    public func assert(keyId: String, challenge: Data) async throws -> Data {
        guard isSupported else { throw AppAttestError.notSupported }

        let clientDataHash = Data(SHA256.hash(data: challenge))

        do {
            return try await service.generateAssertion(keyId, clientDataHash: clientDataHash)
        } catch {
            throw AppAttestError.assertionFailed(error)
        }
    }

    /// Generate native attestation evidence for a WIA challenge.
    ///
    /// App Attest keys are generated exactly once per install: if
    /// `loadPersistedKeyId()` already has one, this throws
    /// `AppAttestError.alreadyAttested` rather than re-attesting (see that
    /// case's doc comment) - callers should treat this exactly like any
    /// other best-effort attestation failure and omit `native_attestation`.
    /// Only a fresh install (no persisted key yet) produces real evidence.
    ///
    /// - Parameters:
    ///   - challenge: The challenge nonce from `/wia/challenge`.
    ///   - keyId: The WSCD instance key ID (the shared contract's
    ///     correlation value) - NOT the App Attest key ID, which is purely
    ///     this provider's own internal persisted state.
    public func generateEvidence(challenge: String, keyId: String) async throws -> NativeAttestationEvidence {
        guard loadPersistedKeyId() == nil else {
            throw AppAttestError.alreadyAttested
        }
        let appAttestKeyId = try await generateKey()
        // Persist only AFTER attest() succeeds (real Copilot-review finding:
        // persisting first meant a transient attest() failure - network
        // error, app killed mid-call, etc. - would leave the unattested key
        // ID persisted forever, permanently throwing alreadyAttested on
        // every later call and bricking native attestation for this install
        // until reinstall). Generating a throwaway key that never gets
        // attested is harmless and cheap; a permanently stuck install is not.
        let attestationObject = try await attest(keyId: appAttestKeyId, challenge: Data(challenge.utf8))
        savePersistedKeyId(appAttestKeyId)
        return NativeAttestationEvidence(
            type: "apple_app_attest",
            token: attestationObject.base64EncodedString(),
            keyId: keyId,
            challenge: challenge
        )
    }
}
#endif

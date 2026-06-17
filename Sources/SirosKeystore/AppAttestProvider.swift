// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

#if canImport(DeviceCheck)
import DeviceCheck
import Foundation
import CryptoKit

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
public final class AppAttestProvider: @unchecked Sendable {

    /// Errors specific to App Attest operations.
    public enum AppAttestError: Error, Sendable {
        case notSupported
        case keyGenerationFailed(Error)
        case attestationFailed(Error)
        case assertionFailed(Error)
    }

    private let service: DCAppAttestService

    public init() {
        self.service = DCAppAttestService.shared
    }

    /// Whether App Attest is supported on this device.
    public var isSupported: Bool {
        service.isSupported
    }

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
}
#endif

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Platform attestation evidence to include in WIA generation requests.
///
/// Send this to the backend's `/wallet-provider/wia/generate` endpoint
/// in the `native_attestation` field alongside the WIA-PoP.
public struct NativeAttestationEvidence: Sendable, Codable {
    /// The attestation type: "apple_app_attest" or "google_play_integrity"
    public let type: String
    /// Base64-encoded attestation token
    public let token: String
    /// The key identifier bound to this attestation
    public let keyId: String
    /// The challenge nonce that was attested
    public let challenge: String

    public init(type: String, token: String, keyId: String, challenge: String) {
        self.type = type
        self.token = token
        self.keyId = keyId
        self.challenge = challenge
    }
}

/// Protocol for platform-specific attestation providers.
///
/// Implementations provide attestation evidence from the native platform
/// (App Attest on iOS, Play Integrity on Android) that the backend uses
/// to issue platform-attested WIA JWTs.
public protocol NativeAttestationProvider: Sendable {
    /// Whether native attestation is available on this device/platform.
    var isAvailable: Bool { get }

    /// Generate attestation evidence for a WIA challenge.
    ///
    /// - Parameters:
    ///   - challenge: The challenge nonce from `/wia/challenge`.
    ///   - keyId: The instance key ID to bind to the attestation.
    /// - Returns: Attestation evidence to include in the WIA generate request.
    func generateEvidence(challenge: String, keyId: String) async throws -> NativeAttestationEvidence
}

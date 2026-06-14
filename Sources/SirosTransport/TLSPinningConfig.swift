// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Configuration for TLS certificate pinning.
///
/// Use this to pin specific certificates or public keys when communicating
/// with the SIROS backend, reducing the risk of man-in-the-middle attacks.
///
/// Usage:
/// ```swift
/// let pins = TLSPinningConfig(
///     pins: [
///         .sha256("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
///     ],
///     includeDefaultTrustAnchors: true
/// )
/// ```
public struct TLSPinningConfig: Sendable {
    /// The set of pinned public key hashes (SPKI SHA-256, base64-encoded).
    public let pins: [Pin]

    /// Whether to also trust the system's default certificate trust store.
    /// Set to `false` for strict pinning (only pinned certificates accepted).
    public let includeDefaultTrustAnchors: Bool

    public init(pins: [Pin], includeDefaultTrustAnchors: Bool = true) {
        self.pins = pins
        self.includeDefaultTrustAnchors = includeDefaultTrustAnchors
    }

    /// A pinned public key hash.
    public struct Pin: Sendable, Equatable {
        /// The hash algorithm used.
        public let algorithm: Algorithm
        /// The base64-encoded hash value.
        public let hash: String

        /// Create a SHA-256 pin from a base64-encoded SPKI hash.
        public static func sha256(_ hash: String) -> Pin {
            Pin(algorithm: .sha256, hash: hash)
        }

        public enum Algorithm: String, Sendable {
            case sha256 = "sha256"
        }
    }
}

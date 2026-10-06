// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// How the SDK tells the orchestrator it can handle EC TS12 `transaction_data`.
///
/// The backend refuses `transaction_data` for any client that did not declare
/// support, so these are produced only when TS12 handling is effectively
/// enabled (flag on AND a consent handler registered) and are empty/nil
/// otherwise.
public enum TransactionDataDeclaration {
    /// `flow_start.features` entry for the legacy engine WebSocket.
    public static let engineFeature = "transaction_data.v1"

    /// Capability name in WMP `capabilities_offered` (OpenID4x profile 2.3).
    public static let wmpCapabilityName = "transaction_data"

    /// Hash algorithms the SDK can compute, in preference order.
    public static let supportedHashAlgs = ["sha-256", "sha-384", "sha-512"]

    /// `flow_start.features` to send, or `nil` to send none.
    public static func engineFeatures(enabled: Bool) -> [String]? {
        enabled ? [engineFeature] : nil
    }

    /// WMP `capabilities_offered` to send, or `nil` to offer nothing.
    public static func wmpCapabilitiesOffered(enabled: Bool) -> [String: AnyCodable]? {
        guard enabled else { return nil }
        return [wmpCapabilityName: .object_([
            "versions": .array([.int(1)]),
            "hash_algs": .array(supportedHashAlgs.map { .string($0) }),
        ])]
    }
}

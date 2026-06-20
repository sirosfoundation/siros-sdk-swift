// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Base error type for the SIROS SDK.
///
/// Each case exposes a machine-readable ``errorCode`` that consuming
/// applications can use to look up localized user-facing messages:
///
/// ```swift
/// let key = "error_\(error.errorCode)"
/// let localized = NSLocalizedString(key, comment: "")
/// ```
public enum SirosError: Error, Sendable {
    case network(message: String, underlying: Error? = nil)
    case auth(message: String, underlying: Error? = nil)
    case keystore(message: String, underlying: Error? = nil)
    case wallet(message: String, underlying: Error? = nil)
    case backendApi(code: Int, message: String, body: String? = nil)

    /// Machine-readable error code for i18n mapping.
    public var errorCode: String {
        switch self {
        case .network: return "network_error"
        case .auth: return "auth_failed"
        case .keystore: return "keystore_error"
        case .wallet: return "wallet_error"
        case .backendApi(let code, _, _): return "backend_api_\(code)"
        }
    }
}

extension SirosError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .network(let message, _): return message
        case .auth(let message, _): return message
        case .keystore(let message, _): return message
        case .wallet(let message, _): return message
        case .backendApi(let code, let message, _): return "\(code): \(message)"
        }
    }
}

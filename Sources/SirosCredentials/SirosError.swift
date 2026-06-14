// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Base error type for the SIROS SDK.
public enum SirosError: Error, Sendable {
    case network(message: String, underlying: Error? = nil)
    case auth(message: String, underlying: Error? = nil)
    case keystore(message: String, underlying: Error? = nil)
    case wallet(message: String, underlying: Error? = nil)
    case backendApi(code: Int, message: String, body: String? = nil)
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

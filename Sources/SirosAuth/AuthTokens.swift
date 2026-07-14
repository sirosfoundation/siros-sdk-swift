// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials

// MARK: - Token Kind

/// Token kind definition — mirrors the MANIFEST in wallet-frontend's AuthTokens.ts.
public struct TokenKind: Sendable {
    public let name: String
    public let aud: String
    public let tac: String
    public let anonymous: Bool

    public init(name: String, aud: String, tac: String, anonymous: Bool = false) {
        self.name = name
        self.aud = aud
        self.tac = tac
        self.anonymous = anonymous
    }
}

// MARK: - AuthTokens

/// Token lifecycle manager for the new AS-based authentication.
///
/// Manages a set of scoped access tokens (defined by ``manifest``),
/// handles caching, and tracks token rejections (401 responses)
/// to trigger forced logout when the session is invalid.
///
/// Mirrors the TypeScript `AuthTokens` from wallet-frontend PR 177.
///
/// Usage:
/// ```swift
/// let authTokens = AuthTokens(authServerClient: client, tenantId: "default")
/// let backendToken = try await authTokens.ensureBackendToken()
/// let anonToken = try await authTokens.ensureAnonymousToken()
/// ```
public final class AuthTokens: @unchecked Sendable {

    /// Callback invoked when repeated token rejections indicate the session
    /// is no longer valid. The host app should trigger a logout flow.
    public var onSessionRejected: (() -> Void)?

    private let authServerClient: AuthServerClient
    private let tenantId: String
    private let lock = NSLock()
    private var tokens: [String: AccessToken] = [:]
    private var rejections: [String: [Date]] = [:]

    public static let tokenBackend = "backend"
    public static let tokenAnonymous = "anonymous"

    private static let rejectionThreshold = 3
    private static let rejectionWindowSeconds: TimeInterval = 60

    /// Token manifest — defines which tokens the SDK manages.
    public static let manifest: [String: TokenKind] = [
        tokenBackend: TokenKind(
            name: tokenBackend,
            aud: "wallet-backend",
            tac: "rwlid",
            anonymous: false
        ),
        tokenAnonymous: TokenKind(
            name: tokenAnonymous,
            aud: "wallet-backend",
            tac: "rl",
            anonymous: true
        ),
    ]

    public init(authServerClient: AuthServerClient, tenantId: String = "default") {
        self.authServerClient = authServerClient
        self.tenantId = tenantId
    }

    /// Ensure a valid token of the given kind is available.
    /// Returns a cached token if still valid, otherwise requests a new one.
    public func ensureToken(_ name: String) async throws -> AccessToken {
        lock.lock()
        if let cached = tokens[name], !cached.isExpired() {
            lock.unlock()
            return cached
        }
        tokens.removeValue(forKey: name)
        lock.unlock()

        guard let kind = Self.manifest[name] else {
            throw SirosError.auth(message: "Unknown token kind: \(name)")
        }

        let token: AccessToken
        if kind.anonymous {
            token = try await authServerClient.requestAnonymousToken(aud: kind.aud, tac: kind.tac)
        } else {
            token = try await authServerClient.requestAccessToken(aud: kind.aud, tac: kind.tac)
        }

        lock.lock()
        tokens[name] = token
        lock.unlock()

        return token
    }

    /// Convenience: ensure a backend token (authenticated, full CRUD).
    public func ensureBackendToken() async throws -> AccessToken {
        try await ensureToken(Self.tokenBackend)
    }

    /// Convenience: ensure an anonymous token (read-only, no auth required).
    public func ensureAnonymousToken() async throws -> AccessToken {
        try await ensureToken(Self.tokenAnonymous)
    }

    /// Force-refresh a token by clearing the cache and re-requesting.
    public func forceRefreshToken(_ name: String) async throws -> AccessToken {
        lock.lock()
        tokens.removeValue(forKey: name)
        lock.unlock()

        guard let kind = Self.manifest[name] else {
            throw SirosError.auth(message: "Unknown token kind: \(name)")
        }

        let token: AccessToken
        if kind.anonymous {
            token = try await authServerClient.requestAnonymousToken(aud: kind.aud, tac: kind.tac)
        } else {
            token = try await authServerClient.requestAccessToken(aud: kind.aud, tac: kind.tac)
        }

        lock.lock()
        tokens[name] = token
        lock.unlock()

        return token
    }

    /// Register a token rejection (e.g. from a 401 response).
    /// After `rejectionThreshold` rejections within `rejectionWindowSeconds`,
    /// invokes `onSessionRejected`.
    public func registerTokenRejection(_ name: String) {
        lock.lock()
        let now = Date()

        // Clear the rejected token from cache so it won't be re-served
        tokens.removeValue(forKey: name)

        var list = rejections[name, default: []]
        list.append(now)

        // Prune old rejections outside the window
        let cutoff = now.addingTimeInterval(-Self.rejectionWindowSeconds)
        list.removeAll { $0 < cutoff }
        rejections[name] = list

        let count = list.count
        lock.unlock()

        if count >= Self.rejectionThreshold {
            onSessionRejected?()
        }
    }

    /// Clear all cached tokens.
    public func clear() {
        lock.lock()
        tokens.removeAll()
        rejections.removeAll()
        lock.unlock()
    }
}

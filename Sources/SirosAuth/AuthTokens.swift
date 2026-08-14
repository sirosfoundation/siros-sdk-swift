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

    // Internal (not private) so `@testable import` can verify
    // `registerTokenRejection`'s rejection-window pruning without a real
    // test waiting out the real `rejectionWindowSeconds` - matching this
    // SDK's existing injectable-for-testing precedent (e.g.
    // `SirosWallet.createEngineSession`). Defaults to the real wall clock.
    var now: () -> Date = Date.init

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
            aud: "wallet-registry",
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
        do {
            if kind.anonymous {
                token = try await authServerClient.requestAnonymousToken(aud: kind.aud, tac: kind.tac)
            } else {
                token = try await authServerClient.requestAccessToken(aud: kind.aud, tac: kind.tac)
            }
        } catch {
            handleAsTokenFailure(error)
            throw error
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

    /// Convenience: ensure an anonymous token (issued without a `sub` claim;
    /// still requires a real, already-authenticated session server-side).
    /// Scoped to `tac ⊆ "rl"` (read/list only), enforced server-side -
    /// intended for registry-style read calls, NOT for anything that needs
    /// to write (e.g. the engine WebSocket session, which needs `insert`
    /// for OID4VCI issuance - use `ensureBackendToken()` there instead).
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
        do {
            if kind.anonymous {
                token = try await authServerClient.requestAnonymousToken(aud: kind.aud, tac: kind.tac)
            } else {
                token = try await authServerClient.requestAccessToken(aud: kind.aud, tac: kind.tac)
            }
        } catch {
            handleAsTokenFailure(error)
            throw error
        }

        lock.lock()
        tokens[name] = token
        lock.unlock()

        return token
    }

    /// A 401 straight from the AS's own `/auth/token` endpoint (i.e. minting a
    /// *new* token failed, not just a previously-issued one being rejected
    /// later by a backend API call) means the AS itself has already declared
    /// the session dead - unlike `registerTokenRejection`'s REST-401 case,
    /// there's no ambiguity to wait out via `rejectionThreshold`/
    /// `rejectionWindowSeconds`, so this fires `onSessionRejected` immediately.
    ///
    /// Without this, a call like "add credential" made with an AS session
    /// that's expired (but whose locally-cached access token hadn't yet hit
    /// its own claimed expiry, or had none cached at all) would throw a raw
    /// error straight out of `ensureToken`/`forceRefreshToken` with no
    /// logout/re-login ever triggered - confirmed via a live "AS request
    /// failed 401 - /auth/token" report with no reauth flow firing.
    private func handleAsTokenFailure(_ error: Error) {
        if case .backendApi(let code, _, _)? = error as? SirosError, code == 401 {
            onSessionRejected?()
        }
    }

    /// Register a token rejection (e.g. from a 401 response).
    /// After `rejectionThreshold` rejections within `rejectionWindowSeconds`,
    /// invokes `onSessionRejected`.
    public func registerTokenRejection(_ name: String) {
        lock.lock()
        let now = self.now()

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

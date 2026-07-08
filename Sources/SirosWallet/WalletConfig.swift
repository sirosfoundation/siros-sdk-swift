// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosCredentials

/// Configuration for ``SirosWallet``.
public struct WalletConfig: Sendable {
    /// The wallet backend URL (e.g. "https://wallet.sirosid.dev").
    public var backendUrl: String

    /// Tenant identifier. Defaults to "default".
    public var tenantId: String

    /// WebSocket engine URL. When empty, the SDK auto-discovers it from
    /// `/.well-known/wallet-configuration` or falls back to `backendUrl`.
    public var engineUrl: String

    /// OAuth redirect URI for authorization code flows.
    public var redirectUri: String

    /// Custom ``CredentialStore`` implementation. When `nil`, uses
    /// a keystore-backed encrypted store.
    public var credentialStore: (any CredentialStore)?

    /// Optional function to rewrite URLs before they are opened in the browser.
    public var urlRewriter: (@Sendable (String) -> String)?

    /// When true, biometric/device authentication is required for passkey operations.
    public var requireUserAuth: Bool

    /// Use the WMP (Wallet Messaging Protocol) JSON-RPC 2.0 transport instead
    /// of the legacy engine protocol. Requires go-wallet-backend with WMP support.
    public var useWmpProtocol: Bool

    public init(
        backendUrl: String,
        tenantId: String = "default",
        engineUrl: String = "",
        redirectUri: String = "",
        credentialStore: (any CredentialStore)? = nil,
        urlRewriter: (@Sendable (String) -> String)? = nil,
        requireUserAuth: Bool = true,
        useWmpProtocol: Bool = false
    ) {
        self.backendUrl = backendUrl
        self.tenantId = tenantId
        self.engineUrl = engineUrl
        self.redirectUri = redirectUri
        self.credentialStore = credentialStore
        self.urlRewriter = urlRewriter
        self.requireUserAuth = requireUserAuth
        self.useWmpProtocol = useWmpProtocol
    }

    /// Discover the engine WebSocket URL from the backend's
    /// `/.well-known/wallet-configuration` endpoint.
    ///
    /// Returns `nil` if discovery fails — the caller should fall back
    /// to `backendUrl` (single-port deployment).
    public static func discoverEngineUrl(backendUrl: String) async -> String? {
        let urlString = backendUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            + "/.well-known/wallet-configuration"
        guard let url = URL(string: urlString) else { return nil }
        return await withCheckedContinuation { continuation in
            let task = URLSession.shared.dataTask(with: url) { data, response, error in
                guard error == nil,
                      let httpResponse = response as? HTTPURLResponse,
                      httpResponse.statusCode == 200,
                      let data = data,
                      let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                      let engine = json["engine_url"] as? String,
                      !engine.isEmpty else {
                    continuation.resume(returning: nil)
                    return
                }
                continuation.resume(returning: engine)
            }
            task.resume()
        }
    }
}

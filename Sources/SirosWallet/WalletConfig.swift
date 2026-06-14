// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials

/// Configuration for ``SirosWallet``.
public struct WalletConfig: Sendable {
    /// The wallet backend URL (e.g. "https://wallet.sirosid.dev").
    public var backendUrl: String

    /// Tenant identifier. Defaults to "default".
    public var tenantId: String

    /// OAuth redirect URI for authorization code flows.
    public var redirectUri: String

    /// Custom ``CredentialStore`` implementation. When `nil`, uses
    /// a keystore-backed encrypted store.
    public var credentialStore: (any CredentialStore)?

    /// Optional function to rewrite URLs before they are opened in the browser.
    public var urlRewriter: (@Sendable (String) -> String)?

    /// When true, biometric/device authentication is required for passkey operations.
    public var requireUserAuth: Bool

    public init(
        backendUrl: String,
        tenantId: String = "default",
        redirectUri: String = "",
        credentialStore: (any CredentialStore)? = nil,
        urlRewriter: (@Sendable (String) -> String)? = nil,
        requireUserAuth: Bool = true
    ) {
        self.backendUrl = backendUrl
        self.tenantId = tenantId
        self.redirectUri = redirectUri
        self.credentialStore = credentialStore
        self.urlRewriter = urlRewriter
        self.requireUserAuth = requireUserAuth
    }
}

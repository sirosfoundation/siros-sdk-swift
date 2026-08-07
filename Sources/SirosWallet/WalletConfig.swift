// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosCredentials
import SirosKeystore

/// Configuration for ``SirosWallet``.
public struct WalletConfig: Sendable {
    /// The wallet backend URL (e.g. "https://wallet.sirosid.dev").
    public var backendUrl: String

    /// Tenant identifier. Defaults to "default".
    public var tenantId: String

    /// Engine base URL (e.g. "https://engine.sirosid.dev"). The SDK appends
    /// the WebSocket path (`/api/v2/wallet?...`) automatically. When empty,
    /// the SDK auto-discovers it from `/.well-known/wallet-configuration`
    /// or falls back to `backendUrl`.
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

    /// Every WSCD plugin the host app has a ready `KeystoreManager` instance
    /// for, keyed by plugin ID (`"softkey"` / `"r2ps"` / `"fido2"` today -
    /// see `WscdPluginCapabilities`), each with its own platform transport
    /// (BLE/USB/CoreNFC/etc) already wired up - only the host app can
    /// construct these, since that transport wiring is deliberately kept out
    /// of the SDK. `nil` (the default) is fully backward compatible: none of
    /// `WscdSelectionPolicy`'s selection logic engages, and credential-
    /// issuance key generation behaves exactly as it does today, always
    /// using the wallet's single `keystore`. An explicitly *empty*
    /// dictionary is NOT the same as `nil` - it means the host app opted
    /// into multi-plugin selection but has zero plugins registered right
    /// now, so a credential type that declares a key-storage requirement
    /// still gets `WscdSelectionError.noEligiblePlugin` rather than a
    /// silent fallback to the default keystore. Only set this to opt into
    /// multi-plugin selection.
    public var availableKeystores: [String: KeystoreManager]?

    /// Host-app-supplied default `(issuer, credentialType) -> pluginId`
    /// mapping (key: `"\(issuer)|\(credentialType)"`), consulted by
    /// `WscdSelectionPolicy` before falling back to auto-pick/user-prompt -
    /// lets an integrator that already knows the right answer skip the
    /// prompt entirely. Only consulted when `availableKeystores` is set.
    public var defaultWscdMapping: [String: String]?

    /// Asks the host app to pick a WSCD plugin when more than one
    /// registered plugin meets a credential type's declared key-storage
    /// requirement and neither TOFU nor `defaultWscdMapping` resolves it -
    /// see `RequestWscdChoice`'s doc comment. Only consulted when
    /// `availableKeystores` is set.
    public var requestWscdChoice: RequestWscdChoice?

    /// Base URL for go-wallet-backend's credential-type registry service
    /// (TS11-backed, cached, includes `attestation_los`/required-key-storage-
    /// tier data) - queried as `<registryUrl>/type-metadata?vct=<id>` for
    /// both SD-JWT `vct` values and ISO 18013-5 mdoc `doctype` values (one
    /// handler/store serves both formats under the same generic query param
    /// name). This is the SAME service the reference wallet-frontend
    /// implementation always calls for VCT/mdoc type-metadata lookups
    /// (`VCT_REGISTRY_URL`), never the issuer directly.
    ///
    /// `nil` (the common case) derives this automatically as
    /// `<backendUrl>/registry` - the registry route is mounted under a
    /// `/registry` path prefix on the same host/port as the rest of
    /// go-wallet-backend's public API. Set this explicitly only to point at
    /// a registry deployment independent of `backendUrl` (e.g. a different
    /// environment's registry, or a standalone registry service), matching
    /// `VCT_REGISTRY_URL` being a distinct, independently-settable config
    /// value in wallet-frontend.
    public var registryUrl: String?

    public init(
        backendUrl: String,
        tenantId: String = "default",
        engineUrl: String = "",
        redirectUri: String = "",
        credentialStore: (any CredentialStore)? = nil,
        urlRewriter: (@Sendable (String) -> String)? = nil,
        requireUserAuth: Bool = true,
        useWmpProtocol: Bool = false,
        availableKeystores: [String: KeystoreManager]? = nil,
        defaultWscdMapping: [String: String]? = nil,
        requestWscdChoice: RequestWscdChoice? = nil,
        registryUrl: String? = nil
    ) {
        self.backendUrl = backendUrl
        self.tenantId = tenantId
        self.engineUrl = engineUrl
        self.redirectUri = redirectUri
        self.credentialStore = credentialStore
        self.urlRewriter = urlRewriter
        self.requireUserAuth = requireUserAuth
        self.useWmpProtocol = useWmpProtocol
        self.availableKeystores = availableKeystores
        self.defaultWscdMapping = defaultWscdMapping
        self.requestWscdChoice = requestWscdChoice
        self.registryUrl = registryUrl
    }

    /// Discover the engine base URL from the backend's
    /// `/.well-known/wallet-configuration` endpoint.
    ///
    /// Returns `nil` if discovery fails — the caller should fall back
    /// to `backendUrl` (single-port deployment).
    public static func discoverEngineUrl(backendUrl: String) async -> String? {
        let urlString = backendUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            + "/.well-known/wallet-configuration"
        guard let url = URL(string: urlString) else { return nil }
        do {
            let (data, response) = try await URLSession.shared.data(from: url)
            guard let httpResponse = response as? HTTPURLResponse,
                  httpResponse.statusCode == 200,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let engine = json["engine_url"] as? String,
                  !engine.isEmpty else {
                return nil
            }
            return engine
        } catch {
            return nil
        }
    }
}

/// See `SirosWallet.capabilities`.
public struct WalletCapabilities: Sendable {
    public let nativeAttestation: Bool
    public let wscd: Bool
}

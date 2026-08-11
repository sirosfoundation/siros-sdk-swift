// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosCredentials
import SirosTransport
import SirosAuth
import SirosKeystore
import SirosFlow
#if canImport(os)
import os
#endif

#if canImport(os)
private let logger = Logger(subsystem: "org.siros.sdk", category: "SirosWallet")
#endif

/// Authorization context captured at `authorization_required` time, needed to
/// resume an OID4VCI issuance flow via a fresh `flow_start` once the OAuth
/// browser redirect returns. See `SirosWallet.completeAuthorization`.
private struct PendingAuthorization: Sendable {
    let offer: String?
    let credentialOfferUri: String?
    let redirectUri: String?
    let codeVerifier: String?
    let state: String
}

/// Main entry point for the SIROS Wallet SDK (cross-platform).
///
/// Provides a single, self-contained API for wallet apps:
///
/// ```swift
/// let wallet = SirosWallet(
///     config: WalletConfig(backendUrl: "https://wallet.sirosid.dev"),
///     authProvider: myAuthProvider,
///     sessionStore: mySessionStore
/// )
/// try await wallet.login()
/// for await state in wallet.stateStream { /* drive UI */ }
/// ```
///
/// The SDK handles WebAuthn authentication with PRF extension, HKDF key
/// derivation, JWE keystore unlock, encrypted private-data sync with the
/// backend, and the engine WebSocket session for issuance/presentation flows.
public final class SirosWallet: @unchecked Sendable {

    // MARK: - Public state

    let lock = NSLock()
    private var _state: WalletState = .disconnected()
    private var stateContinuations: [String: AsyncStream<WalletState>.Continuation] = [:]

    /// Current wallet state (thread-safe read).
    public var state: WalletState {
        lock.lock(); defer { lock.unlock() }
        return _state
    }

    /// AsyncStream of state changes.
    public func stateStream() -> AsyncStream<WalletState> {
        let id = UUID().uuidString
        return AsyncStream<WalletState> { [weak self] continuation in
            guard let self else { return }
            self.lock.lock()
            self.stateContinuations[id] = continuation
            let current = self._state
            self.lock.unlock()
            continuation.yield(current)
            continuation.onTermination = { [weak self] _ in
                self?.lock.lock()
                self?.stateContinuations.removeValue(forKey: id)
                self?.lock.unlock()
            }
        }
    }

    /// All known accounts across all tenants. Survives logout.
    public func listAccounts() -> [CachedAccount] { accountRegistry.listAccounts() }

    /// Accounts that have passkeys and can log in.
    public func listLoginableAccounts() -> [CachedAccount] { accountRegistry.listLoginableAccounts() }

    /// Get a valid access token for authenticated API calls (e.g., IDV backend).
    /// Returns the raw JWT string. Throws if no session is active.
    public func getAccessToken() async throws -> String {
        lock.lock()
        let tokens = authTokens
        lock.unlock()
        guard let tokens else { throw SirosError.auth(message: "No active session") }
        let token = try await tokens.ensureBackendToken()
        return token.raw
    }

    /// Remove a cached account (forgets it from the login screen).
    public func forgetAccount(accountId: String) {
        accountRegistry.removeAccount(accountId: accountId)
        if accountRegistry.activeAccountId == accountId {
            logout()
        } else {
            // Re-emit state so UI reflects the removed account
            setState(.disconnected(cachedAccounts: accountRegistry.listLoginableAccounts()))
        }
    }

    // MARK: - Passkey Management

    /// Passkeys registered for the active account.
    public func listPasskeys() -> [CachedPasskey] {
        guard let active = accountRegistry.activeAccountId else { return [] }
        return accountRegistry.findAccount(accountId: active)?.passkeys ?? []
    }

    /// Rename a passkey (local AccountRegistry only).
    public func renamePasskey(credentialId: String, nickname: String) {
        guard let active = accountRegistry.activeAccountId,
              var account = accountRegistry.findAccount(accountId: active) else { return }
        account.passkeys = account.passkeys.map {
            $0.credentialId == credentialId ? CachedPasskey(credentialId: $0.credentialId, prfSalt: $0.prfSalt, nickname: nickname) : $0
        }
        accountRegistry.upsertAccount(account)
    }

    // MARK: - Configuration & dependencies

    private let config: WalletConfig
    private let authProvider: AuthProvider
    private let sessionStore: SessionStoreProtocol
    private let keystore: KeystoreManager

    /// WSCD hardware-key lifecycle (enroll/rotate/destroy) and
    /// additional-plugin registration (FIDO2 rawSign, R2PS remote HSM) -
    /// `nil` unless `keystore` is WSCD-backed (see `WscdKeystoreAdapter`).
    /// The default JWE-encrypted keystore has no such concept.
    public var wscdManager: WscdManager? { keystore as? WscdManager }

    /// Static feature availability - lets a consumer gate its own UI
    /// without probing by side effect (e.g. attempting a WSCD plugin
    /// registration and catching the resulting error). Reflects what's
    /// *configured*/available on this platform, not runtime
    /// plugin-registration state the app already controls itself (e.g.
    /// whether FIDO2 specifically has been registered on `wscdManager`).
    public var capabilities: WalletCapabilities {
        #if canImport(DeviceCheck)
        let nativeAttestation = AppAttestProvider().isAvailable
        #else
        let nativeAttestation = false
        #endif
        return WalletCapabilities(nativeAttestation: nativeAttestation, wscd: wscdManager != nil)
    }

    /// Read-only snapshot of the persisted WSCD TOFU mapping
    /// (`"issuer|credentialType" -> pluginId`) - lets a host app render/
    /// manage it in its own UI (e.g. a settings screen). See
    /// `WscdSelectionPolicy.currentTofuMapping`'s doc comment. Always empty
    /// when `config.availableKeystores` was never set, since
    /// `WscdSelectionPolicy.resolve` never runs (and so never persists
    /// anything) in that case.
    public var wscdTofuMapping: [String: String] { wscdSelectionPolicy.currentTofuMapping() }

    /// Clears one persisted WSCD TOFU entry - `key` must be exactly one of
    /// `wscdTofuMapping`'s keys. The corresponding (issuer, credentialType)
    /// pair re-resolves (auto-pick/prompt) on its next matching credential
    /// issuance instead of reusing the old choice.
    public func clearWscdTofuMapping(forKey key: String) {
        wscdSelectionPolicy.clearTofuMapping(forKey: key)
    }

    /// Clears every persisted WSCD TOFU entry.
    public func clearAllWscdTofuMappings() {
        wscdSelectionPolicy.clearAllTofuMappings()
    }

    /// Read-only snapshot of every persisted per-(issuer, credentialType)
    /// user override (`"issuer|credentialType" -> pluginId`) - an explicit,
    /// deliberate user preference, distinct from `wscdTofuMapping` (see
    /// `WscdRememberScope`'s doc comment). Mirrors `wscdTofuMapping`'s
    /// pattern exactly.
    public var wscdUserOverrides: [String: String] { wscdSelectionPolicy.currentUserOverrides() }

    /// Sets (or overwrites) an explicit per-(issuer, credentialType) user
    /// preference - outranks TOFU and the global override for this exact
    /// pair on the next matching resolution (see `WscdSelectionPolicy.resolve`).
    public func setWscdUserOverride(issuer: String, credentialType: String, pluginId: String) {
        wscdSelectionPolicy.setUserOverride(issuer: issuer, credentialType: credentialType, pluginId: pluginId)
    }

    /// Clears one persisted per-issuer user override, if present.
    public func clearWscdUserOverride(issuer: String, credentialType: String) {
        wscdSelectionPolicy.clearUserOverride(issuer: issuer, credentialType: credentialType)
    }

    /// The currently persisted global user override (applies to every
    /// issuer/credential type without a more specific per-issuer override),
    /// if any.
    public var wscdGlobalOverride: String? { wscdSelectionPolicy.currentGlobalUserOverride() }

    /// Sets (or overwrites) the single global user override.
    public func setWscdGlobalOverride(pluginId: String) {
        wscdSelectionPolicy.setGlobalUserOverride(pluginId: pluginId)
    }

    /// Clears the global user override, if set.
    public func clearWscdGlobalOverride() {
        wscdSelectionPolicy.clearGlobalUserOverride()
    }

    let credentialStore: CredentialStore
    private let vctmFetcher: VctmFetcher
    let mddlSchemaFetcher: MddlSchemaFetcher
    private let accountRegistry: AccountRegistry

    /// go-wallet-backend's credential-type registry service base URL, for
    /// `vctmFetcher`/`mddlSchemaFetcher`'s registry-service fetch strategy.
    /// Uses `config.registryUrl` when the integrator set one explicitly,
    /// otherwise derives it from `config.backendUrl` - the registry route is
    /// mounted under a `/registry` path prefix on the same host/port as the
    /// rest of go-wallet-backend's public API. Not `private` so
    /// `SirosWallet+Notifications.swift` (a separate file, same module) can
    /// use it too, matching `mddlSchemaFetcher`'s own visibility above.
    var resolvedRegistryUrl: String {
        Self.resolveRegistryUrl(config: config)
    }

    // Internal (not private) so `@testable import` can seed a fake client
    // directly, matching this file's existing precedent for other testable
    // internals (e.g. `cachedWia`, `currentWalletInstanceId()`).
    var apiClient: BackendApiClient?
    var engineSession: WalletEngineSession?
    /// Transport-independent notifier for OID4VCI §10 events.
    var credentialNotifier: CredentialNotifier?
    weak var eventListener: WalletEventListener?
    var activeOffer: CredentialOffer?
    var activeVctm: Vctm?
    /// The mdoc analogue of `activeVctm` - the currently-in-flight
    /// issuance's `MddlSchema`, when the credential being issued is
    /// `mso_mdoc` rather than SD-JWT. Populated the same way `activeVctm`
    /// is: fetched (best-effort - `nil` on any failure, including a 404
    /// because the offer is actually SD-JWT and has no MDDL schema) via
    /// `mddlSchemaFetcher` at the same call sites `activeVctm` is.
    var activeMddlSchema: MddlSchema?
    /// Resolves which registered WSCD plugin should back credential-
    /// issuance key generation - a no-op unless `config.availableKeystores`
    /// is set. See `WscdSelectionPolicy`'s doc comment.
    private let wscdSelectionPolicy: WscdSelectionPolicy
    /// Per-instance device key IDs from the most recent backend Key
    /// Attestation (`attested_keys`, in submission order) - a batch issuer
    /// binds credential `i` in the eventual response to `attested_keys[i]`
    /// (per `requestBackendKeyAttestation`'s doc comment), so
    /// `StoredCredential.kid` for the credential at `StoredCredential.instanceId`
    /// `i` must be `activeAttestedKeyIds[i]` - without this, every signing
    /// operation had no way to know which of the N generated keys a given
    /// batch credential was actually bound to, and silently used an arbitrary
    /// one (see `WscdKeystoreAdapter.selectSigningKey`'s doc comment).
    var activeAttestedKeyIds: [String]?
    /// Ambient (not flow-ID-keyed) guard against overlapping issuance
    /// attempts - set at the top of `startIssuanceByOffer`/`startIssuance`
    /// and checked there too, throwing if already `true`. Not `private` for
    /// the same cross-file-extension-access reason as `activeOffer` etc.
    /// above; guarded by the same `lock`. See `resetIssuanceGuards()` for
    /// why every terminal path must clear it.
    var issuanceInFlight = false
    private var engineTasks: [Task<Void, Never>] = []
    private var _presentationHistory: [PresentationRecord] = []
    /// Stores trust evaluation results keyed by flow ID for use in credential selection UI.
    private var lastTrustResults: [String: TrustResult] = [:]
    /// Authorization context captured from a flow's `authorization_required`
    /// progress message, keyed by flow ID - needed to resume issuance via a
    /// fresh `flow_start` once the OAuth browser redirect returns, since the
    /// original flow_id's WebSocket context isn't guaranteed to survive the
    /// round-trip. See `completeAuthorization`.
    private var pendingAuthorizations: [String: PendingAuthorization] = [:]
    /// Persistent trust cache for degraded-mode operation.
    private let trustCache = TrustCache()

    // New AS-based auth
    private var authServerClient: AuthServerClient?
    private var authTokens: AuthTokens?

    /// Presentation history — most recent first.
    public var presentationHistory: [PresentationRecord] {
        lock.lock(); defer { lock.unlock() }
        return _presentationHistory
    }

    /// Filters `instances` down to the ones this wallet's own
    /// `credentialConsumptionPolicy` and `presentationHistory` currently
    /// consider eligible (i.e. not yet consumed) - the same computation
    /// this class performs internally before every presentation, exposed
    /// as a convenience so consent/selection UI doesn't need to thread
    /// both properties through `CredentialUtils.eligibleInstances` itself.
    public func eligibleInstances(from instances: [StoredCredential]) -> [StoredCredential] {
        CredentialUtils.eligibleInstances(
            instances: instances,
            policy: credentialConsumptionPolicy,
            presentationHistory: presentationHistory
        )
    }

    /// Record a new presentation: adds it to the in-memory history and
    /// persists it into the encrypted container (privatedata-spec's
    /// `S.presentations[]`) so `CredentialUtils.groupForDisplay`'s
    /// remaining-copies count survives an app restart instead of resetting
    /// to the full batch size every time - mirrors `deleteCredential`'s
    /// persist-after-mutation pattern.
    private func recordPresentation(_ record: PresentationRecord) async {
        lock.lock(); _presentationHistory.insert(record, at: 0); lock.unlock()
        if keystore.isUnlocked {
            if let data = try? JSONEncoder().encode(record), let raw = String(data: data, encoding: .utf8) {
                try? await keystore.savePresentationRecord(id: record.id, json: raw)
                await persistAndSyncKeystore()
            }
        }
    }

    /// Reload presentation history from the encrypted container after unlock.
    private func reloadPresentationHistory() async {
        guard let allRaw = try? await keystore.getAllPresentationRecords() else { return }
        let decoder = JSONDecoder()
        let records = allRaw.values.compactMap { raw in
            try? decoder.decode(PresentationRecord.self, from: Data(raw.utf8))
        }.sorted(by: { $0.timestamp > $1.timestamp })
        lock.lock()
        _presentationHistory = records
        lock.unlock()
    }

    /// Factory for creating engine sessions (injectable for testing).
    public static var createEngineSession: @Sendable (String, String) -> WalletEngineSession = { baseUrl, tenantId in
        WalletEngineSession(baseUrl: baseUrl, tenantId: tenantId)
    }

    static let hkdfInfo = "eDiplomas PRF"

    /// Default HTTP POST function using URLSession.
    private static let defaultHttpPost: @Sendable (URL, Data) async throws -> Data = { url, body in
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let (data, _) = try await URLSession.shared.data(for: request)
        return data
    }

    /// Default HTTP function for BackendApiClient.
    private static let defaultHttpFn: @Sendable (String, URL, [String: String], Data?) async throws -> Data = { method, url, headers, body in
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.httpBody = body
        for (k, v) in headers { request.setValue(v, forHTTPHeaderField: k) }
        let (data, _) = try await URLSession.shared.data(for: request)
        return data
    }

    // MARK: - Init

    /// Create a new wallet instance.
    ///
    /// - Parameters:
    ///   - config: backend URL, tenant ID, etc.
    ///   - authProvider: platform-specific WebAuthn/passkey implementation.
    ///   - sessionStore: persistent session storage. Defaults to in-memory.
    ///   - keystore: encrypted keystore. Defaults to JweKeystore on Apple platforms.
    ///     On Linux, you **must** provide a custom `KeystoreManager`.
    /// - Returns: `nil` if no keystore is available (Linux without custom keystore).
    public init?(
        config: WalletConfig,
        authProvider: AuthProvider,
        sessionStore: SessionStoreProtocol = InMemorySessionStore(),
        keystore: KeystoreManager? = nil
    ) {
        self.config = config
        self.authProvider = authProvider
        self.sessionStore = sessionStore

        #if canImport(CryptoKit)
        self.keystore = keystore ?? JweKeystore()
        #else
        guard let ks = keystore else {
            return nil
        }
        self.keystore = ks
        #endif

        self.credentialStore = config.credentialStore ?? KeystoreBackedCredentialStore(keystore: self.keystore)

        self.accountRegistry = AccountRegistry()

        self.wscdSelectionPolicy = WscdSelectionPolicy(
            sessionStore: sessionStore,
            defaultMapping: config.defaultWscdMapping,
            requestChoice: config.requestWscdChoice
        )

        // Set up new AS-based auth
        let asClient = AuthServerClient(baseUrl: config.backendUrl, tenantId: config.tenantId, httpFn: Self.defaultHttpFn)
        self.authServerClient = asClient
        let tokens = AuthTokens(authServerClient: asClient, tenantId: config.tenantId)
        self.authTokens = tokens

        // Shared HTTP GET for both type-metadata fetchers - see
        // `makeTypeMetadataHttpGet`'s doc comment for why the auth headers
        // are conditional on the target URL. Captures `config`, `tokens`,
        // and the `sessionStore` parameter directly (not `self`) - both
        // `resolvedRegistryUrl` and `authTokens` are invariant for this
        // wallet instance's whole lifetime (derived from/aliasing the `let
        // config` below and the local `tokens` just assigned to
        // `self.authTokens` above, never reassigned afterwards), so there's
        // no need to read them via `self` later. This also has to run
        // BEFORE `tokens.onSessionRejected` below: that closure captures
        // `self`, and Swift requires every stored property - including
        // `vctmFetcher`/`mddlSchemaFetcher`, assigned here - to already be
        // initialized before `self` can be captured anywhere in `init`.
        let typeMetadataGet = Self.makeTypeMetadataHttpGet(
            registryUrl: Self.resolveRegistryUrl(config: config),
            tenantId: config.tenantId,
            authTokens: tokens,
            sessionStore: sessionStore
        )
        self.vctmFetcher = VctmFetcher(httpGet: typeMetadataGet)
        self.mddlSchemaFetcher = MddlSchemaFetcher(httpGet: typeMetadataGet)

        tokens.onSessionRejected = { [weak self] in
            self?.handleReauthenticationRequired()
        }
    }

    /// Builds the HTTP GET closure shared by `vctmFetcher`/`mddlSchemaFetcher`.
    ///
    /// Both fetchers' registry-service strategy (Strategy 1: `<registryUrl
    /// >/type-metadata?vct=...`) hits go-wallet-backend's own registry
    /// service, which - like every other backend REST call
    /// (`BackendApiClient.request(_:path:body:)`) - may require an
    /// `Authorization: Bearer` token and always wants the tenant-routing
    /// `X-Tenant-ID` header. Their OTHER two strategies (issuer-direct
    /// `<issuerUrl>/type-metadata/<scope>` and the SD-JWT well-known
    /// `.well-known/vct/...`) hit arbitrary third-party issuer domains -
    /// attaching the wallet's own bearer token/tenant ID there would leak
    /// them to an external party. So headers are attached if and only if the
    /// URL being fetched starts with the resolved registry URL for this
    /// wallet instance - the same prefix `VctmFetcher`/`MddlSchemaFetcher`
    /// construct their registry lookup URL from.
    ///
    /// - Parameter performRequest: the actual network call, isolated behind
    ///   this parameter (default: a real `URLSession.shared.data(for:)` call
    ///   that returns the body only on a 200 response) so
    ///   `SirosWalletRegistryUrlTests` can inject a stub that captures the
    ///   built `URLRequest` - in particular its headers - and assert on
    ///   them directly, without a real network round trip (and without
    ///   needing to construct an `HTTPURLResponse`, which
    ///   swift-corelibs-foundation on Linux has no public initializer for).
    ///   Not `private` for the same `@testable import` access reason.
    static func makeTypeMetadataHttpGet(
        registryUrl: String,
        tenantId: String,
        authTokens: AuthTokens,
        sessionStore: SessionStoreProtocol,
        performRequest: @escaping @Sendable (URLRequest) async -> Data? = { request in
            guard let (data, response) = try? await URLSession.shared.data(for: request),
                  let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                return nil
            }
            return data
        }
    ) -> @Sendable (String) async -> String? {
        { url in
            guard let requestUrl = URL(string: url) else { return nil }
            var request = URLRequest(url: requestUrl)
            request.httpMethod = "GET"

            if url.hasPrefix(registryUrl) {
                request.setValue(tenantId, forHTTPHeaderField: "X-Tenant-ID")
                // Mirrors `BackendApiClient.request(_:path:body:)`'s own
                // auth-token precedence: prefer a live AS-issued backend
                // token, falling back to the legacy plain app-token string
                // (read fresh each call - unlike `authTokens`, this DOES
                // change over the wallet's lifetime, e.g. across
                // login/logout) when no AS session is available.
                if let token = try? await authTokens.ensureBackendToken() {
                    request.setValue("Bearer \(token.raw)", forHTTPHeaderField: "Authorization")
                } else if let appToken = sessionStore.appToken {
                    request.setValue("Bearer \(appToken)", forHTTPHeaderField: "Authorization")
                }
            }

            guard let data = await performRequest(request) else { return nil }
            return String(data: data, encoding: .utf8)
        }
    }

    /// Same derivation as the `resolvedRegistryUrl` instance property below,
    /// factored out as a `static` so it can be computed in `init` before
    /// `self` is fully initialized (see `makeTypeMetadataHttpGet` call site).
    private static func resolveRegistryUrl(config: WalletConfig) -> String {
        if let registryUrl = config.registryUrl { return registryUrl }
        let trimmedBackendUrl = config.backendUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        return "\(trimmedBackendUrl)/registry"
    }

    /// Fires whenever ANY code path determines the current session is no
    /// longer valid and can't be silently refreshed - repeated REST 401s
    /// (`AuthTokens.onSessionRejected`) or the engine WebSocket's token
    /// refresh failing before a reconnect (`WalletEngineSession.State
    /// .reauthRequired`, observed via the engine's `stateStream` in
    /// `connectEngine`). Notifies the host app via
    /// `WalletEventListener.onReauthenticationRequired` - distinct from
    /// `onFlowError` - so it can route straight to a login screen instead of
    /// surfacing a generic error message, then logs out to put the SDK's own
    /// state in sync with that.
    private func handleReauthenticationRequired() {
        lock.lock()
        let listener = eventListener
        lock.unlock()
        listener?.onReauthenticationRequired()
        logout()
    }

    // MARK: - Event listener

    /// Set a listener for events that require user interaction.
    public func setEventListener(_ listener: WalletEventListener?) {
        lock.lock(); defer { lock.unlock() }
        eventListener = listener
    }

    /// Governs whether a successful presentation exhausts the credential
    /// instance it used (see `CredentialUtils.eligibleInstances`). Defaults
    /// to `.neverConsume` so existing behavior doesn't change until a host
    /// app opts in. This is core wallet policy, not a UI-only preference -
    /// the host app is responsible for persisting the user's choice across
    /// restarts and setting it here on startup.
    public var credentialConsumptionPolicy: CredentialConsumptionPolicy = .neverConsume

    // MARK: - Registration

    /// Register a new user with a passkey.
    ///
    /// 1. Gets a registration challenge from the backend.
    /// 2. Creates a passkey via the system UI (with PRF extension).
    /// 3. Derives an encryption key from the PRF output.
    /// 4. Initialises an empty encrypted keystore.
    /// 5. Sends the encrypted keystore to the backend as privateData.
    /// 6. Opens the engine WebSocket.
    public func register(displayName: String) async throws {
        precondition(!displayName.isEmpty && displayName.count <= 256, "displayName must be 1-256 characters")
        guard let asClient = authServerClient, let tokens = authTokens else {
            throw SirosError.wallet(message: "AuthServerClient not initialized")
        }
        setState(.connecting)
        do {
            let prfSalt = Self.randomBytes(32)
            let hkdfSalt = Self.randomBytes(32)
            let hkdfInfo = Data(Self.hkdfInfo.utf8)

            // Step 1: Get challenge from AS
            let challengeResponse = try await asClient.registerBegin()
            guard let challengeId = challengeResponse["challengeId"] as? String else {
                throw SirosError.auth(message: "Missing challengeId")
            }
            guard let createOptions = challengeResponse["createOptions"] as? [String: Any],
                  let publicKey = createOptions["publicKey"] as? [String: Any] else {
                throw SirosError.auth(message: "Missing createOptions.publicKey")
            }
            guard let rpObj = publicKey["rp"] as? [String: Any],
                  let rpId = rpObj["id"] as? String else {
                throw SirosError.auth(message: "Missing rp.id")
            }
            let rpName = rpObj["name"] as? String ?? rpId
            guard let challengeB64 = publicKey["challenge"] as? String,
                  let challenge = Self.b64UrlDecode(challengeB64) else {
                throw SirosError.auth(message: "Missing challenge")
            }
            guard let userObj = publicKey["user"] as? [String: Any],
                  let userIdB64 = userObj["id"] as? String,
                  let userId = Self.b64UrlDecode(userIdB64) else {
                throw SirosError.auth(message: "Missing user.id")
            }
            let userName = userObj["name"] as? String ?? displayName

            // Step 2: Create credential via platform AuthProvider
            let result = try await authProvider.register(options: RegisterOptions(
                rpId: rpId,
                rpName: rpName,
                userId: userId,
                userName: userName,
                userDisplayName: displayName,
                challenge: challenge,
                prfSalt: prfSalt
            ))

            // Step 3: Complete registration with AS
            let credential: [String: Any] = [
                "id": Self.b64UrlEncode(result.credentialId),
                "rawId": Self.b64UrlEncode(result.credentialId),
                "type": "public-key",
                "response": [
                    "attestationObject": Self.b64UrlEncode(result.attestationObject),
                    "clientDataJSON": Self.b64UrlEncode(result.clientDataJSON),
                ],
            ]
            let session = try await asClient.registerFinish(
                challengeId: challengeId,
                credential: credential,
                displayName: displayName
            )

            // Prefer the PRF output already produced by the register() ceremony
            // itself (e.g. LocalAuthProvider computes it locally); only fall back
            // to a separate getPrfOutput() ceremony — and always pass the real
            // credential ID, never an empty placeholder — when it isn't present.
            let prfOutput: PrfOutput
            if let resultPrf = result.prfOutput {
                prfOutput = resultPrf
            } else {
                prfOutput = try await authProvider.getPrfOutput(credentialId: result.credentialId, salt: prfSalt)
            }

            try await keystore.unlock(
                prfOutput: prfOutput.first,
                encryptedContainer: Data(),
                hkdfSalt: hkdfSalt,
                hkdfInfo: hkdfInfo
            )

            let encryptedContainer = try await keystore.exportEncryptedContainer()

            // Register account in the persistent registry (survives logout)
            let accountId = "\(config.tenantId):\(session.uuid)"
            let credIdStr = Self.b64UrlEncode(result.credentialId)
            accountRegistry.upsertAccount(CachedAccount(
                userId: session.uuid,
                tenantId: config.tenantId,
                displayName: displayName,
                backendUrl: config.backendUrl,
                passkeys: [CachedPasskey(
                    credentialId: credIdStr,
                    prfSalt: Self.b64Encode(prfSalt)
                )],
                hkdfSalt: Self.b64Encode(hkdfSalt),
                hkdfInfo: Self.b64Encode(hkdfInfo)
            ))
            accountRegistry.activeAccountId = accountId

            // Scope session store to this account
            sessionStore.activeAccountId = accountId
            sessionStore.userId = session.uuid
            sessionStore.displayName = session.displayName
            sessionStore.tenantId = config.tenantId
            sessionStore.prfSalt = Self.b64Encode(prfSalt)
            sessionStore.hkdfSalt = Self.b64Encode(hkdfSalt)
            sessionStore.hkdfInfo = Self.b64Encode(hkdfInfo)
            sessionStore.privateDataJwe = String(data: encryptedContainer, encoding: .utf8)

            setupApiClientWithTokens(tokens)
            try await syncPrivateDataToBackend()
            try await connectEngineWithToken(tokens)

            let creds = await credentialStore.getAll()
            setState(.ready(userId: session.uuid, displayName: session.displayName, credentials: creds))
        } catch let e as SirosError {
            #if canImport(os)
            logger.error("Registration failed: \(e.localizedDescription)")
            #endif
            rollbackLocalCredential()
            setState(.error(message: e.localizedDescription))
        } catch {
            #if canImport(os)
            logger.error("Registration failed: \(error.localizedDescription)")
            #endif
            rollbackLocalCredential()
            setState(.error(message: error.localizedDescription))
            throw SirosError.wallet(message: "Registration failed: \(error.localizedDescription)")
        }
    }

    // MARK: - Login

    /// Login with an existing passkey.
    public func login() async throws {
        guard let asClient = authServerClient, let tokens = authTokens else {
            throw SirosError.wallet(message: "AuthServerClient not initialized")
        }
        setState(.connecting)
        do {
            let storedPrfSalt = sessionStore.prfSalt.flatMap { Self.b64Decode($0) }

            // Step 1: Get challenge from AS
            let challengeResponse = try await asClient.loginBegin()
            guard let challengeId = challengeResponse["challengeId"] as? String else {
                throw SirosError.auth(message: "Missing challengeId")
            }
            guard let getOptions = challengeResponse["getOptions"] as? [String: Any],
                  let publicKey = getOptions["publicKey"] as? [String: Any] else {
                throw SirosError.auth(message: "Missing getOptions.publicKey")
            }
            guard let rpId = publicKey["rpId"] as? String else {
                throw SirosError.auth(message: "Missing rpId")
            }
            guard let challengeB64 = publicKey["challenge"] as? String,
                  let challenge = Self.b64UrlDecode(challengeB64) else {
                throw SirosError.auth(message: "Missing challenge")
            }

            // Step 2: Authenticate via platform AuthProvider
            let result = try await authProvider.authenticate(options: AuthenticateOptions(
                rpId: rpId,
                challenge: challenge,
                prfSalt: storedPrfSalt
            ))

            // Step 3: Complete login with AS
            var responseDict: [String: Any] = [
                "authenticatorData": Self.b64UrlEncode(result.authenticatorData),
                "clientDataJSON": Self.b64UrlEncode(result.clientDataJSON),
                "signature": Self.b64UrlEncode(result.signature),
            ]
            if let uh = result.userHandle {
                responseDict["userHandle"] = Self.b64UrlEncode(uh)
            }
            let credential: [String: Any] = [
                "id": Self.b64UrlEncode(result.credentialId),
                "rawId": Self.b64UrlEncode(result.credentialId),
                "type": "public-key",
                "response": responseDict,
            ]
            let session = try await asClient.loginFinish(
                challengeId: challengeId,
                credential: credential
            )

            // Prefer the PRF output already produced by the authenticate()
            // ceremony itself (real ASAuthorization PRF assertion, when
            // supported) to avoid a redundant second device-authentication
            // prompt; fall back to a separate getPrfOutput() call — with the
            // real credential ID, never an empty placeholder — otherwise.
            let prfOutput: PrfOutput
            if let resultPrf = result.prfOutput {
                prfOutput = resultPrf
            } else {
                prfOutput = try await authProvider.getPrfOutput(
                    credentialId: result.credentialId,
                    salt: storedPrfSalt ?? Self.randomBytes(32)
                )
            }

            setupApiClientWithTokens(tokens)
            let privateData = await fetchPrivateData()

            let hkdfSalt = sessionStore.hkdfSalt.flatMap { Self.b64Decode($0) } ?? Self.randomBytes(32)
            let hkdfInfo = sessionStore.hkdfInfo.flatMap { Self.b64Decode($0) } ?? Data(Self.hkdfInfo.utf8)
            let prfSaltBytes = sessionStore.prfSalt.flatMap { Self.b64Decode($0) } ?? Self.randomBytes(32)

            try await keystore.unlock(
                prfOutput: prfOutput.first,
                encryptedContainer: privateData,
                hkdfSalt: hkdfSalt,
                hkdfInfo: hkdfInfo
            )

            // Scope session store to this account
            let accountId = "\(config.tenantId):\(session.uuid)"
            sessionStore.activeAccountId = accountId
            accountRegistry.activeAccountId = accountId
            sessionStore.userId = session.uuid
            sessionStore.displayName = session.displayName
            sessionStore.tenantId = config.tenantId
            sessionStore.prfSalt = Self.b64Encode(prfSaltBytes)
            sessionStore.hkdfSalt = Self.b64Encode(hkdfSalt)
            sessionStore.hkdfInfo = Self.b64Encode(hkdfInfo)

            try await connectEngineWithToken(tokens)

            let creds = await credentialStore.getAll()
            setState(.ready(userId: session.uuid, displayName: session.displayName, credentials: creds))
            await reloadPresentationHistory()
        } catch let e as SirosError {
            #if canImport(os)
            logger.error("Login failed: \(e.localizedDescription)")
            #endif
            setState(.error(message: e.localizedDescription))
        } catch {
            #if canImport(os)
            logger.error("Login failed: \(error.localizedDescription)")
            #endif
            setState(.error(message: error.localizedDescription))
            throw SirosError.wallet(message: "Login failed: \(error.localizedDescription)")
        }
    }

    // MARK: - Logout

    /// Disconnect, lock keystore, clear session.
    public func logout() {
        lock.lock()
        let engine = engineSession
        let peer = wmpPeer
        engineSession = nil
        wmpPeer = nil
        credentialNotifier = nil
        apiClient = nil
        lock.unlock()
        engine?.disconnect()
        if let peer { Task { try? await peer.close() } }
        cancelEngineTasks()
        keystore.lock()
        sessionStore.clear()  // clears active account's session only
        accountRegistry.activeAccountId = nil
        authTokens?.clear()
        Task {
            try? await authServerClient?.logout()
        }
        setState(.disconnected(cachedAccounts: accountRegistry.listLoginableAccounts()))
    }

    // MARK: - Session resume

    /// Resume a previous session without requiring a new WebAuthn assertion.
    public func resumeSession() async {
        // Restore the active account ID so the session store reads the right data
        if let activeId = accountRegistry.activeAccountId {
            sessionStore.activeAccountId = activeId
        }
        guard let userId = sessionStore.userId, let tokens = authTokens else { return }
        setState(.connecting)
        do {
            let displayName = sessionStore.displayName

            setupApiClientWithTokens(tokens)

            // Verify the session is still valid by requesting a backend token
            do {
                _ = try await tokens.ensureBackendToken()
            } catch {
                sessionStore.clear()
                lock.lock(); apiClient = nil; lock.unlock()
                setState(.disconnected(cachedAccounts: accountRegistry.listLoginableAccounts()))
                return
            }

            try await connectEngineWithToken(tokens)

            let storedJwe = sessionStore.privateDataJwe
            let hkdfSalt = sessionStore.hkdfSalt.flatMap { Self.b64Decode($0) }
            let hkdfInfo = sessionStore.hkdfInfo.flatMap { Self.b64Decode($0) }

            if storedJwe != nil, hkdfSalt != nil, hkdfInfo != nil {
                setState(.keystoreLocked(userId: userId, displayName: displayName))
            } else {
                setState(.ready(userId: userId, displayName: displayName, credentials: []))
            }
        } catch {
            setState(.disconnected(cachedAccounts: accountRegistry.listLoginableAccounts()))
        }
    }

    // MARK: - Keystore unlock

    /// Unlock the keystore after a session resume.
    public func unlockKeystore() async throws {
        guard case .keystoreLocked(let userId, let displayName) = state,
              let asClient = authServerClient else { return }
        do {
            let storedPrfSalt = sessionStore.prfSalt.flatMap { Self.b64Decode($0) }

            // Use AS login to get PRF output via biometric assertion
            let challengeResponse = try await asClient.loginBegin()
            guard let challengeId = challengeResponse["challengeId"] as? String,
                  let getOptions = challengeResponse["getOptions"] as? [String: Any],
                  let publicKey = getOptions["publicKey"] as? [String: Any],
                  let rpId = publicKey["rpId"] as? String,
                  let challengeB64 = publicKey["challenge"] as? String,
                  let challenge = Self.b64UrlDecode(challengeB64) else {
                throw SirosError.auth(message: "Invalid login challenge for keystore unlock")
            }

            let result = try await authProvider.authenticate(options: AuthenticateOptions(
                rpId: rpId,
                challenge: challenge,
                prfSalt: storedPrfSalt
            ))

            // Complete login with AS (refreshes session cookie)
            var responseDict: [String: Any] = [
                "authenticatorData": Self.b64UrlEncode(result.authenticatorData),
                "clientDataJSON": Self.b64UrlEncode(result.clientDataJSON),
                "signature": Self.b64UrlEncode(result.signature),
            ]
            if let uh = result.userHandle {
                responseDict["userHandle"] = Self.b64UrlEncode(uh)
            }
            let credential: [String: Any] = [
                "id": Self.b64UrlEncode(result.credentialId),
                "rawId": Self.b64UrlEncode(result.credentialId),
                "type": "public-key",
                "response": responseDict,
            ]
            _ = try await asClient.loginFinish(challengeId: challengeId, credential: credential)

            // Prefer the PRF output already produced by the authenticate()
            // ceremony itself; fall back to a separate getPrfOutput() call —
            // with the real credential ID, never an empty placeholder —
            // otherwise. See login() for the same pattern.
            let prfOutput: PrfOutput
            if let resultPrf = result.prfOutput {
                prfOutput = resultPrf
            } else {
                prfOutput = try await authProvider.getPrfOutput(
                    credentialId: result.credentialId,
                    salt: storedPrfSalt ?? Self.randomBytes(32)
                )
            }

            guard let storedJwe = sessionStore.privateDataJwe else {
                throw SirosError.keystore(message: "Missing private data")
            }
            guard let hkdfSalt = sessionStore.hkdfSalt.flatMap({ Self.b64Decode($0) }) else {
                throw SirosError.keystore(message: "Missing HKDF salt")
            }
            let hkdfInfo = sessionStore.hkdfInfo.flatMap { Self.b64Decode($0) } ?? Data(Self.hkdfInfo.utf8)

            try await keystore.unlock(
                prfOutput: prfOutput.first,
                encryptedContainer: Data(storedJwe.utf8),
                hkdfSalt: hkdfSalt,
                hkdfInfo: hkdfInfo
            )

            let creds = await credentialStore.getAll()
            setState(.ready(userId: userId, displayName: displayName, credentials: creds))
            await reloadPresentationHistory()
        } catch {
            setState(.error(message: error.localizedDescription))
        }
    }

    // MARK: - Credentials

    /// Get credentials, optionally including expired.
    public func getCredentials(includeExpired: Bool = false) async -> [StoredCredential] {
        let all = await credentialStore.getAll()
        if includeExpired { return all }
        let now = Int64(Date().timeIntervalSince1970)
        return all.filter { $0.expiresAt == nil || $0.expiresAt! > now }
    }

    /// Delete a credential by ID and sync to backend.
    public func deleteCredential(_ credentialId: Int64) async {
        await credentialStore.delete(credentialId)
        if case .ready(let userId, let displayName, _, _) = state {
            let creds = await credentialStore.getAll()
            setState(.ready(userId: userId, displayName: displayName, credentials: creds))
        }
        await persistAndSyncKeystore()
    }

    /// Sign an mDoc DeviceResponse for an ISO 18013-5 proximity (BLE)
    /// presentation - the local, engine-free counterpart to the redirect/
    /// DC-API presentation paths (`handleSignRequest`/wallet-managed-protocol
    /// sign handling above), since proximity presentation has no
    /// wallet-backend/engine round trip at all: the reader IS the
    /// counterpart, connected directly over BLE.
    ///
    /// - Parameters:
    ///   - credentialId: the `StoredCredential.id` of the mdoc credential to present.
    ///   - disclosedClaims: element identifiers to disclose (see `DeviceRequestParser.DocRequest.disclosedClaims`).
    ///   - sessionTranscriptBytes: the proximity `SessionTranscript` bytes, from `ProximitySessionTranscript.build`.
    /// - Returns: CBOR-encoded DeviceResponse bytes.
    public func signMdocPresentationForProximity(
        credentialId: Int64,
        disclosedClaims: [String]?,
        sessionTranscriptBytes: Data
    ) async throws -> Data {
        guard let credential = await credentialStore.getById(credentialId) else {
            throw SirosError.wallet(message: "Credential not found: \(credentialId)")
        }
        let allInstances = await credentialStore.getAll().filter { $0.batchId == credential.batchId }
        let eligible = CredentialUtils.eligibleInstances(
            instances: allInstances,
            policy: credentialConsumptionPolicy,
            presentationHistory: presentationHistory
        )
        guard eligible.contains(where: { $0.id == credentialId }) else {
            throw SirosError.wallet(message: "No eligible copies of this credential remain - renew it to get more")
        }
        guard let credBytes = CredentialUtils.base64UrlDecode(credential.raw) else {
            throw SirosError.wallet(message: "Credential \(credentialId) has malformed base64url raw data")
        }
        let response = try await keystore.signMdocPresentationForProximity(
            credentialBytes: credBytes,
            disclosedClaims: disclosedClaims,
            sessionTranscriptBytes: sessionTranscriptBytes,
            kid: credential.kid
        )
        await recordPresentation(PresentationRecord(
            id: randomUint32Id(),
            flowId: "proximity-\(UUID().uuidString)",
            credentialIds: [credentialId],
            credentialNames: [credential.metadata?.name].compactMap { $0 },
            requestedClaims: disclosedClaims ?? [],
            timestamp: Int64(Date().timeIntervalSince1970 * 1000)
        ))
        return response
    }

    // MARK: - Issuance

    /// Discover all available credentials across all visible issuers.
    ///
    /// Returns a flat list of `CredentialOffer` items ready for display in a
    /// picker UI. Each item can be passed to `startIssuanceByOffer`.
    public func getAvailableCredentials() async throws -> [CredentialOffer] {
        lock.lock(); let client = apiClient; lock.unlock()
        guard let client else {
            throw SirosError.wallet(message: "Not connected")
        }

        // Step 1: Get issuers from backend
        let rawIssuers = try await client.getIssuers()
        let issuersData: Data
        if let dict = rawIssuers as? [[String: Any]] {
            issuersData = try JSONSerialization.data(withJSONObject: dict)
        } else if let obj = rawIssuers as? [String: Any],
                  let arr = obj["issuers"] as? [[String: Any]] ?? obj["data"] as? [[String: Any]] {
            issuersData = try JSONSerialization.data(withJSONObject: arr)
        } else {
            issuersData = try JSONSerialization.data(withJSONObject: rawIssuers)
        }
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        let issuers = (try? decoder.decode([IssuerEntry].self, from: issuersData))?.filter { $0.visible } ?? []

        // Step 2: For each issuer, fetch metadata and build offers
        var offers: [CredentialOffer] = []
        for issuer in issuers {
            do {
                let metaDict = try await client.getIssuerMetadata(id: Int(issuer.id))
                let metaData = try JSONSerialization.data(withJSONObject: metaDict)
                let metaDecoder = JSONDecoder()
                let metadata = try metaDecoder.decode(IssuerMetadata.self, from: metaData)

                for configId in metadata.credentialConfigurationsSupported.keys {
                    if let offer = Self.buildCredentialOffer(
                        issuerUrl: issuer.credentialIssuerIdentifier,
                        configId: configId,
                        metadata: metadata
                    ) {
                        offers.append(offer)
                    }
                }
            } catch {
                // Skip issuers that fail metadata fetch
                continue
            }
        }
        return offers
    }

    /// Build a `CredentialOffer` (display name/logo/colors) for one credential
    /// configuration from an issuer's already-fetched `IssuerMetadata`, reading
    /// the standard OID4VCI `credential_metadata.display` field (falling back
    /// to the issuer's own top-level `display`). Shared by
    /// `getAvailableCredentials` (lists every configuration a registered
    /// issuer supports) and `startIssuance` (resolves display metadata for the
    /// single configuration named in a scanned/deep-linked offer, including
    /// from issuers - e.g. interop test issuers - never registered with this
    /// wallet).
    ///
    /// Returns `nil` if `configId` isn't actually offered by this issuer.
    ///
    /// `static` (takes no wallet state) so it's unit-testable without
    /// constructing a full `SirosWallet`, which requires a keystore -
    /// unavailable in a plain Linux test run (see `KeystoreManager`'s
    /// CryptoKit-gated default).
    static func buildCredentialOffer(
        issuerUrl: String,
        configId: String,
        metadata: IssuerMetadata
    ) -> CredentialOffer? {
        guard let config = metadata.credentialConfigurationsSupported[configId] else { return nil }
        let issuerDisplay = metadata.display?.first
        let issuerName = issuerDisplay?.name
            ?? URL(string: issuerUrl)?.host
            ?? issuerUrl
        let credDisplay = config.credentialMetadata?.display?.first
        let credName = credDisplay?.name ?? configId

        return CredentialOffer(
            credentialConfigurationId: configId,
            credentialIssuerIdentifier: issuerUrl,
            credentialName: credName,
            credentialDescription: credDisplay?.description,
            issuerName: issuerName,
            backgroundColor: credDisplay?.backgroundColor ?? issuerDisplay?.backgroundColor,
            textColor: credDisplay?.textColor ?? issuerDisplay?.textColor,
            logoUri: credDisplay?.logo?.uri,
            issuerLogoUri: issuerDisplay?.logo?.uri,
            vct: config.vct,
            doctype: config.doctype
        )
    }

    /// Fetch an issuer's standard OID4VCI metadata directly by its URL (not
    /// via `apiClient`, which only knows issuers registered with this
    /// wallet's own backend) - needed to resolve display metadata for
    /// arbitrary/third-party issuers named in a scanned credential offer.
    private func fetchIssuerMetadata(issuerUrl: String) async throws -> IssuerMetadata {
        let trimmed = issuerUrl.hasSuffix("/") ? String(issuerUrl.dropLast()) : issuerUrl
        guard let url = URL(string: trimmed + "/.well-known/openid-credential-issuer") else {
            throw SirosError.wallet(message: "Invalid issuer URL: \(issuerUrl)")
        }
        let (data, response) = try await URLSession.shared.data(from: url)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw SirosError.wallet(message: "Metadata fetch failed for \(issuerUrl)")
        }
        return try JSONDecoder().decode(IssuerMetadata.self, from: data)
    }

    /// In-memory cache for this session's Wallet Instance Attestation (WIA) -
    /// refetched when missing or close to expiry (see
    /// `ensureWalletInstanceAttestation`). Not persisted across app restarts:
    /// cheap to reissue given a challenge round trip, unlike the instance KEY
    /// itself (`SessionStoreProtocol.instanceKeyId`), which must stay stable.
    // Internal (not private), matching this file's `handleFlowComplete`
    // convention - lets tests seed a fake WIA directly via `@testable
    // import` rather than driving a full challenge/generateWIA network round
    // trip through a real keystore.
    var cachedWia: String?
    var cachedWiaExpiresAt: Int = 0

    /// Get (creating once, on first use) this wallet installation's persistent
    /// OAuth Client Attestation instance key ID - see
    /// `SessionStoreProtocol.instanceKeyId`.
    private func ensureInstanceKeyId() async throws -> String {
        if let existing = sessionStore.instanceKeyId {
            return existing
        }
        let keyId = try await keystore.generateKey(algorithm: "ES256")
        sessionStore.instanceKeyId = keyId
        return keyId
    }

    /// Obtain (fetching + caching, refreshing before expiry) a Wallet
    /// Instance Attestation for this wallet instance from this wallet's own
    /// backend (draft-ietf-oauth-attestation-based-client-auth-10 §3.1 /
    /// CS-04 §7.1.2): request a single-use challenge, sign a PoP JWT over it
    /// with the instance key, and exchange both for a WIA JWT.
    ///
    /// Best-effort: returns nil on any failure (network, backend not
    /// configured for WIA, etc.) rather than throwing - a missing/unavailable
    /// client attestation must never block issuance, since not every backend
    /// deployment enables this feature.
    private func ensureWalletInstanceAttestation() async -> String? {
        let now = Int(Date().timeIntervalSince1970)
        lock.lock(); let cached = cachedWia; let expiresAt = cachedWiaExpiresAt; lock.unlock()
        if let wia = cached, expiresAt - now > 60 {
            return wia
        }
        guard let client = apiClient else { return nil }
        do {
            let keyId = try await ensureInstanceKeyId()
            let challengeResponse = try await client.requestWIAChallenge()
            guard let challenge = challengeResponse["challenge"] as? String else { return nil }
            let pop = try await keystore.generateKeyProof(
                keyId: keyId,
                typ: "oauth-client-attestation-pop+jwt",
                // iss doesn't need to equal client_id for THIS PoP - it's
                // validated by our own backend (WIAService.validatePop only
                // checks iss is non-empty), unlike the per-issuer PoP built in
                // resolveClientAttestation. clientAttestationClientId() is
                // still a reasonable choice: consistent, and non-empty.
                issuer: clientAttestationClientId(),
                // Must match the backend's configured wallet_provider_uri, if
                // it enforces one (WIAService.validatePop only checks aud
                // when that's non-empty) - the base backend URL is the only
                // value discoverable client-side without a dedicated endpoint.
                audience: config.backendUrl,
                extraClaims: ["nonce": challenge]
            )
            // Best-effort, on its OWN try/catch (not the outer one): a
            // native-attestation failure must degrade to a plain
            // backend-attested WIA, not abort issuance entirely. No
            // WalletConfig field needed on iOS - unlike Play Integrity,
            // App Attest needs no host-app-supplied config beyond the Xcode
            // entitlement (a project-level setting), so this constructs the
            // provider directly whenever the platform/OS version supports it.
            #if canImport(DeviceCheck)
            var nativeAttestation: [String: Any]?
            let appAttestProvider = AppAttestProvider(
                loadPersistedKeyId: { [weak self] in self?.sessionStore.appAttestKeyId },
                savePersistedKeyId: { [weak self] in self?.sessionStore.appAttestKeyId = $0 }
            )
            if appAttestProvider.isAvailable {
                do {
                    let evidence = try await appAttestProvider.generateEvidence(challenge: challenge, keyId: keyId)
                    nativeAttestation = [
                        "type": evidence.type,
                        "token": evidence.token,
                        "key_id": evidence.keyId,
                        "challenge": evidence.challenge,
                    ]
                } catch {
                    // Best-effort - device capability/entitlement issues are
                    // common and expected (Simulator, no entitlement, key
                    // already attested this install) - but silent failures
                    // here are hard to diagnose in the field, so log them.
                    print("[SirosWallet] App Attest evidence generation failed, continuing without it: \(error)")
                    nativeAttestation = nil
                }
            }
            #else
            let nativeAttestation: [String: Any]? = nil
            #endif
            let wia = try await client.generateWIA(
                pop: pop,
                challenge: challenge,
                // draft-ietf-oauth-attestation-based-client-auth-10: "the sub
                // claim MUST specify client_id value of the OAuth Client" -
                // confirmed via a real geneva2026.mdoc.online conformance run
                // that flagged sub=<instance jkt> as a FAIL.
                clientId: clientAttestationClientId(),
                nativeAttestation: nativeAttestation
            )
            let expiresAt = (CredentialUtils.parseJwtPayload(wia)?["exp"] as? Int) ?? (now + 300)
            lock.lock(); cachedWia = wia; cachedWiaExpiresAt = expiresAt; lock.unlock()
            return wia
        } catch {
            return nil
        }
    }

    /// The wallet_instance_id to send with a Key Attestation request: the
    /// JWK Thumbprint (`cnf.jkt`) of the current session's WIA-issued
    /// instance key, but only when that WIA's `attestation_source` is a
    /// verified native platform attestation (ios_app_attest /
    /// android_play_integrity) - go-wallet-backend's KA trust gate clamps to
    /// K3 for anything else anyway, so there's no value in sending an ID
    /// that won't lift the clamp, and every other failure mode (no WIA, WIA
    /// disabled, non-native tier) must resolve to omitting the field exactly
    /// like today's pre-this-change behavior.
    ///
    /// Peeks the existing WIA cache only - deliberately does NOT call
    /// `ensureWalletInstanceAttestation()` (real Copilot-review finding:
    /// that would trigger a challenge+generateWIA network round trip, and
    /// retry it on every backend key-attestation attempt in deployments
    /// where WIA is unsupported/misconfigured, adding latency for a field
    /// that's optional in the first place). A WIA obtained earlier this
    /// session (e.g. during issuance) is still picked up; one that was
    /// never fetched simply omits the field, exactly like today's behavior.
    func currentWalletInstanceId() -> String? {
        let now = Int(Date().timeIntervalSince1970)
        let nativeAttestationSources: Set<String> = ["ios_app_attest", "android_play_integrity"]
        lock.lock(); let cached = cachedWia; let expiresAt = cachedWiaExpiresAt; lock.unlock()
        guard let wia = cached, expiresAt - now > 60,
              let payload = CredentialUtils.parseJwtPayload(wia),
              let source = payload["attestation_source"] as? String,
              nativeAttestationSources.contains(source),
              let cnf = payload["cnf"] as? [String: Any],
              let jkt = cnf["jkt"] as? String else { return nil }
        return jkt
    }

    /// The OAuth `client_id` this wallet uses in OID4VCI/OID4VP flows.
    /// Mirrors go-wallet-backend's `OID4VCIHandler.clientID` default
    /// (`h.clientID = h.redirectURI`, OID4VCI §7.1's unregistered-client
    /// convention) - known to be correct for any issuer that doesn't have its
    /// own registered client_id override server-side (the common case; a
    /// registered override isn't visible to the client, so a cached WIA/PoP
    /// built against this default would be spec-inconsistent for that rarer
    /// case - a known, accepted limitation rather than something this method
    /// can resolve without per-issuer client_id discovery).
    private func clientAttestationClientId() -> String {
        config.redirectUri
    }

    /// Resolve OAuth Client Attestation (a WIA plus a fresh per-flow PoP) for
    /// an issuance flow targeting `issuerUrl` - the pair the engine forwards
    /// as `OAuth-Client-Attestation`/`OAuth-Client-Attestation-PoP` headers to
    /// the credential issuer.
    ///
    /// The PoP's `aud` targets the issuer's own authorization server if
    /// discoverable from its metadata, falling back to the credential issuer
    /// URL itself for issuers that self-host their AS at the same origin.
    /// Its `iss` is the same client_id used for the WIA's `sub` (see
    /// `ensureWalletInstanceAttestation`) - draft-ietf-oauth-attestation-based-client-auth-10
    /// requires both to match. Its `challenge` claim, when the AS publishes a
    /// `challenge_endpoint` in its metadata, is fetched fresh from there
    /// (§ "Challenge Endpoint" - POST returns `{"attestation_challenge": ...}`);
    /// omitted otherwise, since the claim is optional per spec.
    ///
    /// Best-effort: returns nil on any failure - missing/misconfigured WIA
    /// support must never block issuance itself.
    private func resolveClientAttestation(issuerUrl: String) async -> (String, String)? {
        guard let wia = await ensureWalletInstanceAttestation() else { return nil }
        do {
            let asUrl: String
            if let metadata = try? await fetchIssuerMetadata(issuerUrl: issuerUrl),
               let server = metadata.authorizationServers?.first(where: { !$0.isEmpty }) {
                asUrl = server
            } else {
                asUrl = issuerUrl
            }
            let challenge = await fetchAttestationChallenge(asUrl: asUrl)
            let keyId = try await ensureInstanceKeyId()
            var extraClaims: [String: String] = [:]
            if let challenge { extraClaims["challenge"] = challenge }
            let pop = try await keystore.generateKeyProof(
                keyId: keyId,
                typ: "oauth-client-attestation-pop+jwt",
                issuer: clientAttestationClientId(),
                audience: asUrl,
                extraClaims: extraClaims
            )
            return (wia, pop)
        } catch {
            return nil
        }
    }

    /// Fetch a fresh attestation challenge from `asUrl`'s own metadata-published
    /// `challenge_endpoint` (draft-ietf-oauth-attestation-based-client-auth-10
    /// §"Challenge Endpoint"), if it publishes one. Tries the OAuth 2.0
    /// Authorization Server Metadata well-known path (RFC 8414) first, falling
    /// back to the OIDC discovery path for ASes that only publish there.
    ///
    /// Returns nil (never throws) if the AS doesn't publish a challenge
    /// endpoint, or on any fetch failure - the `challenge` claim is optional
    /// per spec, so its absence must never block attestation entirely.
    private func fetchAttestationChallenge(asUrl: String) async -> String? {
        guard let metadata = await fetchOAuthServerMetadata(asUrl: asUrl),
              let challengeEndpoint = metadata["challenge_endpoint"] as? String,
              let url = URL(string: challengeEndpoint) else {
            return nil
        }
        do {
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.httpBody = Data("{}".utf8)
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { return nil }
            let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            return json?["attestation_challenge"] as? String
        } catch {
            return nil
        }
    }

    private func fetchOAuthServerMetadata(asUrl: String) async -> [String: Any]? {
        let base = asUrl.hasSuffix("/") ? String(asUrl.dropLast()) : asUrl
        for path in ["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"] {
            guard let url = URL(string: base + path) else { continue }
            do {
                let (data, response) = try await URLSession.shared.data(from: url)
                guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { continue }
                if let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    return json
                }
            } catch {
                // Try the next well-known path.
            }
        }
        return nil
    }

    /// Start issuance with a credential offer object.
    public func startIssuanceByOffer(_ offer: CredentialOffer) async throws {
        guard let engine = engineSession else {
            throw SirosError.wallet(message: "Not connected")
        }
        try await ensureEngineConnected(engine)
        lock.lock()
        if issuanceInFlight {
            lock.unlock()
            throw SirosError.wallet(message: "Another issuance is already in progress")
        }
        issuanceInFlight = true
        activeOffer = offer
        lock.unlock()
        do {

            // Try to fetch VCTM (SD-JWT) and MDDL schema (mdoc) - format-blind,
            // like `activeVctm`'s existing fetch: whichever one doesn't match
            // this offer's actual format simply fails to decode and stays nil.
            let vctm = try? await vctmFetcher.fetch(
                issuerUrl: offer.credentialIssuerIdentifier,
                scope: offer.credentialConfigurationId,
                vct: offer.vct,
                registryUrl: resolvedRegistryUrl
            )
            let mddlSchema = await mddlSchemaFetcher.fetch(
                issuerUrl: offer.credentialIssuerIdentifier,
                scope: offer.credentialConfigurationId,
                doctype: offer.doctype,
                registryUrl: resolvedRegistryUrl
            )
            lock.lock()
            activeVctm = vctm
            activeMddlSchema = mddlSchema
            lock.unlock()

            var credOffer: [String: AnyCodable] = [
                "credential_issuer": .string(offer.credentialIssuerIdentifier),
                "credential_configuration_ids": .array([.string(offer.credentialConfigurationId)]),
            ]

            var grants: [String: AnyCodable] = [:]
            if let preAuth = offer.preAuthorizedCode {
                var preAuthGrant: [String: AnyCodable] = ["pre-authorized_code": .string(preAuth)]
                if offer.txCode != nil {
                    preAuthGrant["tx_code"] = .object_(["input_mode": .string("text")])
                }
                grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"] = .object_(preAuthGrant)
            } else {
                grants["authorization_code"] = .object_([:])
            }
            credOffer["grants"] = .object_(grants)

            let offerJson: String
            if let data = try? JSONEncoder().encode(credOffer),
               let s = String(data: data, encoding: .utf8) {
                offerJson = s
            } else {
                offerJson = "{}"
            }

            let clientAttestation = await resolveClientAttestation(issuerUrl: offer.credentialIssuerIdentifier)
            engine.startIssuance(
                offer: offerJson,
                redirectUri: config.redirectUri.isEmpty ? nil : config.redirectUri,
                clientAttestation: clientAttestation?.0,
                clientAttestationPoP: clientAttestation?.1
            )
        } catch {
            // A synchronous start failure here means the flow was never
            // registered server-side, so nothing will ever clear the guard
            // via the normal flow_complete/flow_error path - without this,
            // every future issuance attempt would be permanently blocked.
            resetIssuanceGuards()
            throw error
        }
    }

    /// Start issuance with a raw offer URI or JSON.
    public func startIssuance(offerUri: String) async throws {
        guard let engine = engineSession else {
            throw SirosError.wallet(message: "Not connected")
        }
        try await ensureEngineConnected(engine)
        lock.lock()
        if issuanceInFlight {
            lock.unlock()
            throw SirosError.wallet(message: "Another issuance is already in progress")
        }
        issuanceInFlight = true
        lock.unlock()
        do {
            if let offer = await resolveOfferForDisplay(offerUri) {
                lock.lock(); activeOffer = offer; lock.unlock()
                let vctm = try? await vctmFetcher.fetch(
                    issuerUrl: offer.credentialIssuerIdentifier,
                    scope: offer.credentialConfigurationId,
                    vct: offer.vct,
                    registryUrl: resolvedRegistryUrl
                )
                let mddlSchema = await mddlSchemaFetcher.fetch(
                    issuerUrl: offer.credentialIssuerIdentifier,
                    scope: offer.credentialConfigurationId,
                    doctype: offer.doctype,
                    registryUrl: resolvedRegistryUrl
                )
                lock.lock(); activeVctm = vctm; activeMddlSchema = mddlSchema; lock.unlock()
            }
            // Resolve OAuth Client Attestation once, independent of whether the
            // display-metadata resolution above succeeded - a client that can't
            // be shown a name/logo should still get an attestation attached.
            var attestation: String?
            var attestationPoP: String?
            if let header = await extractOfferHeader(offerUri),
               let pair = await resolveClientAttestation(issuerUrl: header.credentialIssuer) {
                attestation = pair.0
                attestationPoP = pair.1
            }
            if offerUri.hasPrefix("openid-credential-offer://") {
                // Deep-link URI with inline offer - send as "offer" so the engine
                // extracts the credential_offer query parameter instead of HTTP-fetching.
                engine.startIssuance(offer: offerUri, clientAttestation: attestation, clientAttestationPoP: attestationPoP)
            } else if offerUri.hasPrefix("http") {
                // Universal-link-style offer: the credential_offer/credential_offer_uri
                // live in the URI's own query string (e.g. an issuer's wallet-redirect
                // page), so the URI itself is not fetchable as the offer JSON - unlike
                // the engine's openid-credential-offer:// handling, it only strips
                // that query param for that exact scheme, so it must be extracted here.
                let queryItems = URLComponents(string: offerUri)?.queryItems ?? []
                func queryValue(_ name: String) -> String? {
                    queryItems.first(where: { $0.name == name })?.value
                }
                if let credentialOffer = queryValue("credential_offer") {
                    engine.startIssuance(offer: credentialOffer, clientAttestation: attestation, clientAttestationPoP: attestationPoP)
                } else if let credentialOfferUri = queryValue("credential_offer_uri") {
                    engine.startIssuance(credentialOfferUri: credentialOfferUri, clientAttestation: attestation, clientAttestationPoP: attestationPoP)
                } else {
                    engine.startIssuance(credentialOfferUri: offerUri, clientAttestation: attestation, clientAttestationPoP: attestationPoP)
                }
            } else {
                engine.startIssuance(offer: offerUri, clientAttestation: attestation, clientAttestationPoP: attestationPoP)
            }
        } catch {
            // A synchronous start failure here means the flow was never
            // registered server-side, so nothing will ever clear the guard
            // via the normal flow_complete/flow_error path - without this,
            // every future issuance attempt would be permanently blocked.
            resetIssuanceGuards()
            throw error
        }
    }

    /// Just enough of a raw `credential_offer` JSON object to resolve display
    /// metadata - `credential_issuer` and the first `credential_configuration_ids`
    /// entry.
    private struct RawCredentialOfferHeader: Decodable {
        let credentialIssuer: String
        let credentialConfigurationIds: [String]

        enum CodingKeys: String, CodingKey {
            case credentialIssuer = "credential_issuer"
            case credentialConfigurationIds = "credential_configuration_ids"
        }
    }

    /// Resolve display metadata (name/logo/colors) for a scanned/deep-linked
    /// credential offer, ahead of forwarding it to the engine.
    ///
    /// `activeOffer` was previously only ever set by `startIssuanceByOffer`
    /// (the picker-driven path from `getAvailableCredentials`) - the QR/
    /// deep-link entry point here never populated it, so every credential
    /// issued that way (mdoc or SD-JWT, ours or a third-party issuer's) was
    /// stored with no display metadata AND no recorded issuer/config
    /// identifiers at all (both derive from `activeOffer` at storage time),
    /// confirmed against a real geneva2026.mdoc.online mDL credential offer.
    ///
    /// Best-effort: returns `nil` on any failure (unparseable offer,
    /// unreachable issuer, issuer doesn't support the offered configuration)
    /// rather than throwing - a missing display must never block issuance
    /// itself.
    private func resolveOfferForDisplay(_ offerUri: String) async -> CredentialOffer? {
        guard let header = await extractOfferHeader(offerUri),
              let configId = header.credentialConfigurationIds.first else { return nil }
        do {
            let metadata = try await fetchIssuerMetadata(issuerUrl: header.credentialIssuer)
            return Self.buildCredentialOffer(issuerUrl: header.credentialIssuer, configId: configId, metadata: metadata)
        } catch {
            return nil
        }
    }

    /// Extract the raw `credential_offer` JSON object from any of the shapes
    /// `startIssuance` accepts.
    private func extractOfferHeader(_ offerUri: String) async -> RawCredentialOfferHeader? {
        if offerUri.hasPrefix("openid-credential-offer://") || offerUri.hasPrefix("http") {
            let queryItems = URLComponents(string: offerUri)?.queryItems ?? []
            func queryValue(_ name: String) -> String? {
                queryItems.first(where: { $0.name == name })?.value
            }
            if let credentialOffer = queryValue("credential_offer"),
               let data = credentialOffer.data(using: .utf8) {
                return try? JSONDecoder().decode(RawCredentialOfferHeader.self, from: data)
            } else if let credentialOfferUri = queryValue("credential_offer_uri") {
                return await fetchOfferHeader(credentialOfferUri)
            }
            return nil
        } else {
            // Not a URI at all - offerUri is itself the raw offer JSON.
            guard let data = offerUri.data(using: .utf8) else { return nil }
            return try? JSONDecoder().decode(RawCredentialOfferHeader.self, from: data)
        }
    }

    private func fetchOfferHeader(_ uri: String) async -> RawCredentialOfferHeader? {
        guard let url = URL(string: uri) else { return nil }
        do {
            let (data, response) = try await URLSession.shared.data(from: url)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { return nil }
            return try? JSONDecoder().decode(RawCredentialOfferHeader.self, from: data)
        } catch {
            return nil
        }
    }

    /// Start a presentation flow.
    public func startPresentation(requestUri: String) async throws {
        guard let engine = engineSession else {
            throw SirosError.wallet(message: "Not connected")
        }
        try await ensureEngineConnected(engine)
        engine.startPresentation(requestUri: requestUri)
    }

    /// The final payload to hand back to the OS/browser for a W3C Digital
    /// Credentials API presentation - the platform's own credential-provider
    /// bridge (Android's `PendingIntentHandler`, or the equivalent wherever
    /// iOS eventually wires up native DC API OS integration - a separate,
    /// larger, already-tracked gap, not addressed here) wraps `responseJson`
    /// as the `DigitalCredential`'s response data.
    ///
    /// For `response_mode=dc_api` (unencrypted): `{"vp_token": {...}}`.
    /// For `response_mode=dc_api.jwt`: `{"response": "<jwe-compact>"}` per
    /// OpenID4VP 1.0 Appendix A.3.2.
    public struct DCAPIPresentationResult: Sendable {
        public let responseJson: String
        public let credentialIds: [Int64]

        public init(responseJson: String, credentialIds: [Int64]) {
            self.responseJson = responseJson
            self.credentialIds = credentialIds
        }
    }

    /// Process an incoming W3C Digital Credentials API (DC API) OpenID4VP
    /// presentation request entirely client-side - mirrors the Kotlin SDK's
    /// `handleDCAPIRequest` architecture rather than the
    /// `startPresentation`/engine-relay pattern: there is no
    /// `WalletEngineSession` involvement and no DC-API-specific backend call.
    /// The only backend calls made are the SAME generic trust-evaluation
    /// (`evaluateTrustDirect`) and presentation-history persistence the
    /// redirect flow already uses.
    ///
    /// - Parameters:
    ///   - rawRequestJson: the raw request data string from the OS/browser -
    ///     either a raw OpenID4VP request JSON object (unsigned protocol
    ///     variant) or `{"request": "<JWT>"}` (signed/multisigned JAR variant).
    ///   - origin: the browser/page origin that made the
    ///     `navigator.credentials.get()` call, as verified by the platform -
    ///     NOT read from the request body, which is untrusted until the
    ///     platform attests it.
    /// - Throws: `DCAPIRequestException` if the request is malformed or (for
    ///   the signed variant) fails JWS verification; `SirosError.wallet` if
    ///   no credential in the wallet is eligible to satisfy it.
    public func handleDCAPIRequest(rawRequestJson: String, origin: String) async throws -> DCAPIPresentationResult {
        let request = try DCAPIRequestParser.parse(rawRequestJson)

        // request.clientId is only cryptographically bound to anything when
        // the request is signed (keyMaterial != nil, verified against the
        // JWS header's own key in DCAPIRequestParser) - for the unsigned
        // variant it's just a caller-supplied field in the untrusted request
        // body. Using it there let a malicious page set client_id to some
        // other, possibly-whitelisted verifier's identity and have trust
        // (and presentation history) evaluated against that spoofed identity
        // instead of the platform-attested origin.
        let subjectId = request.keyMaterial != nil ? (request.clientId ?? origin) : origin
        let trustResult: TrustResult
        do {
            trustResult = try await evaluateTrustDirect(
                subjectId: subjectId,
                subjectType: "credential_verifier",
                keyMaterialType: request.keyMaterial?.x5c != nil ? "x5c" : (request.keyMaterial?.jwk != nil ? "jwk" : nil),
                x5c: request.keyMaterial?.x5c,
                jwk: request.keyMaterial?.jwk,
                context: nil
            )
        } catch {
            trustResult = trustCache.get(identifier: subjectId)
                ?? TrustResult(trusted: false, reason: error.localizedDescription, identifier: subjectId)
        }

        // Unlike the QR/redirect flow, there is no engine round-trip here to
        // gate on (trust is evaluated and enforced entirely wallet-side) - a
        // request from an untrusted or trust-eval-failed verifier must be
        // rejected before any credential is matched or signed, not merely
        // have its trust result computed and ignored.
        guard trustResult.trusted else {
            throw SirosError.wallet(message: "Verifier '\(subjectId)' is not trusted: \(trustResult.reason ?? "no reason given")")
        }

        let allCreds = await credentialStore.getAll()
        let dcqlOutput: CredentialMatcher.DcqlMatchOutput
        if let dcqlQuery = request.dcqlQuery {
            dcqlOutput = CredentialMatcher.matchDcql(dcqlQuery: dcqlQuery, credentials: allCreds)
        } else {
            dcqlOutput = CredentialMatcher.DcqlMatchOutput(
                queryResults: [CredentialMatcher.MatchResult(
                    queryId: "_default", format: nil, candidates: allCreds, requestedClaims: []
                )],
                credentialSets: nil,
                satisfiableOptions: []
            )
        }
        let matchResults = dcqlOutput.queryResults
        var seenIds = Set<Int64>()
        let candidates = matchResults.flatMap { $0.candidates }.filter { cred in
            guard !seenIds.contains(cred.id) else { return false }
            seenIds.insert(cred.id)
            return true
        }

        // Unlike the QR/redirect flow, credential selection and consent
        // already happened natively - the OS's own credential picker showed
        // the matching registered entries and the user picked one before
        // this call was ever reached. Routing through eventListener's
        // interactive onCredentialSelectionRequired here would suspend
        // waiting for an in-app consent screen that this headless flow
        // never shows.
        let eligible = CredentialUtils.eligibleInstances(
            instances: candidates,
            policy: credentialConsumptionPolicy,
            presentationHistory: presentationHistory
        )
        let selectedIds = eligible.map(\.id)

        if selectedIds.isEmpty {
            throw SirosError.wallet(message: candidates.isEmpty
                ? "No credential in the wallet matches the request"
                : "No eligible copies of the requested credential remain - renew it to get more"
            )
        }

        // "origin:<value>" per OpenID4VP 1.0 Appendix A is only used for the
        // VP token audience claim at signing time - trust evaluation above
        // uses the bare origin.
        let audience = "origin:\(origin)"
        var encryptionJwk: [String: Any]?
        if request.responseMode == "dc_api.jwt" {
            guard let jwk = Self.findEncryptionJwk(request.clientMetadata) else {
                throw SirosError.wallet(message: "dc_api.jwt response_mode requires client_metadata.jwks with an encryption key")
            }
            encryptionJwk = jwk
        }
        // `DCAPIResponseEncryption` is entirely CryptoKit-gated (Apple
        // platforms only, matching this module's existing convention e.g.
        // `EncryptedContainer`) - `nil` here on an unsupported platform still
        // lets an unencrypted `dc_api` presentation proceed; `dc_api.jwt`
        // itself is rejected below with a clear error instead.
        var encryptionThumbprint: String?
        #if canImport(CryptoKit)
        encryptionThumbprint = encryptionJwk.flatMap { DCAPIResponseEncryption.jwkThumbprint($0) }
        #endif

        // Per OpenID4VP 1.0 (#response_parameters), vp_token's value for each
        // DCQL query id MUST be a JSON array of one or more Presentations -
        // even when `multiple` is omitted/false, the array MUST still
        // contain exactly one Presentation, never a bare string. A real bug,
        // confirmed via Multipaz's own server source
        // (multipaz-verifier-server's handleDcGetDataOpenID4VP does
        // `value.jsonArray.map{...}` for the openid4vp-v1-signed/-unsigned
        // protocol versions): putting a bare string here throws inside their
        // server and surfaces as an opaque HTTP 500.
        var tokensByQueryId: [String: [String]] = [:]
        var queryIdOrder: [String] = []
        for id in selectedIds {
            guard let cred = allCreds.first(where: { $0.id == id }) else { continue }
            let matchResult = matchResults.first(where: { result in result.candidates.contains(where: { $0.id == id }) })
            let queryId = matchResult?.queryId ?? "_default"
            let disclosedClaims = matchResult?.requestedClaims.compactMap(\.last)

            let token: String
            if cred.format == "mso_mdoc" {
                guard let credBytes = Self.b64UrlDecode(cred.raw) else {
                    throw SirosError.wallet(message: "Credential \(cred.id) has malformed base64url raw data")
                }
                let deviceResponse = try await keystore.signMdocPresentationForDCAPI(
                    credentialBytes: credBytes,
                    disclosedClaims: disclosedClaims,
                    nonce: request.nonce,
                    origin: origin,
                    encryptionPublicJwkThumbprint: encryptionThumbprint,
                    kid: cred.kid
                )
                token = Self.b64UrlEncode(deviceResponse)
            } else {
                token = try await keystore.signVpToken(
                    credential: cred.raw,
                    disclosedClaims: disclosedClaims,
                    nonce: request.nonce,
                    audience: audience,
                    kid: cred.kid
                )
            }

            if tokensByQueryId[queryId] == nil {
                tokensByQueryId[queryId] = []
                queryIdOrder.append(queryId)
            }
            tokensByQueryId[queryId]?.append(token)
        }

        var vpTokenObj: [String: Any] = [:]
        for queryId in queryIdOrder {
            vpTokenObj[queryId] = tokensByQueryId[queryId] ?? []
        }

        var responseBody: [String: Any] = ["vp_token": vpTokenObj]
        // The verifier's only means of correlating this response back to the
        // right authorization session - the response arrives via the DC API
        // callback, a wholly separate channel from the original request,
        // with no other correlator available. Omitting this (a real bug:
        // request.state was parsed but never echoed back) left the verifier
        // decrypting a JWE it had no way to attribute to any session.
        if let state = request.state {
            responseBody["state"] = state
        }
        guard let responseBodyData = try? JSONSerialization.data(withJSONObject: responseBody),
              let responseBodyJson = String(data: responseBodyData, encoding: .utf8) else {
            throw SirosError.wallet(message: "Failed to serialize DC API response body")
        }

        let responseData: [String: Any]
        if request.responseMode == "dc_api.jwt", let encryptionJwk {
            #if canImport(CryptoKit)
            let jwe = try DCAPIResponseEncryption.encryptResponse(responseJson: responseBodyJson, verifierJwk: encryptionJwk)
            responseData = ["response": jwe]
            #else
            throw SirosError.wallet(message: "dc_api.jwt response encryption requires CryptoKit (unsupported on this platform)")
            #endif
        } else {
            responseData = responseBody
        }

        // The platform's own reference wallet
        // (https://github.com/digitalcredentialsdev/CMWallet) wraps its
        // response in this exact {"protocol": ..., "data": {...}} envelope
        // before handing it back - the mirror image of the {"requests":
        // [{"protocol", "data"}]} envelope the request itself arrives in
        // (see `DCAPIRequestParser`). Returning the bare `data` object on its
        // own leaves the platform with no declared protocol to associate the
        // response with.
        let finalResponse: [String: Any] = ["protocol": request.protocolIdentifier, "data": responseData]
        guard let finalResponseData = try? JSONSerialization.data(withJSONObject: finalResponse),
              let finalResponseJson = String(data: finalResponseData, encoding: .utf8) else {
            throw SirosError.wallet(message: "Failed to serialize DC API response envelope")
        }

        var seenClaims = Set<String>()
        let requestedClaims = matchResults.flatMap { $0.requestedClaims.flatMap { $0 } }.filter { seenClaims.insert($0).inserted }

        await recordPresentation(PresentationRecord(
            id: randomUint32Id(),
            flowId: "dc-api-\(UUID().uuidString)",
            verifierName: trustResult.entityName,
            credentialIds: selectedIds,
            credentialNames: selectedIds.compactMap { id in allCreds.first(where: { $0.id == id })?.metadata?.name },
            requestedClaims: requestedClaims,
            timestamp: Int64(Date().timeIntervalSince1970 * 1000)
        ))

        return DCAPIPresentationResult(responseJson: finalResponseJson, credentialIds: selectedIds)
    }

    /// Direct (non-engine-relayed) trust evaluation, for flows like
    /// `handleDCAPIRequest` that have no `WalletEngineSession` involvement at
    /// all - mirrors `handleTrustEvaluation`'s request shape/AuthZEN
    /// action-name mapping exactly.
    private func evaluateTrustDirect(
        subjectId: String,
        subjectType: String?,
        keyMaterialType: String?,
        x5c: [String]?,
        jwk: [String: Any]?,
        context: [String: Any]?
    ) async throws -> TrustResult {
        lock.lock(); let client = apiClient; lock.unlock()
        guard let client else { throw SirosError.wallet(message: "Not connected") }

        var resource: [String: Any] = [
            "type": keyMaterialType ?? "x5c",
            "id": subjectId,
        ]
        if let x5c {
            resource["key"] = x5c
        } else if let jwk {
            resource["key"] = [jwk]
        }

        var evaluationRequest: [String: Any] = [
            "subject": ["type": "key", "id": subjectId],
            "resource": resource,
            "action": ["name": subjectType == "credential_verifier" ? "credential-verifier" : "credential-issuer"],
        ]
        if let context {
            evaluationRequest["context"] = context
        }

        let response = try await client.evaluateTrust(evaluationRequest)
        let decision = response["decision"] as? Bool ?? false
        let respContext = response["context"] as? [String: Any]

        // Mirrors the Kotlin SDK's `evaluateTrustDirect` exactly: unlike
        // `handleTrustEvaluation` (the engine-relayed path), this direct-call
        // variant deliberately does NOT populate `trustCache` on success -
        // only `handleDCAPIRequest`'s catch block reads it, as a fallback
        // when the live call itself fails.
        return TrustResult(
            trusted: decision,
            framework: respContext?["framework"] as? String,
            reason: (respContext?["reason"] as? String) ?? (respContext?["message"] as? String),
            entityName: respContext?["entity_name"] as? String,
            entityLogo: respContext?["logo_uri"] as? String,
            clientIdScheme: nil,
            identifier: subjectId,
            domain: respContext?["domain"] as? String
        )
    }

    /// Find the verifier's response-encryption key (`use: "enc"`) from DC API `client_metadata.jwks`.
    private static func findEncryptionJwk(_ clientMetadata: [String: Any]?) -> [String: Any]? {
        guard let jwks = clientMetadata?["jwks"] as? [String: Any],
              let keys = jwks["keys"] as? [[String: Any]] else {
            return nil
        }
        return keys.first(where: { ($0["use"] as? String) == "enc" }) ?? keys.first
    }

    /// Force a fresh engine WebSocket connection before starting a new flow,
    /// rather than trusting a connection that may have gone idle since the
    /// last one - mirrors `completeAuthorization`'s existing zombie-connection
    /// handling. A connection left open across a backend restart or any other
    /// silent network drop can look connected while actually discarding every
    /// send, and that failure mode isn't unique to the post-OAuth-redirect gap.
    private func ensureEngineConnected(_ engine: WalletEngineSession) async throws {
        guard let tokens = authTokens else {
            throw SirosError.wallet(message: "Not connected")
        }
        let token = try await tokens.ensureBackendToken()
        engine.forceReconnect(appToken: token.raw)
        try await engine.awaitConnected()
    }

    /// Clear the ambient issuance-in-progress guard fields, unconditionally.
    ///
    /// Every terminal path for an issuance attempt must call this - a
    /// `flow_complete`/`flow_error` from the engine, a client-side
    /// termination (e.g. `reportSignFailure`), a synchronous start failure,
    /// or the user cancelling before the engine ever assigned a flow ID at
    /// all (see `cancelCurrentFlow`'s doc comment for why that last case is
    /// real, not just defensive). Not `private`, for the same
    /// cross-file-extension-access reason as `activeOffer` etc.
    func resetIssuanceGuards() {
        lock.lock()
        activeOffer = nil
        activeVctm = nil
        activeAttestedKeyIds = nil
        issuanceInFlight = false
        lock.unlock()
    }

    /// Cancel the current flow.
    ///
    /// `resetIssuanceGuards()` is called unconditionally, not just inside the
    /// `.flowActive` branch - a slow/unresponsive issuer leaves the wallet in
    /// `.ready` the whole time `startIssuance`/`startIssuanceByOffer` is
    /// awaiting the engine's first progress message, since the engine
    /// doesn't assign (and report) a flow ID until then. Gating the local
    /// guard reset on `.flowActive` too meant cancelling during exactly that
    /// window did nothing at all - not even a local reset - permanently
    /// stranding `issuanceInFlight` at `true` and blocking every subsequent
    /// issuance attempt until the app process was killed (real bug hit
    /// against a slow Geneva interop test issuer). The backend `cancelFlow`
    /// send stays gated on `.flowActive`, since only then does a real
    /// `flowId` exist to send to the server - the local guard reset does
    /// not need one, and is a no-op if no issuance was ever in flight, so
    /// it's always safe to call unconditionally.
    public func cancelCurrentFlow() {
        if case .flowActive(let userId, let displayName, let flowId, _, _, let creds) = state {
            try? engineSession?.cancelFlow(flowId: flowId)
            setState(.ready(userId: userId, displayName: displayName, credentials: creds))
        }
        resetIssuanceGuards()
    }

    // MARK: - Identity Verification

    /// Perform identity verification via a plugin provider and automatically start
    /// credential issuance with the resulting offer.
    ///
    /// This is the primary integration point for IDV flows (FaceTec, iProov, etc.).
    /// The provider handles all capture UI and backend communication; this method
    /// bridges the IDV result into the standard OID4VCI issuance flow.
    ///
    /// - Parameters:
    ///   - provider: An ``IdentityVerificationProvider`` implementation.
    ///   - presentingViewController: The UIViewController to present the IDV UI from.
    /// - Throws: ``IDVError`` if verification fails, or ``SirosError`` if issuance fails.
    public func verifyIdentityAndIssue(
        provider: IdentityVerificationProvider,
        presentingViewController: Any
    ) async throws {
        guard await provider.isAvailable() else {
            throw IDVError.unavailable(reason: "\(provider.name) is not available on this device")
        }
        let result = try await provider.startVerification(
            presentingViewController: presentingViewController
        )
        try await startIssuance(offerUri: result.credentialOfferURI)
    }

    /// Complete an OAuth authorization flow.
    ///
    /// If a pending authorization context was captured from this flow's
    /// `authorization_required` progress message, resumes issuance via a
    /// brand-new `flow_start` (not a `flow_action` on the original flow_id,
    /// which isn't guaranteed to survive the OAuth browser round-trip) -
    /// mirrors the wallet-backend's `resumeWithAuthCode` contract already
    /// used by the web client. The engine WebSocket is force-reconnected
    /// first in case it silently went stale ("zombie") during the redirect.
    /// Falls back to the legacy `flow_action`-based completion if no pending
    /// context was captured (e.g. an older backend that doesn't send it).
    public func completeAuthorization(flowId: String, code: String, state: String) {
        lock.lock()
        let engine = engineSession
        // Peek, don't remove yet - removing before the state check below
        // meant a mismatched (e.g. attacker-forged) callback destroyed the
        // real, still-pending context, so any later legitimate completion
        // attempt for the same flowId fell through to the no-context branch,
        // which sends the flow action straight through with no CSRF check
        // at all. Only remove once the check actually passes.
        let pending = pendingAuthorizations[flowId]
        let tokens = authTokens
        let listener = eventListener
        lock.unlock()

        guard let engine else { return }

        guard let pending else {
            engine.sendFlowAction(
                flowId: flowId,
                action: "authorization_complete",
                payload: ["code": .string(code), "state": .string(state)]
            )
            return
        }

        guard pending.state == state else {
            listener?.onFlowError(flowId: flowId, errorMessage: "Authorization state mismatch")
            return
        }

        lock.lock(); pendingAuthorizations.removeValue(forKey: flowId); lock.unlock()

        Task {
            do {
                guard let tokens else {
                    throw SirosError.wallet(message: "Not connected")
                }
                let token = try await tokens.ensureBackendToken()
                engine.forceReconnect(appToken: token.raw)
                try await engine.awaitConnected()
                // Client attestation for the resumed flow: Execute() sets up
                // h.attestationProvider identically whether msg.AuthCode is
                // set or not (it runs before that branch), so the ONLY thing
                // missing here was the client never sending it - the backend
                // already handled resume correctly. Confirmed missing via a
                // real geneva2026.mdoc.online conformance run: the token
                // request (which only ever happens via this resume path for
                // redirect-based authorization_code issuers) showed "No OAuth
                // Client Attestations were provided".
                var clientAttestation: (String, String)?
                if let offerJson = pending.offer,
                   let data = offerJson.data(using: .utf8),
                   let offerObj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let issuerUrl = offerObj["credential_issuer"] as? String {
                    clientAttestation = await resolveClientAttestation(issuerUrl: issuerUrl)
                }
                engine.resumeIssuance(
                    offer: pending.offer,
                    credentialOfferUri: pending.credentialOfferUri,
                    redirectUri: pending.redirectUri,
                    authCode: code,
                    codeVerifier: pending.codeVerifier,
                    clientAttestation: clientAttestation?.0,
                    clientAttestationPoP: clientAttestation?.1
                )
            } catch {
                lock.lock(); let listener = eventListener; lock.unlock()
                listener?.onFlowError(
                    flowId: flowId,
                    errorMessage: "Failed to resume issuance: \(error.localizedDescription)"
                )
            }
        }
    }

    /// Release all resources. Instance must not be reused after this.
    public func destroy() {
        lock.lock()
        let engine = engineSession
        engineSession = nil
        credentialNotifier = nil
        apiClient = nil
        lock.unlock()
        engine?.disconnect()
        cancelEngineTasks()
        keystore.lock()
    }

    /// Roll back a locally-stored credential after a failed registration.
    /// Prevents orphaned passkeys from appearing in the login picker.
    private func rollbackLocalCredential() {
        if let local = authProvider as? LocalAuthProvider {
            local.rollbackLastRegistration()
        }
    }

    // MARK: - Private helpers

    func setState(_ newState: WalletState) {
        lock.lock()
        _state = newState
        let conts = Array(stateContinuations.values)
        lock.unlock()
        for c in conts { c.yield(newState) }
    }

    private func setupApiClient(session: AuthSession) {
        let client = BackendApiClient(
            baseUrl: config.backendUrl,
            tenantId: config.tenantId,
            httpFn: Self.defaultHttpFn
        )
        client.setAppToken(session.appToken)
        lock.lock(); apiClient = client; lock.unlock()
    }

    private func setupApiClientWithTokens(_ tokens: AuthTokens) {
        let client = BackendApiClient(
            baseUrl: config.backendUrl,
            tenantId: config.tenantId,
            httpFn: Self.defaultHttpFn
        )
        client.setAuthTokens(tokens)
        lock.lock(); apiClient = client; lock.unlock()
    }

    private func saveSession(session: AuthSession, credentialId: Data, prfSalt: Data, hkdfSalt: Data, hkdfInfo: Data) {
        sessionStore.appToken = session.appToken
        sessionStore.refreshToken = session.refreshToken
        sessionStore.userId = session.uuid
        sessionStore.displayName = session.displayName
        sessionStore.tenantId = config.tenantId
        sessionStore.credentialId = Self.b64UrlEncode(credentialId)
        sessionStore.prfSalt = Self.b64Encode(prfSalt)
        sessionStore.hkdfSalt = Self.b64Encode(hkdfSalt)
        sessionStore.hkdfInfo = Self.b64Encode(hkdfInfo)
    }

    private func fetchPrivateData() async -> Data {
        lock.lock(); let client = apiClient; lock.unlock()
        guard let client else { return Data() }
        do {
            let response = try await client.getPrivateData()
            if let pd = response["privateData"] {
                if let pdDict = pd as? [String: Any], let b64u = pdDict["$b64u"] as? String {
                    let containerBytes = Self.b64UrlDecode(b64u) ?? Data()
                    if !containerBytes.isEmpty {
                        sessionStore.privateDataJwe = String(data: containerBytes, encoding: .utf8)
                    }
                    return containerBytes
                } else if let pdStr = pd as? String {
                    let containerBytes = Data(pdStr.utf8)
                    sessionStore.privateDataJwe = pdStr
                    return containerBytes
                }
            }
        } catch {
            #if canImport(os)
            logger.warning("Could not fetch privateData: \(error.localizedDescription)")
            #endif
        }
        return Data()
    }

    private func syncPrivateDataToBackend() async throws {
        lock.lock(); let client = apiClient; lock.unlock()
        guard let client else { return }
        guard let containerJson = sessionStore.privateDataJwe else { return }
        do {
            // Parse the JSON string back to a dict and send
            if let data = containerJson.data(using: .utf8),
               let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                _ = try await client.updatePrivateData(dict)
            }
        } catch {
            #if canImport(os)
            logger.error("Failed to sync private data: \(error.localizedDescription)")
            #endif
            lock.lock(); let listener = eventListener; lock.unlock()
            listener?.onFlowError(flowId: "sync", errorMessage: "Private data sync failed: \(error.localizedDescription)")
        }
    }

    func persistAndSyncKeystore() async {
        guard keystore.isUnlocked else { return }
        do {
            let container = try await keystore.exportEncryptedContainer()
            sessionStore.privateDataJwe = String(data: container, encoding: .utf8)
            try await syncPrivateDataToBackend()
        } catch {
            #if canImport(os)
            logger.error("Failed to persist keystore: \(error.localizedDescription)")
            #endif
        }
    }

    private func cancelEngineTasks() {
        for t in engineTasks { t.cancel() }
        engineTasks.removeAll()
    }

    // MARK: - Engine connection

    /// Connect engine using a backend token from the AS. The anonymous token
    /// is scoped to `tac="rl"` for registry-style reads only - the engine
    /// session needs `insert` for OID4VCI issuance, so it must use the
    /// fully-scoped backend token, not the anonymous one
    /// (go-wallet-backend#264 made the missing `insert` scope a hard
    /// server-side rejection for `oid4vci` flow_start, not just a
    /// documentation note).
    private func connectEngineWithToken(_ tokens: AuthTokens) async throws {
        let token = try await tokens.ensureBackendToken()
        if config.useWmpProtocol {
            try await connectViaWmp(appToken: token.raw)
        } else {
            try await connectEngine(appToken: token.raw)
        }
    }

    // MARK: - WMP Protocol Path

    private var wmpPeer: WmpPeer?

    private func connectViaWmp(appToken: String) async throws {
        // Resolve engine base URL
        let engineBase: String
        if !config.engineUrl.isEmpty {
            engineBase = config.engineUrl
        } else if let discovered = await WalletConfig.discoverEngineUrl(backendUrl: config.backendUrl) {
            engineBase = discovered
        } else {
            engineBase = config.backendUrl
        }

        let wsUrl = engineBase.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            .replacingOccurrences(of: "http://", with: "ws://")
            .replacingOccurrences(of: "https://", with: "wss://")
            + "/api/v2/wallet?tenant_id=\(config.tenantId)"

        let transport = WmpWebSocketTransport(url: URL(string: wsUrl)!)
        let session = WmpSession(transport: transport)
        let peer = WmpPeer(session: session)

        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onSignRequest: { [weak self] flowId, params in
                guard let self else { throw SirosError.auth(message: "Wallet deallocated") }
                return try await self.handleWmpSignRequest(flowId: flowId, params: params)
            },
            onMatchRequest: { [weak self] flowId, payload in
                guard let self else { throw SirosError.auth(message: "Wallet deallocated") }
                return await self.handleWmpMatchRequest(flowId: flowId, payload: payload)
            },
            onTrustEvaluation: { [weak self] flowId, payload in
                guard let self else { return SirosTransport.TrustResult(trusted: false, reason: "Wallet deallocated") }
                return await self.handleWmpTrustEvaluation(flowId: flowId, payload: payload)
            },
            onComplete: { [weak self] flowId, _ in
                // Terminal path for this issuance over the WMP transport too -
                // see `resetIssuanceGuards()`.
                self?.resetIssuanceGuards()
                self?.eventListener?.onFlowComplete(flowId: flowId)
            },
            onError: { [weak self] flowId, code, message in
                self?.resetIssuanceGuards()
                self?.eventListener?.onFlowError(flowId: flowId, errorMessage: "\(code ?? ""): \(message ?? "")")
            }
        ))
        peer.use(profile)
        try await peer.connect(authToken: appToken)
        lock.lock(); wmpPeer = peer; lock.unlock()

        #if canImport(os)
        logger.info("Connected via WMP protocol to \(wsUrl)")
        #endif
    }

    /// Select the proof type to generate, shared by both transports (WMP and
    /// the legacy WS engine) so a real external issuer that lists only
    /// "attestation" in proof_types_supported gets the same treatment
    /// regardless of which transport carried the request. `proofTypesSupported`
    /// (from the issuer's metadata) takes precedence when present; `proofTypeHint`
    /// is a fallback for WMP, whose wire format only carries a single hint string,
    /// not the full supported-types set the legacy engine path receives.
    private func selectProofType(proofTypesSupported: [String: AnyCodable]?, proofTypeHint: String?) -> String {
        if let supported = proofTypesSupported, !supported.isEmpty {
            if supported["jwt"] != nil { return "jwt" }
            if supported["attestation"] != nil { return "attestation" }
            return supported.keys.first ?? "jwt"
        }
        if let hint = proofTypeHint, !hint.isEmpty { return hint }
        return "jwt"
    }

    /// Internal counterpart to the wire-format `ProofObject`, additionally
    /// carrying the device key IDs backing an `attestation` proof's
    /// `attested_keys` (in submission order) - `nil` when unavailable (the
    /// self-signed-fallback path doesn't currently expose the keys it
    /// generated internally). See `activeAttestedKeyIds`'s doc comment for
    /// why this ordering matters for per-credential key selection at signing
    /// time.
    // Internal (not private) - see `requestBackendKeyAttestation`'s doc
    // comment on why that function itself is internal for testability; the
    // fallback-keystore-bypass regression test needs to drive `generateProofs`
    // directly, which needs this to be visible to `@testable import` too.
    struct GeneratedProofData {
        var proofType: String
        var jwt: String?
        var attestation: String?
        var attestedKeyIds: [String]?
    }

    // Internal (not private) - see `requestBackendKeyAttestation`'s doc
    // comment on why that function itself is internal for testability.
    struct BackendAttestationResult {
        var jwt: String
        var keyIds: [String]
    }

    /// Generate proofs for a `generate_proof` sign request - shared by both
    /// transports so proof generation (including real backend Key Attestation
    /// with a self-signed fallback) behaves identically regardless of which
    /// transport carried the request.
    // Internal (not private) so `@testable import` can exercise the
    // backend-attestation-fails-so-fall-back-to-self-signed path directly
    // (see `SirosWalletWscdSelectionTests.testFallbackAfterFailedBackendAttestationUsesResolvedKeystoreNotDefault`),
    // matching `requestBackendKeyAttestation`'s existing testability precedent.
    func generateProofs(
        audience: String,
        nonce: String,
        count: Int,
        proofTypesSupported: [String: AnyCodable]?,
        proofTypeHint: String?
    ) async throws -> [GeneratedProofData] {
        let chosen = selectProofType(proofTypesSupported: proofTypesSupported, proofTypeHint: proofTypeHint)
        if chosen == "attestation" {
            let (backendAttestation, effectiveKeystore) = try await requestBackendKeyAttestation(audience: audience, nonce: nonce, count: count)
            let attestationJwt: String
            if let backendAttestation {
                attestationJwt = backendAttestation.jwt
            } else {
                // Must fall back on the SAME resolved keystore
                // `requestBackendKeyAttestation` picked for this call (e.g.
                // a `WscdSelectionPolicy`-resolved plugin), never
                // unconditionally `self.keystore` - otherwise a resolved
                // higher-tier plugin would be silently bypassed on fallback,
                // generating a lower-tier self-signed attestation instead.
                attestationJwt = try await effectiveKeystore.generateKeyAttestation(nonce: nonce, count: count)
            }
            return [GeneratedProofData(
                proofType: "attestation",
                attestation: attestationJwt,
                attestedKeyIds: backendAttestation?.keyIds
            )]
        }
        var proofs: [GeneratedProofData] = []
        for _ in 0..<count {
            let jwt = try await keystore.generateProof(audience: audience, nonce: nonce, freshKey: count > 1)
            proofs.append(GeneratedProofData(proofType: "jwt", jwt: jwt))
        }
        return proofs
    }

    /// Ask go-wallet-backend's real, x5c-chained Key Attestation endpoint
    /// (`POST /wallet-provider/key-attestation/generate`) to attest freshly
    /// generated keys, instead of `KeystoreManager.generateKeyAttestation`'s
    /// self-signed fallback (a bare `jwk` header - cryptographically valid
    /// but no trust anchor a real issuer can validate against).
    ///
    /// Private keys never leave the device: only the public JWKs (from
    /// `KeystoreManager.generateKeypairs`) and security properties are sent -
    /// the backend signs an attestation *over* them with its own,
    /// operator-provisioned x5c-chained key.
    ///
    /// Returns a `nil` result (caller falls back to the self-signed path,
    /// via the `keystore` also returned here - see below) when there's no
    /// backend session, the keystore can't produce raw keypairs, or the
    /// backend doesn't support/expose the endpoint.
    ///
    /// - Returns: the attestation result (`nil` on any failure - see above),
    ///   ALONGSIDE the `KeystoreManager` this call actually resolved and
    ///   used for key generation (`self.keystore` unless
    ///   `WscdSelectionPolicy` picked a different registered plugin for
    ///   this credential type). The caller's self-signed fallback on a
    ///   `nil` result must use THIS keystore, not `self.keystore` again -
    ///   otherwise a resolved higher-tier plugin would be silently bypassed
    ///   on fallback, generating a lower-tier self-signed attestation
    ///   instead.
    /// - Throws: `WscdSelectionError.noEligiblePlugin` or
    ///   `.ambiguousChoiceNotMade` when `config.availableKeystores` is set
    ///   but selection couldn't produce a plugin ID to use - unlike every
    ///   other failure here, these must NOT be swallowed into a nil/
    ///   self-signed fallback, since that fallback would just use an
    ///   equally (or more) insufficient plugin (see `WscdSelectionPolicy`'s
    ///   doc comment).
    // Internal (not private) so `@testable import` can exercise the WSCD
    // plugin-selection wiring directly (see `SirosWalletWscdSelectionTests`),
    // matching this file's existing precedent for other testable internals.
    func requestBackendKeyAttestation(audience: String, nonce: String, count: Int) async throws -> (result: BackendAttestationResult?, keystore: KeystoreManager) {
        lock.lock(); let client = apiClient; lock.unlock()

        // Pick which registered keystore backs this batch's key generation -
        // a no-op (stays `self.keystore`) unless the host app opted in via
        // `config.availableKeystores`. This can throw `noEligiblePlugin`/
        // `.ambiguousChoiceNotMade`; that's allowed to propagate past this
        // function's own catch-all below (see the doc comment above).
        // Resolved BEFORE the `client` guard so a `nil` "no backend session"
        // return still carries the correctly-resolved keystore for the
        // caller's fallback, rather than always `self.keystore`.
        var effectiveKeystore = keystore
        if let availableKeystores = config.availableKeystores {
            lock.lock()
            let credentialType = activeVctm?.vct ?? activeMddlSchema?.doctype ?? activeOffer?.credentialConfigurationId ?? ""
            let requiredTier = activeVctm?.requiredKeyStorage ?? activeMddlSchema?.requiredKeyStorage
            lock.unlock()
            if let pluginId = try await wscdSelectionPolicy.resolve(
                issuer: audience,
                credentialType: credentialType,
                requiredTier: requiredTier,
                availablePluginIds: Array(availableKeystores.keys)
            ), let picked = availableKeystores[pluginId] {
                effectiveKeystore = picked
            }
        }

        guard let client else { return (nil, effectiveKeystore) }

        do {
            let keypairs = try await effectiveKeystore.generateKeypairs(count: count)
            await registerFido2AttestationsForBatch(keypairs: keypairs, client: client, keystore: effectiveKeystore)
            var secDict: [String: Any]?
            if let keyId = keypairs.first?.keyId, let props = await effectiveKeystore.securityProperties(keyId: keyId) {
                secDict = [
                    "key_storage": props.keyStorage,
                    "user_authentication": props.userAuthentication,
                    "certification": props.certification.toJsonValue(),
                ]
            }
            let jwt = try await client.requestKeyAttestation(
                jwks: keypairs.map { $0.publicKeyJWK },
                nonce: nonce,
                securityProperties: secDict,
                credentialIssuer: audience.isEmpty ? nil : audience,
                walletInstanceId: currentWalletInstanceId()
            )
            // keypairs[i]'s key is exactly attested_keys[i] in the JWT just
            // built (jwks preserves list order) - the issuer is expected to
            // mint credential i in the eventual batch response bound to
            // attested_keys[i], so this ordering IS the instanceId -> kid
            // mapping the credential-storage handler needs later.
            return (BackendAttestationResult(jwt: jwt, keyIds: keypairs.map { $0.keyId }), effectiveKeystore)
        } catch {
            return (nil, effectiveKeystore)
        }
    }

    /// Register each freshly-generated credential key's FIDO2/CTAP2 hardware
    /// attestation with the backend, keyed by that specific key - NOT the
    /// wallet's own identity key (see go-wallet-backend's `KeyAttestationStore`
    /// doc for why this must be per-credential-key: the identity key and
    /// credential-issuance keys are separate keys, not guaranteed to share a
    /// WSCD plugin, so registering only the identity key's attestation would
    /// incorrectly leave the actual credential keys - the ones a KA request's
    /// `attested_keys`/`security_properties` claim is really about -
    /// unattested).
    ///
    /// A no-op per key when `keystore`'s active plugin isn't hardware-backed
    /// (`attestationChain` returns nil for those - most commonly the whole
    /// batch, since `generateKeypairs` uses whichever single plugin is
    /// currently active for every key in one call). Best-effort per key: a
    /// registration failure for one key must never block the others, or the
    /// overall KA request that follows - it's simply retried the next time a
    /// fresh batch happens to reuse the same plugin (there's no "already
    /// registered" dedup here, unlike the old identity-key path: these keys
    /// are one-shot, used once for this batch, so there's nothing to dedupe
    /// against).
    ///
    /// Requires a cached WIA to supply `wallet_instance_id` for the
    /// registration record's auditing/scoping - peeks `cachedWia` directly
    /// (any `attestation_source`, not gated to native platform attestation
    /// like `currentWalletInstanceId` - that gate is specifically about the
    /// KA security_properties clamp-lift, unrelated to this). No cached WIA
    /// means nothing to register against, so this is a no-op entirely.
    /// - Parameter keystore: the keystore that actually generated
    ///   `keypairs` - `requestBackendKeyAttestation` may have swapped in a
    ///   registered plugin other than `self.keystore` for this batch (see
    ///   `WscdSelectionPolicy`), so this must NOT assume `self.keystore`.
    private func registerFido2AttestationsForBatch(keypairs: [KeypairInfo], client: BackendApiClient, keystore: KeystoreManager) async {
        let now = Int(Date().timeIntervalSince1970)
        lock.lock(); let wia = cachedWia; let expiresAt = cachedWiaExpiresAt; lock.unlock()
        guard let wia, expiresAt - now > 60,
              let cnf = CredentialUtils.parseJwtPayload(wia)?["cnf"] as? [String: Any],
              let walletInstanceId = cnf["jkt"] as? String else { return }
        for kp in keypairs {
            guard let chain = try? await keystore.attestationChain(keyId: kp.keyId),
                  let attestationObject = chain.certificates.first else { continue }
            do {
                try await client.registerFido2Attestation(
                    walletInstanceId: walletInstanceId,
                    attestationObject: attestationObject,
                    clientDataHash: chain.clientDataHash
                )
            } catch {
                #if canImport(os)
                logger.warning("FIDO2 attestation registration failed for key \(kp.keyId), continuing: \(error.localizedDescription)")
                #endif
            }
        }
    }

    private func handleWmpSignRequest(flowId: String, params: SignSubFlowParams) async throws -> SignSubFlowResult {
        switch params.action {
        case "generate_proof":
            let count = params.count ?? 1
            let generated = try await generateProofs(
                audience: params.audience,
                nonce: params.nonce,
                count: count,
                proofTypesSupported: nil,
                proofTypeHint: params.proofType
            )
            lock.lock(); activeAttestedKeyIds = generated.first(where: { $0.attestedKeyIds != nil })?.attestedKeyIds; lock.unlock()
            let proofs = generated.map { ProofObject(proofType: $0.proofType, jwt: $0.jwt, attestation: $0.attestation) }
            return SignSubFlowResult(proofs: proofs)

        case "sign_presentation":
            // Same defense-in-depth audience check as the legacy engine
            // transport's handleSignRequest - this transport previously
            // skipped it entirely, so a WMP-relayed sign_presentation was
            // never checked against the trust result computed for this flow.
            try validateAudience(flowId: flowId, audience: params.audience)
            let vpToken = try await keystore.signPresentation(
                nonce: params.nonce,
                audience: params.audience,
                credentialIds: [],
                kid: nil
            )
            return SignSubFlowResult(vpToken: vpToken)

        default:
            throw SirosError.auth(message: "Unknown sign action: \(params.action)")
        }
    }

    private func handleWmpMatchRequest(flowId: String, payload: AnyCodable?) async -> MatchResult {
        let allCreds = await credentialStore.getAll()
        // Only offer instances the active consumption policy still considers
        // usable - mirrors the legacy engine path's handleMatchRequest (and
        // Kotlin's matchRequests() collector) so a credential exhausted under
        // CONSUME_ALL/CONSUME_NON_ZKP can't be matched into a new
        // presentation via this transport either.
        let eligibleCreds = CredentialUtils.eligibleInstances(
            instances: allCreds,
            policy: credentialConsumptionPolicy,
            presentationHistory: presentationHistory
        )
        let matches = eligibleCreds.map { cred in
            // credentialId is the WMP wire-protocol identifier - a separate,
            // unverified backend contract distinct from privatedata-spec's
            // numeric StoredCredential.id, so it deliberately stays String.
            CredentialMatch(
                credentialQueryId: nil,
                credentialId: String(cred.id),
                format: cred.format,
                vct: cred.metadata?.vct,
                availableClaims: nil
            )
        }
        return MatchResult(matches: matches)
    }

    private func handleWmpTrustEvaluation(flowId: String, payload: AnyCodable?) async -> SirosTransport.TrustResult {
        // Extract subject_id from the payload
        guard case .object_(let payloadDict) = payload,
              case .object_(let request) = payloadDict["request"],
              case .string(let subjectId) = request["subject_id"],
              !subjectId.isEmpty else {
            return SirosTransport.TrustResult(trusted: false, reason: "Missing subject_id")
        }

        lock.lock(); let client = apiClient; lock.unlock()
        guard let client else {
            return SirosTransport.TrustResult(trusted: false, reason: "No API client")
        }

        // WMP carries both issuance (generate_proof) and presentation
        // (sign_presentation) sign requests over the same profile - the
        // action name must follow subject_type like the legacy engine path's
        // handleTrustEvaluation does, not be hardcoded to "credential-issuer"
        // for every subject (a real bug: a verifier evaluated over WMP was
        // being checked against the issuer trust policy instead of the
        // verifier one).
        var subjectType: String?
        if case .string(let t) = request["subject_type"] {
            subjectType = t
        }
        let actionName = subjectType == "credential_verifier" ? "credential-verifier" : "credential-issuer"

        do {
            let kmType: String
            if case .object_(let km) = request["key_material"],
               case .string(let t) = km["type"] {
                kmType = t
            } else {
                kmType = "x5c"
            }

            let evaluationRequest: [String: Any] = [
                "subject": ["type": "key", "id": subjectId],
                "resource": ["type": kmType, "id": subjectId],
                "action": ["name": actionName],
            ]
            let response = try await client.evaluateTrust(evaluationRequest)
            let decision = response["decision"] as? Bool ?? false
            let context = response["context"] as? [String: Any]

            // Store for the later sign_presentation step's validateAudience
            // check, mirroring handleTrustEvaluation - without this, WMP
            // presentations had no audience-binding defense-in-depth at all.
            lock.lock()
            lastTrustResults[flowId] = TrustResult(
                trusted: decision,
                framework: context?["framework"] as? String,
                reason: (context?["reason"] as? String) ?? (context?["message"] as? String),
                entityName: context?["entity_name"] as? String,
                entityLogo: context?["logo_uri"] as? String,
                identifier: subjectId
            )
            lock.unlock()

            return SirosTransport.TrustResult(trusted: decision)
        } catch {
            return SirosTransport.TrustResult(trusted: false, reason: error.localizedDescription)
        }
    }

    // MARK: - Legacy Engine Path

    func connectEngine(appToken: String) async throws {
        // Resolve engine base URL: explicit config > discovery > same as backend
        let engineBase: String
        if !config.engineUrl.isEmpty {
            engineBase = config.engineUrl
        } else if let discovered = await WalletConfig.discoverEngineUrl(backendUrl: config.backendUrl) {
            engineBase = discovered
        } else {
            engineBase = config.backendUrl
        }
        let engine = Self.createEngineSession(engineBase, config.tenantId)
        lock.lock(); engineSession = engine; credentialNotifier = engine; lock.unlock()
        engine.connect(appToken: appToken) { [weak self] in
            guard let tokens = self?.authTokens else {
                throw SirosError.wallet(message: "Not connected")
            }
            return try await tokens.ensureBackendToken().raw
        }
        try await engine.awaitConnected()

        // Catches WalletEngineSession.State.reauthRequired transitions from
        // the automatic background reconnect loop, which never goes through
        // awaitConnected - cancelled alongside every other engine task on
        // logout (see cancelEngineTasks).
        let reauthTask = Task { [weak self] in
            for await state in engine.stateStream where state == .reauthRequired {
                self?.handleReauthenticationRequired()
            }
        }

        // Sign requests → auto-sign with keystore
        let signTask = Task { [weak self] in
            guard let self else { return }
            for await msg in engine.signRequests() {
                await self.handleSignRequest(engine: engine, msg: msg)
            }
        }
        // Match requests → credential matching
        let matchTask = Task { [weak self] in
            guard let self else { return }
            for await msg in engine.matchRequests() {
                await self.handleMatchRequest(engine: engine, msg: msg)
            }
        }
        // Flow progress
        let progressTask = Task { [weak self] in
            guard let self else { return }
            for await msg in engine.flowProgress() {
                await self.handleFlowProgress(engine: engine, msg: msg)
            }
        }
        // Flow complete
        let completeTask = Task { [weak self] in
            guard let self else { return }
            for await msg in engine.flowComplete() {
                await self.handleFlowComplete(msg: msg)
            }
        }
        // Flow errors
        let errorTask = Task { [weak self] in
            guard let self else { return }
            for await msg in engine.flowErrors() {
                self.handleFlowError(msg: msg)
            }
        }
        engineTasks = [signTask, matchTask, progressTask, completeTask, errorTask, reauthTask]
    }

    private func handleSignRequest(engine: WalletEngineSession, msg: SignRequestMessage) async {
        do {
            switch msg.action {
            case "generate_proof":
                let count = msg.params.count ?? 1
                let generated = try await generateProofs(
                    audience: msg.params.audience ?? "",
                    nonce: msg.params.nonce ?? "",
                    count: count,
                    proofTypesSupported: msg.params.proofTypesSupported,
                    proofTypeHint: msg.params.proofType
                )
                lock.lock(); activeAttestedKeyIds = generated.first(where: { $0.attestedKeyIds != nil })?.attestedKeyIds; lock.unlock()
                let proofs = generated.map { ProofObject(proofType: $0.proofType, jwt: $0.jwt, attestation: $0.attestation) }
                engine.sendSignResponse(flowId: msg.flowId, proofs: proofs, messageId: msg.messageId)

            case "sign_presentation":
                let nonce = msg.params.nonce ?? ""
                let audience = msg.params.audience ?? ""
                let credsToInclude = msg.params.credentialsToInclude

                // Validate audience matches trusted verifier identity
                try validateAudience(flowId: msg.flowId, audience: audience)

                if let credsToInclude, !credsToInclude.isEmpty {
                    let allCreds = await credentialStore.getAll()
                    var vpParts: [String] = []
                    for ref in credsToInclude {
                        // ref.credentialId is the WMP wire-protocol identifier
                        // (String) - parse it back to the numeric
                        // StoredCredential.id it refers to.
                        guard let cred = allCreds.first(where: { $0.id == Int64(ref.credentialId) }) else { continue }

                        if cred.format == "mso_mdoc" {
                            // mDoc DeviceResponse (ISO 18013-5)
                            guard let credBytes = Self.b64UrlDecode(cred.raw) else {
                                throw SirosError.wallet(message: "Credential \(cred.id) has malformed base64url raw data")
                            }
                            let deviceResponse = try await keystore.signMdocPresentation(
                                credentialBytes: credBytes,
                                disclosedClaims: ref.disclosedClaims,
                                nonce: nonce,
                                audience: audience,
                                responseUri: msg.params.responseUri ?? "",
                                verifierJwkThumbprint: msg.params.verifierJwkThumbprint,
                                kid: cred.kid
                            )
                            vpParts.append(deviceResponse.base64EncodedString()
                                .replacingOccurrences(of: "+", with: "-")
                                .replacingOccurrences(of: "/", with: "_")
                                .replacingOccurrences(of: "=", with: "")
                            )
                        } else {
                            // SD-JWT VP token with KB-JWT
                            let vp = try await keystore.signVpToken(
                                credential: cred.raw,
                                disclosedClaims: ref.disclosedClaims,
                                nonce: nonce,
                                audience: audience,
                                kid: cred.kid
                            )
                            vpParts.append(vp)
                        }
                    }
                    let vpToken = vpParts.joined(separator: "\n")
                    engine.sendSignResponse(flowId: msg.flowId, vpToken: vpToken, messageId: msg.messageId)
                } else {
                    let vpToken = try await keystore.signPresentation(
                        nonce: nonce, audience: audience, credentialIds: [], kid: nil
                    )
                    engine.sendSignResponse(flowId: msg.flowId, vpToken: vpToken, messageId: msg.messageId)
                }

            default:
                break
            }
        } catch {
            #if canImport(os)
            logger.error("Error handling sign request: \(error.localizedDescription)")
            #endif
            reportSignFailure(flowId: msg.flowId, message: error.localizedDescription)
        }
    }

    private func handleMatchRequest(engine: WalletEngineSession, msg: MatchRequestMessage) async {
        let allCreds = await credentialStore.getAll()
        lock.lock()
        let listener = eventListener
        // Read only - do NOT remove. The later `sign_presentation` step
        // (`handleSignRequest` -> `validateAudience`) still needs this
        // entry; credential selection (this handler) always runs before
        // signing in the engine's own step ordering, so removing it here
        // silently defeated `validateAudience`'s defense-in-depth check for
        // every presentation - it always saw a nil trust result and
        // no-op'd. `validateAudience` itself removes the entry once it's
        // actually consumed.
        let trustResult = lastTrustResults[msg.flowId]
        lock.unlock()

        let selectedIds: [Int64]
        if let listener, !allCreds.isEmpty {
            selectedIds = await listener.onCredentialSelectionRequired(
                request: PresentationRequest(
                    verifierName: trustResult?.entityName,
                    trustResult: trustResult,
                    candidates: allCreds
                )
            )
        } else {
            selectedIds = CredentialUtils.eligibleInstances(
                instances: allCreds,
                policy: credentialConsumptionPolicy,
                presentationHistory: presentationHistory
            ).map(\.id)
        }

        // The app is trusted to only return IDs it was offered, but shouldn't
        // be the only thing enforcing consumption - re-validate here too
        // (defense in depth).
        let eligibleIds = Set(CredentialUtils.eligibleInstances(
            instances: allCreds,
            policy: credentialConsumptionPolicy,
            presentationHistory: presentationHistory
        ).map(\.id))
        guard selectedIds.allSatisfy({ eligibleIds.contains($0) }) else {
            #if canImport(os)
            logger.error("Selected credential has no eligible copies remaining")
            #endif
            return
        }

        await recordPresentation(PresentationRecord(
            id: randomUint32Id(),
            flowId: msg.flowId,
            credentialIds: selectedIds,
            credentialNames: selectedIds.compactMap { id in
                allCreds.first(where: { $0.id == id })?.metadata?.name
            },
            timestamp: Int64(Date().timeIntervalSince1970 * 1000)
        ))

        let matches: [CredentialMatch] = selectedIds.compactMap { id in
            guard let cred = allCreds.first(where: { $0.id == id }) else { return nil }
            // credentialId is the legacy engine wire-protocol identifier - a
            // separate, unverified backend contract distinct from
            // privatedata-spec's numeric StoredCredential.id, so it
            // deliberately stays String.
            return CredentialMatch(
                credentialId: String(cred.id),
                format: cred.format,
                vct: cred.metadata?.vct
            )
        }
        engine.sendMatchResponse(flowId: msg.flowId, matches: matches)
    }

    private func handleFlowProgress(engine: WalletEngineSession, msg: FlowProgressMessage) async {
        let payloadDict = msg.payload?.objectValue

        // Handle trust evaluation
        if msg.step == "evaluating_trust" || msg.step == "evaluating_verifier_trust" {
            if let payloadDict,
               payloadDict["trust_evaluation_required"]?.boolValue == true {
                let payload = anyCodableDictToAny(payloadDict)
                await handleTrustEvaluation(engine: engine, flowId: msg.flowId, payload: payload)
            }
        }

        // Handle server-side issuer trust result (informational, no response needed).
        // The engine sends step="trust_evaluated" with payload.issuer_trust_evaluated=true.
        // This is distinct from the verifier trust flow — it does NOT overwrite
        // lastTrustResults (which is used for credential selection consent UI).
        if msg.step == "trust_evaluated",
           let payloadDict,
           payloadDict["issuer_trust_evaluated"]?.boolValue == true {
            let trustResult = TrustResult(
                trusted: payloadDict["trusted"]?.boolValue ?? false,
                framework: payloadDict["framework"]?.stringValue,
                reason: payloadDict["reason"]?.stringValue,
                identifier: payloadDict["issuer"]?.stringValue
            )
            // Only populate the trust cache — do NOT store in lastTrustResults
            // (that map is for verifier consent UI in handleMatchRequest)
            trustCache.put(identifier: trustResult.identifier ?? "", result: trustResult)
        }

        // Handle authorization required
        if msg.step == "authorization_required" {
            if let payloadDict {
                let payloadType = payloadDict["type"]?.stringValue
                if payloadType == "tx_code" {
                    lock.lock(); let listener = eventListener; lock.unlock()
                    if let txCode = listener?.onTxCodeRequired(
                        flowId: msg.flowId,
                        description: payloadDict["message"]?.stringValue
                    ) {
                        engine.sendFlowAction(
                            flowId: msg.flowId,
                            action: "provide_pin",
                            payload: ["tx_code": .string(txCode)]
                        )
                    }
                } else {
                    if let authUrl = payloadDict["authorization_url"]?.stringValue {
                        let redirectUri = payloadDict["expected_redirect_uri"]?.stringValue ?? ""
                        let effectiveState = payloadDict["state"]?.stringValue
                            ?? URLComponents(string: authUrl)?.queryItems?.first(where: { $0.name == "state" })?.value
                            ?? ""

                        // Capture enough context to resume issuance via a fresh
                        // flow_start once the OAuth redirect returns - the
                        // original flow_id's WebSocket context may not survive
                        // the browser round-trip. See completeAuthorization.
                        let pending = PendingAuthorization(
                            offer: payloadDict["credential_offer"]?.stringValue,
                            credentialOfferUri: payloadDict["credential_offer_uri"]?.stringValue,
                            redirectUri: redirectUri,
                            codeVerifier: payloadDict["code_verifier"]?.stringValue,
                            state: effectiveState
                        )
                        lock.lock()
                        pendingAuthorizations[msg.flowId] = pending
                        lock.unlock()

                        let rewrittenUrl = config.urlRewriter?(authUrl) ?? authUrl
                        lock.lock(); let listener = eventListener; lock.unlock()
                        listener?.onAuthorizationRequired(
                            flowId: msg.flowId,
                            authorizationUrl: rewrittenUrl,
                            redirectUri: redirectUri,
                            state: effectiveState
                        )
                    }
                }
            }
        }

        // Transition to FlowActive state
        switch state {
        case .ready(let userId, let displayName, let creds, _),
             .flowActive(let userId, let displayName, _, _, _, let creds):
            setState(.flowActive(
                userId: userId,
                displayName: displayName,
                flowId: msg.flowId,
                flowType: msg.step,
                status: msg.step,
                credentials: creds
            ))
        default:
            break
        }
    }

    /// Validates that the audience for VP signing matches the trusted verifier identity.
    ///
    /// Throws (rather than merely logging) on mismatch - confirmed the same
    /// gap exists in the Kotlin SDK's own validateAudience, found via code
    /// review: a mismatch was only ever printed as a warning, so
    /// handleSignRequest proceeded to sign and send the VP token regardless,
    /// defeating the audience-binding protection this function's name
    /// implies it provides.
    private func validateAudience(flowId: String, audience: String) throws {
        lock.lock()
        // Consume (remove) the entry here, at actual point of use, instead
        // of at credential-selection time - see `handleMatchRequest`'s
        // comment for why removing it earlier defeated this check entirely.
        let trustResult = lastTrustResults.removeValue(forKey: flowId)
        lock.unlock()

        guard let trustResult, let expectedId = trustResult.identifier else { return }
        if !audience.isEmpty && !expectedId.isEmpty && audience != expectedId {
            throw SirosError.wallet(message: "Audience mismatch for flow \(flowId): sign_request audience='\(audience)' != trusted identifier='\(expectedId)'")
        }
    }

    func handleTrustEvaluation(engine: WalletEngineSession, flowId: String, payload: [String: Any]) async {
        guard let request = payload["request"] as? [String: Any],
              let subjectId = request["subject_id"] as? String, !subjectId.isEmpty else {
            engine.sendTrustResult(flowId: flowId, trusted: false, reason: "Missing subject_id")
            return
        }

        let subjectType = request["subject_type"] as? String
        let keyMaterial = request["key_material"] as? [String: Any]
        let kmType = keyMaterial?["type"] as? String ?? "x5c"

        var resource: [String: Any] = [
            "type": kmType,
            "id": subjectId,
        ]
        if let x5c = keyMaterial?["x5c"] {
            resource["key"] = x5c
        } else if let jwk = keyMaterial?["jwk"] {
            resource["key"] = [jwk]
        }

        let actionName = subjectType == "credential_verifier" ? "credential-verifier" : "credential-issuer"

        var evaluationRequest: [String: Any] = [
            "subject": ["type": "key", "id": subjectId],
            "resource": resource,
            "action": ["name": actionName],
        ]
        if let ctx = request["context"] {
            evaluationRequest["context"] = ctx
        }

        lock.lock(); let client = apiClient; lock.unlock()
        guard let client else {
            engine.sendTrustResult(flowId: flowId, trusted: false, reason: "No API client")
            return
        }
        do {
            let response = try await client.evaluateTrust(evaluationRequest)
            let decision = response["decision"] as? Bool ?? false
            let context = response["context"] as? [String: Any]
            let reqContext = request["context"] as? [String: Any]

            // Build typed TrustResult from the PDP response
            let trustResult = TrustResult(
                trusted: decision,
                framework: context?["framework"] as? String,
                reason: (context?["reason"] as? String)
                    ?? (context?["message"] as? String)
                    ?? context?["reason"].map { String(describing: $0) },
                entityName: context?["entity_name"] as? String,
                entityLogo: context?["logo_uri"] as? String,
                clientIdScheme: reqContext?["client_id_scheme"] as? String,
                identifier: subjectId,
                domain: context?["domain"] as? String
            )

            // Store for use in credential selection UI
            lock.lock()
            lastTrustResults[flowId] = trustResult
            lock.unlock()

            // Populate trust cache (only positive results are stored)
            trustCache.put(identifier: subjectId, result: trustResult)

            engine.sendTrustResult(flowId: flowId, trusted: decision)
        } catch {
            // Degraded mode: check cache for a recent positive result
            if let cached = trustCache.get(identifier: subjectId) {
                print("[SirosWallet] ⚠️ Using cached trust result for \(subjectId) (backend unreachable)")
                lock.lock()
                lastTrustResults[flowId] = cached
                lock.unlock()
                engine.sendTrustResult(flowId: flowId, trusted: true)
            } else {
                engine.sendTrustResult(flowId: flowId, trusted: false, reason: error.localizedDescription)
            }
        }
    }

    /// Report a flow-terminating failure immediately (e.g. a keystore/WSCD
    /// exception, or an audience-mismatch, raised while handling a sign
    /// request) instead of leaving the flow to die silently until the
    /// engine's own reply timeout fires.
    ///
    /// Mirrors the Kotlin SDK's reportSignFailure, added after the same real
    /// FIDO2 CTAP2_ERR_PIN_INVALID bug was found via live hardware testing:
    /// handleSignRequest's catch block previously only logged
    /// (logger.error), so the engine waited indefinitely for a sign_response
    /// that would never arrive.
    private func reportSignFailure(flowId: String, message: String) {
        lock.lock(); let listener = eventListener; lock.unlock()
        listener?.onFlowError(flowId: flowId, errorMessage: message)

        // A terminal path for whatever issuance may have been in flight - a
        // no-op for a presentation sign-request failure, which never sets
        // these fields in the first place. See `resetIssuanceGuards()`.
        resetIssuanceGuards()

        switch state {
        case .flowActive(let userId, let displayName, _, _, _, _),
             .ready(let userId, let displayName, _, _):
            Task {
                let creds = await credentialStore.getAll()
                setState(.ready(userId: userId, displayName: displayName, credentials: creds))
            }
        default:
            break
        }
    }

    private func handleFlowError(msg: FlowErrorMessage) {
        let fid = msg.flowId ?? "unknown"
        lock.lock(); let listener = eventListener; lock.unlock()
        listener?.onFlowError(flowId: fid, errorMessage: msg.error.message)

        // Terminal path for whatever issuance may have been in flight -
        // a no-op for a presentation flow error, which never sets these
        // fields. See `resetIssuanceGuards()`.
        resetIssuanceGuards()

        switch state {
        case .flowActive(let userId, let displayName, _, _, _, _),
             .ready(let userId, let displayName, _, _):
            Task {
                let creds = await credentialStore.getAll()
                setState(.ready(userId: userId, displayName: displayName, credentials: creds))
            }
        default:
            break
        }
    }

    // MARK: - Base64 helpers

    /// Convert AnyCodable dict to [String: Any] for internal use.
    private func anyCodableDictToAny(_ dict: [String: AnyCodable]?) -> [String: Any] {
        guard let dict else { return [:] }
        var result: [String: Any] = [:]
        for (k, v) in dict { result[k] = anyCodableToAny(v) }
        return result
    }

    private func anyCodableToAny(_ value: AnyCodable) -> Any {
        switch value {
        case .string(let s): return s
        case .int(let i): return i
        case .double(let d): return d
        case .bool(let b): return b
        case .object_(let obj): return anyCodableDictToAny(obj)
        case .array(let arr): return arr.map { anyCodableToAny($0) }
        case .null_: return NSNull()
        }
    }

    static func randomBytes(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBuffer(&bytes, count)
        return Data(bytes)
    }

    static func b64Encode(_ data: Data) -> String {
        data.base64EncodedString()
    }

    static func b64Decode(_ string: String) -> Data? {
        Data(base64Encoded: string)
    }

    static func b64UrlEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func b64UrlDecode(_ string: String) -> Data? {
        var s = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        return Data(base64Encoded: s)
    }

    /// Cross-platform secure random bytes.
    // swiftlint:disable:next identifier_name
    private static func SecRandomCopyBuffer(_ buffer: inout [UInt8], _ count: Int) -> Int32 {
        #if canImport(Security)
        return SecRandomCopyBytes(kSecRandomDefault, count, &buffer)
        #else
        // Linux fallback
        guard let f = fopen("/dev/urandom", "r") else { return -1 }
        let read = fread(&buffer, 1, count, f)
        fclose(f)
        return read == count ? 0 : -1
        #endif
    }
}

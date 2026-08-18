// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
@preconcurrency import SwiftCBOR
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
// Not `private`: `SirosWallet+Engine.swift`'s `connectEngine` needs it too -
// same cross-file-extension-access reason as `keystore` above.
struct PendingAuthorization: Sendable {
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
    // Not `private`: `setState` (in `SirosWallet+Lifecycle.swift`, a
    // separate file, same module) needs it too - Swift's `private` is
    // file-scoped, not module-scoped, matching this file's existing
    // `keystore`/`activeOffer` etc. convention.
    var _state: WalletState = .disconnected()
    var stateContinuations: [String: AsyncStream<WalletState>.Continuation] = [:]

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

    // Not `private`: `SirosWallet+Issuance.swift`, `SirosWallet+Lifecycle.swift`
    // and `SirosWallet+Engine.swift` (separate files, same module) need it
    // too - same cross-file-extension-access reason as `keystore` above.
    let config: WalletConfig
    // Not `private`: `SirosWallet+Lifecycle.swift` needs it too - same
    // cross-file-extension-access reason as `keystore` above.
    let authProvider: AuthProvider
    // Not `private`: `SirosWallet+Issuance.swift` and
    // `SirosWallet+Lifecycle.swift` need it too - same cross-file-
    // extension-access reason as `keystore` above.
    let sessionStore: SessionStoreProtocol
    // Not `private`: `SirosWallet+Renewal.swift` (a separate file, same
    // module) needs it too - Swift's `private` is file-scoped, not
    // module-scoped, matching this file's existing `activeOffer` etc.
    // convention.
    let keystore: KeystoreManager

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

    /// A hardware-backed WSCD plugin's persisted key metadata, synced via
    /// privatedata (see `WscdKeystoreAdapter.exportWscdCredentialsState`'s
    /// doc comment) - `nil` before any key has ever been exported for this
    /// plugin. The host app should pass this to
    /// `WscdManager.registerFido2PluginWithState` instead of
    /// `WscdManager.registerFido2Plugin` whenever it's non-nil, so a key
    /// enrolled on ANY device sharing this account - not just the one that
    /// originally enrolled it - stays addressable. Deliberately NOT backed by
    /// device-local storage: CTAP2 roaming authenticators (e.g. a YubiKey)
    /// are enrolled once but usable from any device.
    public func wscdCredentials(pluginId: String) async -> String? {
        #if canImport(CryptoKit)
        guard let adapter = keystore as? WscdKeystoreAdapter else { return nil }
        return await adapter.exportWscdCredentialsState()[pluginId]
        #else
        // `WscdKeystoreAdapter` is only defined where CryptoKit is
        // available (see its `#if canImport(CryptoKit)` guard) - on other
        // platforms there's no WSCD-backed keystore to read state from.
        return nil
        #endif
    }

    /// Record a WSCD plugin's freshly-exported key metadata (see
    /// `WscdManager.exportFido2State`) and sync it to the backend, so it
    /// survives to the next `wscdCredentials` call on any device sharing
    /// this account. Call after every enrollment/key-generation that could
    /// have changed the plugin's state.
    public func saveWscdCredentials(pluginId: String, state: String) async {
        #if canImport(CryptoKit)
        if let adapter = keystore as? WscdKeystoreAdapter {
            await adapter.setWscdCredentialsState(pluginId: pluginId, state: state)
        }
        #endif
        await persistAndSyncKeystore()
    }

    /// Exposes `authProvider` as a `WscdAutoEnrollHint` when it implements
    /// one - `nil` otherwise (e.g. a host-supplied `AuthProvider` that
    /// doesn't). Intended use: right after a successful `login()`, the host
    /// app checks `wscdAutoEnrollHint()?.suggestsWscdCapableDevice()` to
    /// decide whether to offer enrolling the just-used login credential as a
    /// WSCD signing device - see that protocol's doc comment for why this is
    /// a hint requiring a real (offered, not automatic) enrollment attempt to
    /// confirm, not a guarantee.
    public func wscdAutoEnrollHint() -> WscdAutoEnrollHint? {
        authProvider as? WscdAutoEnrollHint
    }

    // exportCredentialRefreshTokens/setCredentialRefreshToken/
    // removeCredentialRefreshToken (credential re-issuance/renewal plan,
    // Phase 2) now live in SirosWallet+Renewal.swift, alongside the rest of
    // that plan's logic - see this file's `keystore` doc comment for why
    // `keystore` itself had to stay internal (not private).

    let credentialStore: CredentialStore
    // Not `private`: `SirosWallet+Issuance.swift` needs it too - same
    // cross-file-extension-access reason as `keystore` above.
    let vctmFetcher: VctmFetcher
    let mddlSchemaFetcher: MddlSchemaFetcher
    private let accountRegistry: AccountRegistry

    /// Client for go-zk-circuits' `/v1` REST API, built from
    /// `config.zkCircuitUrls`. Feeds `zkProofSystemRegistry` below.
    public let zkCircuitClient: ZkCircuitClient

    /// Registered ZK proof systems, resolved against a verifier's
    /// `zk_system_type` request in `handleDCAPIRequest`/`handleSignRequest`'s
    /// ZK branches. Empty on non-iOS platforms - `LongfellowZkProofSystem`
    /// wraps the `zk-cred-longfellow` native XCFramework, which only ships
    /// iOS slices (see that type's own `#if os(iOS)` gating) - so a ZK
    /// request simply finds no matching system there, the same "unsupported"
    /// outcome as any other unregistered proof system.
    public let zkProofSystemRegistry: ZkProofSystemRegistry

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
    // Not `private`: `SirosWallet+Engine.swift` needs it too - same
    // cross-file-extension-access reason as `keystore` above.
    let wscdSelectionPolicy: WscdSelectionPolicy
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
    /// When set, the next `flow_complete` is a renewal's - see
    /// `renewCredential`/`SirosWallet+Notifications.swift`'s `handleFlowComplete`.
    /// Not `private` for the same cross-file-extension-access reason as
    /// `activeOffer` etc. above; guarded by the same `lock`.
    var pendingRenewalSourceBatchId: Int64?
    // Not `private`: `SirosWallet+Lifecycle.swift` and
    // `SirosWallet+Engine.swift` need it too - same cross-file-extension-
    // access reason as `keystore` above.
    var engineTasks: [Task<Void, Never>] = []
    private var _presentationHistory: [PresentationRecord] = []
    /// Stores trust evaluation results keyed by flow ID for use in credential selection UI.
    // Not `private`: `SirosWallet+Engine.swift` needs it too - same
    // cross-file-extension-access reason as `keystore` above.
    var lastTrustResults: [String: TrustResult] = [:]
    /// Cached per-flow-id DCQL match results from whichever credential-
    /// matching step actually ran for that flow (`handleCredentialSelection`'s
    /// `"credential_selection"` flow_progress step - the real, live path for
    /// redirect-flow/haip-vp:// presentations - or the legacy engine's own
    /// `handleMatchRequest`). The later `sign_presentation` sign_request step
    /// (`handleSignRequest`) needs this to know the originating query's
    /// `format`/`zkSystemTypes`/`ppidContext` per credential, since its own
    /// `credentials_to_include` wire shape doesn't carry that back. Mirrors
    /// Kotlin's `pendingMatchResultsByFlow` exactly. Entries are removed once
    /// consumed by `handleSignRequest`, or when the flow terminates (see
    /// `handleFlowComplete`/`handleFlowError`/`reportSignFailure`).
    ///
    /// Not `private` - `handleFlowComplete` (in `SirosWallet+Notifications.swift`)
    /// needs to clear it too, the same cross-file-extension-access reason as
    /// `activeOffer`/`activeAttestedKeyIds` etc. above; guarded by the same `lock`.
    var pendingMatchResultsByFlow: [String: [CredentialMatcher.MatchResult]] = [:]
    /// Authorization context captured from a flow's `authorization_required`
    /// progress message, keyed by flow ID - needed to resume issuance via a
    /// fresh `flow_start` once the OAuth browser redirect returns, since the
    /// original flow_id's WebSocket context isn't guaranteed to survive the
    /// round-trip. See `completeAuthorization`.
    // Not `private`: `SirosWallet+Lifecycle.swift` and
    // `SirosWallet+Engine.swift` need it too - same cross-file-extension-
    // access reason as `keystore` above.
    var pendingAuthorizations: [String: PendingAuthorization] = [:]
    /// Persistent trust cache for degraded-mode operation.
    // Not `private`: `SirosWallet+DCAPI.swift` and `SirosWallet+Engine.swift`
    // need it too - same cross-file-extension-access reason as `keystore`
    // above.
    let trustCache = TrustCache()

    // New AS-based auth
    private var authServerClient: AuthServerClient?
    // Not `private`: `SirosWallet+Lifecycle.swift` and
    // `SirosWallet+Engine.swift` need it too - same cross-file-extension-
    // access reason as `keystore` above.
    var authTokens: AuthTokens?

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

    // Not `private`: `SirosWallet+Engine.swift`'s `connectViaWmp` needs it
    // too - same cross-file-extension-access reason as `keystore` above.
    var wmpPeer: WmpPeer?

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
    // Not `private`: `SirosWallet+DCAPI.swift` and `SirosWallet+Engine.swift`
    // need it too - same cross-file-extension-access reason as `keystore`
    // above.
    func recordPresentation(_ record: PresentationRecord) async {
        lock.lock(); _presentationHistory.insert(record, at: 0); lock.unlock()
        if keystore.isUnlocked {
            if let data = try? JSONEncoder().encode(record), let raw = String(data: data, encoding: .utf8) {
                try? await keystore.savePresentationRecord(id: record.id, json: raw)
                await persistAndSyncKeystore()
            }
        }
        await checkRenewThresholds(consumedCredentialIds: record.credentialIds)
    }

    /// Per-credential-configuration-id override for
    /// `CredentialUtils.renewThreshold` (plan §4.3: "near-expiry threshold
    /// is a per-credential user preference," not a global constant). Not
    /// durably persisted in this pass - callers wanting persistence across
    /// restarts should re-set this on wallet construction from their own
    /// settings store, matching how `credentialConsumptionPolicy` itself is
    /// currently handled.
    public var renewThresholds: [String: Int] = [:]
    // `renewThresholdFor`/`checkRenewThresholds` that read this live in
    // `SirosWallet+Renewal.swift` (credential re-issuance/renewal plan,
    // Phase 2) - kept together with the rest of that plan's logic; this
    // stored property itself has to stay here since Swift extensions can't
    // add stored properties to a type.

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
    // Not `private`: `SirosWallet+Lifecycle.swift` needs it too - same
    // cross-file-extension-access reason as `keystore` above.
    static let defaultHttpFn: @Sendable (String, URL, [String: String], Data?) async throws -> Data = { method, url, headers, body in
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
        self.zkCircuitClient = ZkCircuitClient(sources: config.zkCircuitUrls)
        #if os(iOS)
        self.zkProofSystemRegistry = ZkProofSystemRegistry(systems: [LongfellowZkProofSystem(zkCircuitClient: self.zkCircuitClient)])
        #else
        self.zkProofSystemRegistry = ZkProofSystemRegistry(systems: [])
        #endif

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
    // Not `private`: `SirosWallet+Engine.swift` needs it too - same
    // cross-file-extension-access reason as `keystore` above.
    func handleReauthenticationRequired() {
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
        let deletedBatchId = await credentialStore.getAll().first { $0.id == credentialId }?.batchId
        await credentialStore.delete(credentialId)
        // If that was the last instance of its batch, its refresh_token
        // entry (if any) is now orphaned - privatedata-spec §6.2 requires
        // it not linger pointing at a batch that no longer exists.
        if let batchId = deletedBatchId {
            let remaining = await credentialStore.getAll()
            if !remaining.contains(where: { $0.batchId == batchId }) {
                await removeCredentialRefreshToken(batchId: batchId)
            }
        }
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

}

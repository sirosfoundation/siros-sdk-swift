// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SirosWallet

/// The WMP Groups screen's state and actions (split from WalletViewModel to
/// keep the view model below the file-length lint ceiling).
extension WalletViewModel {

    @Published var wmpEndpoints: [WmpEndpointInfo] = []
    @Published var wmpMessages: [WmpGroupMessage] = []
    var wmpEventsJob: Task<Void, Never>?
    private lazy var wmpJoinStore = JsonFileWmpJoinStore()
    private var wmpJoinsRestored = false
    private var wmpJoinRestoreJob: Task<Void, Never>?

    // MARK: - WSCD lifecycle

    @Published var selectedPluginId: String = "softkey"
    @Published var lifecycleState: LifecycleState?
    @Published var lifecycleStatus: LifecycleStatus?
    @Published var enrollmentInProgress = false
    @Published var wscdKeys: [SignerKeyInfo] = []
    /// Every registered WSCD plugin ID this session actually has a signer
    /// for (mirrors Kotlin's `_availableWscdPluginIds`), set from
    /// `rebuildWalletIfNeeded()`'s local `availableKeystores` dict. Used by
    /// `maybeOfferWscdAutoEnroll()` to check the hinted plugin is actually
    /// usable in this session before offering it.
    @Published var availableWscdPluginIds: [String] = []
    @Published var wscdKeySecurityProps: [String: SignerSecurityProperties] = [:]
    /// Snapshot of `SirosWallet.wscdTofuMapping`, refreshed on demand
    /// (`refreshWscdTofuMapping()`) - the SDK doesn't publish TOFU changes
    /// as wallet-state stream events (they're a side effect of credential
    /// issuance, not a first-class state transition), so this is an
    /// imperative refresh like `listPasskeysForUI()`/`wscdKeys` rather than
    /// always-live.
    @Published var wscdTofuMappingSnapshot: [String: String] = [:]
    /// Snapshot of `SirosWallet.wscdUserOverrides` - deliberate per-(issuer,
    /// credentialType) user preferences, distinct from the TOFU snapshot
    /// above (see `WscdRememberScope`'s doc comment). Refreshed the same
    /// imperative way.
    @Published var wscdUserOverridesSnapshot: [String: String] = [:]
    /// Snapshot of `SirosWallet.wscdGlobalOverride` - the single global user
    /// preference, or `nil` for "no preference."
    @Published var wscdGlobalOverrideSnapshot: String?

    // MARK: - TS11 registry discovery (best-effort, see WscdSettingsView.WscdMappingCard)

    /// Result of the last `discoverTs11Schemas()` call, for
    /// `WscdSettingsView`'s common (not per-plugin) "Discover from TS11
    /// Registry" action - mirrors Kotlin's `WalletViewModel.ts11DiscoveredCredentials`.
    /// Each entry has already been enriched with a real display identity by
    /// `Ts11CredentialDiscovery` - a raw registry entry only carries an
    /// opaque `Ts11SchemaMeta.id`, which is not something worth surfacing
    /// directly to the user.
    @Published var ts11DiscoveredCredentials: [Ts11DiscoveredCredential] = []
    @Published var ts11DiscoveryInProgress = false

    /// Queries `registry.siros.org` (via `Ts11CredentialDiscovery`) for
    /// every published credential type and stores the result in
    /// `ts11DiscoveredCredentials` for `WscdMappingCard` to offer as
    /// candidates. Best-effort: network/parse failures degrade to whatever
    /// subset of entries resolved, never surfaced as an app-level error -
    /// mirrors Kotlin's `discoverTs11Schemas()`.
    func discoverTs11Schemas() {
        guard !ts11DiscoveryInProgress else { return }
        ts11DiscoveryInProgress = true
        Task {
            defer { ts11DiscoveryInProgress = false }
            ts11DiscoveredCredentials = await Ts11CredentialDiscovery().discover()
        }
    }

    // MARK: - Loading / error

    @Published var isLoading = false
    @Published var errorMessage: String?
    @Published var showError = false

    // MARK: - Info (non-error, transient confirmations e.g. batch receipt)

    @Published var infoMessage: String?
    @Published var showInfo = false

    // MARK: - Wallet instance

    // `private(set)` rather than `private`: the Devices actions live in
    // `WalletViewModel+Devices.swift` (Swift extensions cannot hold stored
    // properties, so only the behaviour moved) and need to read it. Still
    // assigned only here.
    private(set) var wallet: SirosWallet?
    private var stateTask: Task<Void, Never>?
    private var pendingAuthFlowId: String?
    /// The flow type of the most recent `.flowActive` state, captured in
    /// `updateState` while the flow is still active. `onFlowComplete` needs
    /// this to distinguish issuance from presentation, but its own body runs
    /// in a deferred `Task { @MainActor in ... }` - by the time that runs,
    /// the wallet's state may have already transitioned to `.ready`, so it
    /// can't just read `wallet?.state` at completion time.
    // Internal, not private: the flow-complete callback in
    // WalletViewModel+PresentationFlow.swift reads it.
    var lastFlowType: String?
    /// Credentials received so far in the current flow. Flows in this app
    /// run one at a time, so a plain counter reset on consumption (in
    /// onFlowComplete) is enough - no need to key it by flowId, which
    /// onCredentialReceived doesn't carry anyway.
    // Internal, not private: the flow-complete callback in
    // WalletViewModel+PresentationFlow.swift resets it.
    var receivedCredentialCount = 0
    #if canImport(siros_wscd_managerFFI)
    /// Stored reference to the UniFFISigner for `listKeys()`/
    /// `securityProperties(keyId:)` calls only - these aren't part of
    /// `WscdManager` at all (they're generic `Signer`/`KeystoreManager`
    /// surface). Everything else (lifecycle, plugin registration) goes
    /// through `wallet.wscdManager`.
    private var wscdSigner: UniFFISigner?
    #endif
    /// Internal, not private: `WalletViewModel+Wscd.swift` is the other half
    /// of this type and a Swift extension in another file cannot see `private`.
    var lifecycleContextId: String?
    /// The SDK prompt behind `pendingWscdChoice`; its `onChange` is wired in `init`.
    let wscdChoice = ConsentPrompt<WscdChoiceQuestion, WscdChoiceResult>(decline: .cancelled)
    /// Offered at most once per process - a user who dismisses it isn't
    /// re-nagged every time `.ready` re-emits (e.g. after a token refresh),
    /// and one who accepts doesn't need it again once `enrollWscd()` runs.
    private var autoEnrollOffered = false

    init() {
        let defaults = UserDefaults.standard
        var backendUrl = defaults.string(forKey: "siros_backend_url") ?? defaultBackendUrl
        var tenantId = defaults.string(forKey: "siros_tenant_id") ?? defaultTenantId
        #if DEBUG
        // Debug-only test-environment override, the closest Swift/iOS analog
        // to Android's `adb shell am start --es backend_url ... --es tenant_id ...`:
        // set via `SIMCTL_CHILD_SIROS_BACKEND_URL=... xcrun simctl launch <udid> <bundle-id>`.
        // Session-scoped only - not persisted to UserDefaults.
        let env = ProcessInfo.processInfo.environment
        if let overrideBackendUrl = env["SIROS_BACKEND_URL"] { backendUrl = overrideBackendUrl }
        if let overrideTenantId = env["SIROS_TENANT_ID"] { tenantId = overrideTenantId }
        #endif
        self.backendUrl = backendUrl
        self.tenantId = tenantId
        self.useWmpProtocol = defaults.bool(forKey: "siros_use_wmp_protocol")
        self.wmpEngineMode = WmpEngineMode(
            rawValue: defaults.string(forKey: "siros_wmp_engine_mode") ?? ""
        ) ?? .legacyWS
        self.wmpSendUrl = defaults.string(forKey: "siros_wmp_send_url") ?? ""
        self.wmpSseUrl = defaults.string(forKey: "siros_wmp_sse_url") ?? ""
        // Default ON for all three (the deployed engines run tenant mode
        // with both providers enabled): bool(forKey:) answers false for an
        // unset key, so the object-as-Bool shape carries the default.
        self.engineLocalEnabled = defaults.object(forKey: "siros_engine_local_enabled") as? Bool ?? true
        self.engineRemoteEnabled = defaults.object(forKey: "siros_engine_remote_enabled") as? Bool ?? true
        self.engineTenantTokens = defaults.object(forKey: "siros_engine_tenant_tokens") as? Bool ?? true
        self.transactionDataEnabled = defaults.bool(forKey: Self.transactionDataEnabledKey)
        if let storedShowDetails = defaults.object(forKey: "siros_show_credential_details") as? Bool {
            self.showCredentialDetails = storedShowDetails
        } else {
            #if DEBUG
            self.showCredentialDetails = true
            #else
            self.showCredentialDetails = false
            #endif
        }
        // Raw FlowStep tokens shown alongside the friendly progress label -
        // default false: seeing both together in practice is redundant, the
        // localized label alone is enough. Kept as an opt-in toggle for
        // debugging (was default true during initial rollout).
        self.showDiagnosticMessages = defaults.object(forKey: "siros_show_diagnostic_messages") as? Bool ?? false
        self.showPhotoIdOnboarding = defaults.object(forKey: "siros_show_photo_id_onboarding") as? Bool ?? false
        self.credentialConsumptionPolicy = defaults.string(forKey: "siros_credential_consumption_policy")
            .flatMap { CredentialConsumptionPolicy(rawValue: $0) } ?? .neverConsume
        self.wscdMultiPluginEnabled = defaults.bool(forKey: "siros_wscd_multi_plugin_enabled")
        self.wscdDefaultMapping = defaults.string(forKey: "siros_wscd_default_mapping_json")
            .flatMap { $0.data(using: .utf8) }
            .flatMap { try? JSONDecoder().decode([String: String].self, from: $0) } ?? [:]
        self.zkCircuitUrls = defaults.string(forKey: "siros_zk_circuit_urls_json")
            .flatMap { $0.data(using: .utf8) }
            .flatMap { try? JSONDecoder().decode([String].self, from: $0) }
            .flatMap { $0.isEmpty ? nil : $0 } ?? [ZkCircuitClient.defaultZkCircuitUrl]
        self.preferLocalReaderTrustEvaluation = defaults.bool(forKey: "siros_prefer_local_reader_trust_evaluation")
        self.readerTrustRootCertificatePem = defaults.string(forKey: "siros_reader_trust_root_certificate_pem") ?? ""
        // The mode knobs (2026-11-16): stored as the enum's rawValue; an
        // unset key is the default (remoteWithLocalFallback), not a stored
        // name, so an unknown value cannot silently narrow.
        self.readerTrustEvaluationMode = MdocTrustEvaluationMode(
            rawValue: defaults.string(forKey: "siros_reader_trust_evaluation_mode") ?? ""
        ) ?? .remoteWithLocalFallback
        self.issuerTrustEvaluationMode = MdocTrustEvaluationMode(
            rawValue: defaults.string(forKey: "siros_issuer_trust_evaluation_mode") ?? ""
        ) ?? .remoteWithLocalFallback
        self.issuerTrustRootCertificatePem = defaults.string(forKey: "siros_issuer_trust_root_certificate_pem") ?? ""
        #if DEBUG
        applyFixtureCredentialsIfRequested()
        #endif

        // The SDK prompts publish their current question; read it on the main actor so the order is the truth.
        transactionConsent.onChange = { [weak self] _ in
            Task { @MainActor in self?.pendingTransactionConsent = self?.transactionConsent.current }
        }
        wscdChoice.onChange = { [weak self] _ in
            Task { @MainActor in self?.pendingWscdChoice = self?.wscdChoice.current }
        }
    }

    // MARK: - Public actions

    func login() {
        rebuildWalletIfNeeded()
        guard let wallet else { return }
        isLoading = true
        Task {
            do {
                try await wallet.login()
            } catch {
                setError(error.localizedDescription)
            }
            isLoading = false
        }
    }

    func loginWithAccount(_ account: CachedAccount) {
        rebuildWalletIfNeeded()
        guard let wallet else { return }
        isLoading = true
        Task {
            do {
                try await wallet.login()
            } catch {
                setError(error.localizedDescription)
            }
            isLoading = false
        }
    }

    func register(displayName: String) {
        rebuildWalletIfNeeded()
        guard let wallet else { return }
        isLoading = true
        Task {
            do {
                try await wallet.register(displayName: displayName)
            } catch {
                setError(error.localizedDescription)
            }
            isLoading = false
        }
    }

    func forgetAccount(_ accountId: String) {
        wallet?.forgetAccount(accountId: accountId)
        cachedAccounts.removeAll { $0.accountId == accountId }
    }

    func listPasskeysForUI() {
        passkeys = wallet?.listPasskeys() ?? []
    }

    func renamePasskey(credentialId: String, nickname: String) {
        wallet?.renamePasskey(credentialId: credentialId, nickname: nickname)
        listPasskeysForUI()
    }

    func disconnect() {
        wmpJoinRestoreJob?.cancel()
        wmpJoinsRestored = false
        wmpJoinStore.clear()
        wallet?.logout()
        selectedTab = 1
        showAddCredential = false
        availableCredentials = []
        selectedCredential = nil
        showHistory = false
        showActivate = false
        showWscaDeveloper = false
        showIDVPreparation = false
        closeWmpEndpoints()
        resetTransactionDataState()
        resetDevicesNavigation()
    }

    func cancelCurrentFlow() {
        wallet?.cancelCurrentFlow()
    }


    func openWmpEndpoints() {
        showWmpEndpoints = true
        wmpEventsJob?.cancel()
        guard let wallet else {
            refreshWmpEndpoints()
            return
        }
        wmpEventsJob = Task { @MainActor [weak self, wallet] in
            // Entry waits for any startup restore, then takes the endpoint
            // snapshot and starts the collector with the restored peers.
            await self?.wmpJoinRestoreJob?.value
            guard let self, !Task.isCancelled, self.showWmpEndpoints else { return }
            self.refreshWmpEndpoints()
            for await _ in wallet.groupMessageEvents() {
                self.wmpMessages = wallet.wmpGroupInbox()
            }
        }
    }

    func closeWmpEndpoints() {
        showWmpEndpoints = false
        wmpEventsJob?.cancel()
        wmpEventsJob = nil
    }

    func refreshWmpEndpoints() {
        guard let wallet else {
            wmpEndpoints = []
            wmpMessages = []
            return
        }
        wmpEndpoints = wallet.connectedWmpEndpoints()
        wmpMessages = wallet.wmpGroupInbox()
        Task { @MainActor in
            await wallet.pollGroupMessages()
            wmpEndpoints = wallet.connectedWmpEndpoints()
            wmpMessages = wallet.wmpGroupInbox()
        }
    }

    func sendWmpGroupReply(backend: String, text: String) {
        guard let wallet else { return }
        Task { @MainActor in
            do {
                try await wallet.replyToGroup(backend: backend, text: text)
                wmpMessages = wallet.wmpGroupInbox()
            } catch {
                setError(error.localizedDescription)
            }
        }
    }

    /// Restore sessions only. Groups deliberately refresh their published
    /// endpoint/message state when the user opens the Groups screen.
    func restoreWmpJoinsIfNeeded() {
        guard !wmpJoinsRestored, let wallet else { return }
        wmpJoinsRestored = true
        let records = wmpJoinStore.load()
        guard !records.isEmpty else { return }
        wmpJoinRestoreJob = Task { @MainActor [weak self, wallet] in
            for record in records {
                if await wallet.resumeWmpJoin(record: record) {
                    guard let self, !Task.isCancelled, self.wallet === wallet else { return }
                    // The resume rotated the token: persist the replacement.
                    self.persistJoinedGroups()
                }
            }
        }
    }

    func persistJoinedGroups() {
        guard let wallet else { return }
        for endpoint in wallet.connectedWmpEndpoints() {
            guard let provider = endpoint.providerUrl,
                  let record = wallet.wmpJoinRecord(provider: provider) else { continue }
            wmpJoinStore.save(record)
        }
    }

}

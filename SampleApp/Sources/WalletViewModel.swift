// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SwiftUI
import SirosWallet
import SirosCredentials
import SirosAuth
import SirosKeystore
#if canImport(siros_wscd_managerFFI)
import siros_wscd_managerFFI
#endif

#if DEBUG
private let defaultBackendUrl = "http://192.168.240.1:8090"
#else
private let defaultBackendUrl = "https://wallet.sirosid.dev"
#endif

private let defaultTenantId = "default"
private let defaultR2psUrl = "http://192.168.240.1:9000"
private let redirectScheme = "siros-sample"

/// Sample app ViewModel.
///
/// The entire wallet lifecycle — auth, key management, engine protocol,
/// credential storage — is handled by `SirosWallet`. This ViewModel only
/// needs to expose UI-level state and forward user actions.
@MainActor
final class WalletViewModel: ObservableObject {

    // MARK: - Configuration

    @Published var backendUrl: String {
        didSet { UserDefaults.standard.set(backendUrl, forKey: "siros_backend_url") }
    }
    @Published var tenantId: String {
        didSet { UserDefaults.standard.set(tenantId, forKey: "siros_tenant_id") }
    }
    @Published var useWmpProtocol: Bool {
        didSet { UserDefaults.standard.set(useWmpProtocol, forKey: "siros_use_wmp_protocol") }
    }
    @Published var showCredentialDetails: Bool {
        didSet { UserDefaults.standard.set(showCredentialDetails, forKey: "siros_show_credential_details") }
    }
    /// Show the raw backend step token alongside the friendly progress label
    /// during a flow. Default false - opt-in debugging aid, not shown by
    /// default since it duplicates the localized label.
    @Published var showDiagnosticMessages: Bool {
        didSet { UserDefaults.standard.set(showDiagnosticMessages, forKey: "siros_show_diagnostic_messages") }
    }
    @Published var r2psEnabled: Bool = false
    @Published var r2psServerUrl: String = defaultR2psUrl
    /// Core wallet policy (not a UI-only preference like the toggles above) -
    /// persisted here, but enforced by `SirosWallet` itself (see
    /// `SirosWallet.credentialConsumptionPolicy`'s doc comment). Applied to
    /// `wallet` both immediately on change (`didSet`) and again whenever
    /// `rebuildWalletIfNeeded()` creates a fresh instance.
    @Published var credentialConsumptionPolicy: CredentialConsumptionPolicy {
        didSet {
            UserDefaults.standard.set(credentialConsumptionPolicy.rawValue, forKey: "siros_credential_consumption_policy")
            wallet?.credentialConsumptionPolicy = credentialConsumptionPolicy
        }
    }

    // MARK: - Wallet state

    @Published var walletState: WalletViewState = .disconnected
    @Published var credentials: [StoredCredential] = []
    @Published var displayName: String?
    @Published var userId: String?

    // MARK: - Multi-account

    @Published var cachedAccounts: [CachedAccount] = []

    // MARK: - Passkeys

    @Published var passkeys: [CachedPasskey] = []

    // MARK: - Navigation state

    @Published var showAddCredential = false
    @Published var showHistory = false
    @Published var showQrScanner = false
    @Published var showWscaDeveloper = false
    @Published var showProximityEngagement = false
    @Published var selectedCredential: StoredCredential?
    @Published var pendingPresentation: PresentationRequest?

    // MARK: - Add credential state

    @Published var availableCredentials: [CredentialOffer] = []
    @Published var isLoadingOffers = false

    // MARK: - Presentation history

    @Published var presentationHistory: [PresentationRecord] = []

    // MARK: - WSCD lifecycle

    @Published var selectedPluginId: String = "softkey"
    @Published var lifecycleState: LifecycleState?
    @Published var lifecycleStatus: LifecycleStatus?
    @Published var enrollmentInProgress = false
    @Published var wscdKeys: [SignerKeyInfo] = []
    @Published var wscdKeySecurityProps: [String: SignerSecurityProperties] = [:]

    // MARK: - Loading / error

    @Published var isLoading = false
    @Published var errorMessage: String?
    @Published var showError = false

    // MARK: - Info (non-error, transient confirmations e.g. batch receipt)

    @Published var infoMessage: String?
    @Published var showInfo = false

    // MARK: - Wallet instance

    private var wallet: SirosWallet?
    private var stateTask: Task<Void, Never>?
    private var pendingAuthFlowId: String?
    /// The flow type of the most recent `.flowActive` state, captured in
    /// `updateState` while the flow is still active. `onFlowComplete` needs
    /// this to distinguish issuance from presentation, but its own body runs
    /// in a deferred `Task { @MainActor in ... }` - by the time that runs,
    /// the wallet's state may have already transitioned to `.ready`, so it
    /// can't just read `wallet?.state` at completion time.
    private var lastFlowType: String?
    /// Credentials received so far in the current flow. Flows in this app
    /// run one at a time, so a plain counter reset on consumption (in
    /// onFlowComplete) is enough - no need to key it by flowId, which
    /// onCredentialReceived doesn't carry anyway.
    private var receivedCredentialCount = 0
    #if canImport(siros_wscd_managerFFI)
    private var wscdSigner: UniFFISigner?
    #endif
    private var lifecycleContextId: String?

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
        self.credentialConsumptionPolicy = defaults.string(forKey: "siros_credential_consumption_policy")
            .flatMap { CredentialConsumptionPolicy(rawValue: $0) } ?? .neverConsume
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
        wallet?.logout()
        showAddCredential = false
        availableCredentials = []
        selectedCredential = nil
        showHistory = false
        showQrScanner = false
        showWscaDeveloper = false
    }

    func cancelCurrentFlow() {
        wallet?.cancelCurrentFlow()
    }

    // MARK: - WSCD lifecycle actions

    func selectPlugin(_ pluginId: String) {
        selectedPluginId = pluginId
        if pluginId == "r2ps" {
            r2psEnabled = true
        } else if selectedPluginId == "r2ps" {
            r2psEnabled = false
        }
    }

    func enrollWscd() {
        #if canImport(siros_wscd_managerFFI)
        guard let signer = wscdSigner else {
            setError("WSCD signer not initialized")
            return
        }
        enrollmentInProgress = true
        Task {
            do {
                let pluginId = selectedPluginId
                let contextId = "ctx-\(Int(Date().timeIntervalSince1970 * 1000))"
                let factorKind: FactorKind = pluginId == "r2ps" ? .opaque : .rawSign

                let regOutcome = try await signer.registerLifecycle(
                    request: RegisterLifecycleRequest(
                        pluginId: pluginId,
                        contextId: contextId,
                        factorKind: factorKind
                    )
                )
                lifecycleState = regOutcome.state

                let actOutcome = try await signer.activateLifecycle(
                    request: ActivateLifecycleRequest(
                        pluginId: pluginId,
                        contextId: contextId
                    )
                )
                lifecycleState = actOutcome.state
                lifecycleContextId = contextId
            } catch {
                setError("Enrollment failed: \(error.localizedDescription)")
            }
            enrollmentInProgress = false
        }
        #else
        setError("WSCD not available (siros_wscd_managerFFI not linked)")
        #endif
    }

    func rotateLifecycle() {
        #if canImport(siros_wscd_managerFFI)
        guard let signer = wscdSigner, let ctxId = lifecycleContextId else {
            setError("WSCD not enrolled")
            return
        }
        Task {
            do {
                let outcome = try await signer.rotateLifecycle(
                    request: RotateLifecycleRequest(
                        pluginId: selectedPluginId,
                        contextId: ctxId
                    )
                )
                lifecycleState = outcome.state
                refreshWscdInfo()
            } catch {
                setError("Rotation failed: \(error.localizedDescription)")
            }
        }
        #endif
    }

    func destroyLifecycle(mode: DestroyMode) {
        #if canImport(siros_wscd_managerFFI)
        guard let signer = wscdSigner, let ctxId = lifecycleContextId else {
            setError("WSCD not enrolled")
            return
        }
        Task {
            do {
                let outcome = try await signer.destroyLifecycle(
                    request: DestroyLifecycleRequest(
                        pluginId: selectedPluginId,
                        contextId: ctxId,
                        mode: mode
                    )
                )
                lifecycleState = outcome.state
                lifecycleContextId = nil
                refreshWscdInfo()
            } catch {
                setError("Destruction failed: \(error.localizedDescription)")
            }
        }
        #endif
    }

    func openWscaDeveloper() {
        showWscaDeveloper = true
        refreshWscdInfo()
    }

    func closeWscaDeveloper() {
        showWscaDeveloper = false
    }

    func refreshWscdInfo() {
        #if canImport(siros_wscd_managerFFI)
        Task {
            guard let signer = wscdSigner else { return }
            do {
                let keys = try await signer.listKeys()
                wscdKeys = keys
                var props: [String: SignerSecurityProperties] = [:]
                for key in keys {
                    if let p = try? await signer.securityProperties(keyId: key.keyId) {
                        props[key.keyId] = p
                    }
                }
                wscdKeySecurityProps = props
            } catch {
                print("Failed to list keys: \(error)")
            }
            guard let ctxId = lifecycleContextId else { return }
            do {
                let status = try await signer.lifecycleStatus(pluginId: selectedPluginId, contextId: ctxId)
                lifecycleStatus = status
                lifecycleState = status.state
            } catch {
                print("Failed to get lifecycle status: \(error)")
            }
        }
        #endif
    }

    /// Start issuance from a credential offer URI (for testing/automation).
    func startIssuance(_ offerUri: String) {
        Task {
            do {
                try await wallet?.startIssuance(offerUri: offerUri)
            } catch {
                setError(error.localizedDescription)
            }
        }
    }

    /// Start presentation from a request URI (for testing/automation).
    func startPresentation(_ requestUri: String) {
        Task {
            do {
                try await wallet?.startPresentation(requestUri: requestUri)
            } catch {
                setError(error.localizedDescription)
            }
        }
    }

    // MARK: - Credential operations

    func openAddCredential() {
        showAddCredential = true
        isLoadingOffers = true
        Task {
            do {
                availableCredentials = try await wallet?.getAvailableCredentials() ?? []
            } catch {
                print("Failed to load available credentials: \(error)")
                availableCredentials = []
            }
            isLoadingOffers = false
        }
    }

    func closeAddCredential() {
        showAddCredential = false
        pendingIssuanceOffer = nil
    }

    // MARK: - Issuance consent

    @Published var pendingIssuanceOffer: CredentialOffer?

    func selectCredentialOffer(_ offer: CredentialOffer) {
        pendingIssuanceOffer = offer
    }

    func confirmIssuance() {
        guard let offer = pendingIssuanceOffer else { return }
        pendingIssuanceOffer = nil
        showAddCredential = false
        Task {
            try? await wallet?.startIssuanceByOffer(offer)
        }
    }

    func cancelIssuance() {
        pendingIssuanceOffer = nil
    }

    // MARK: - Identity Verification (FaceTec IDV)

    /// IDV server URL — defaults to facetec-api co-hosted behind /idv path.
    var idvServerUrl: String { backendUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + "/idv" }

    func startIDV() {
        Task {
            do {
                isLoading = true
                guard let wallet else { throw SirosError.wallet(message: "Wallet is not connected") }
                let token = try await wallet.getAccessToken()
                let delegate = FaceTecCaptureDelegate()
                let client = RemoteIDVClient(config: RemoteIDVClient.Config(
                    serverUrl: idvServerUrl,
                    authToken: "Bearer \(token)"
                ))
                let provider = RemoteIDVProvider(client: client, delegate: delegate)
                let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene
                let rootViewController = windowScene?.windows.first?.rootViewController ?? UIViewController()
                try await wallet.verifyIdentityAndIssue(provider: provider, presentingViewController: rootViewController)
            } catch {
                errorMessage = "IDV failed: \(error.localizedDescription)"
            }
            isLoading = false
        }
    }

    func openCredentialDetail(_ credential: StoredCredential) {
        guard showCredentialDetails else { return }
        selectedCredential = credential
    }

    func closeCredentialDetail() {
        selectedCredential = nil
    }

    func deleteCredential(_ id: Int64) {
        Task {
            await wallet?.deleteCredential(id)
            selectedCredential = nil
        }
    }

    // MARK: - Presentation

    func acceptPresentation(_ selectedIds: [Int64]) {
        pendingPresentation = nil
        presentationContinuation?.resume(returning: selectedIds)
        presentationContinuation = nil
    }

    func declinePresentation() {
        pendingPresentation = nil
        presentationContinuation?.resume(returning: [])
        presentationContinuation = nil
    }

    // MARK: - History

    func openHistory() {
        showHistory = true
        presentationHistory = wallet?.presentationHistory ?? []
    }

    func closeHistory() {
        showHistory = false
    }

    // MARK: - QR Scanner

    func openQrScanner() {
        showQrScanner = true
    }

    func closeQrScanner() {
        showQrScanner = false
    }

    // MARK: - Proximity (ISO 18013-5 BLE) presentation

    func openProximityEngagement() {
        showProximityEngagement = true
    }

    func closeProximityEngagement() {
        showProximityEngagement = false
    }

    /// Mirrors `SirosWallet.getCredentials` - passed to `BlePeripheralServer`
    /// so it can match a request's docType without depending on this view
    /// model or `SirosWallet` directly.
    func getCredentialsForProximity() async -> [StoredCredential] {
        await wallet?.getCredentials() ?? []
    }

    /// Mirrors `SirosWallet.signMdocPresentationForProximity` - passed to
    /// `BlePeripheralServer`.
    func signMdocPresentationForProximity(
        credentialId: Int64,
        disclosedClaims: [String]?,
        sessionTranscriptBytes: Data
    ) async throws -> Data {
        guard let wallet else {
            throw SirosError.wallet(message: "Wallet is not connected")
        }
        return try await wallet.signMdocPresentationForProximity(
            credentialId: credentialId,
            disclosedClaims: disclosedClaims,
            sessionTranscriptBytes: sessionTranscriptBytes
        )
    }

    /// The wallet's presentation history, read live (unlike `presentationHistory`
    /// above, which is only refreshed when the History screen opens) - for
    /// callers like `CredentialsView`/`filterEligibleForProximity` that need
    /// an up-to-date view to compute `CredentialUtils.eligibleInstances`
    /// on every render/decision rather than a possibly-stale cached copy.
    var currentPresentationHistory: [PresentationRecord] {
        wallet?.presentationHistory ?? []
    }

    /// Mirrors `CredentialUtils.eligibleInstances` bound to `wallet`'s current
    /// `credentialConsumptionPolicy`/`presentationHistory` - passed to
    /// `BlePeripheralServer`/`BleCentralClient` and `ProximityConsentSheet`
    /// so a family the user approves can't be signed with (or picked for)
    /// an exhausted instance.
    func filterEligibleForProximity(_ instances: [StoredCredential]) -> [StoredCredential] {
        CredentialUtils.eligibleInstances(
            instances: instances,
            policy: credentialConsumptionPolicy,
            presentationHistory: currentPresentationHistory
        )
    }

    /// Same as `filterEligibleForProximity`, generalized for the redirect/DC
    /// API presentation consent screen (`PresentationConsentView`) - a query
    /// is unsatisfiable if every candidate that matched it has already been
    /// used up under the active consumption policy (see
    /// `CredentialUtils.eligibleInstances`). The SDK itself refuses to sign
    /// with an exhausted instance regardless (defense in depth), but the
    /// user shouldn't be let all the way to "Share" only to have it silently
    /// fail.
    func eligibleCredentialIds(from candidates: [StoredCredential]) -> [Int64] {
        CredentialUtils.eligibleInstances(
            instances: candidates,
            policy: credentialConsumptionPolicy,
            presentationHistory: currentPresentationHistory
        ).map(\.id)
    }

    /// Re-request a fresh batch of `credential` directly from its own
    /// issuer/config (already stored on it - see
    /// `StoredCredential.credentialIssuerIdentifier`/`StoredCredential.credentialConfigurationId`),
    /// skipping the generic issuer-browsing screen entirely - for
    /// `CredentialCardView`'s "Renew" action once every batch instance has
    /// been used up (see `CredentialUtils.eligibleInstances`).
    func renewCredential(_ credential: StoredCredential) {
        guard let issuerId = credential.credentialIssuerIdentifier,
              let configId = credential.credentialConfigurationId else {
            setError("Cannot renew this credential - issuer information is missing")
            return
        }
        let offer = CredentialOffer(
            credentialConfigurationId: configId,
            credentialIssuerIdentifier: issuerId,
            credentialName: credential.metadata?.name ?? credential.format,
            issuerName: credential.metadata?.issuer?.name ?? issuerId
        )
        Task {
            do {
                try await wallet?.startIssuanceByOffer(offer)
            } catch {
                setError(error.localizedDescription)
            }
        }
    }

    func handleQrResult(_ code: String) {
        showQrScanner = false
        let linkType = DeepLinkClassifier.classify(code)
        switch linkType {
        case .credentialOffer(let uri):
            Task { try? await wallet?.startIssuance(offerUri: uri) }
        case .presentationRequest(let uri):
            Task { try? await wallet?.startPresentation(requestUri: uri) }
        case .authCallback(let authCode, let state):
            handleAuthRedirect(code: authCode, state: state)
        case .unknown(let uri):
            // Fallback: treat unclassified URIs as presentation requests -
            // covers plain https://...?request_uri= patterns from QR codes
            // that DeepLinkClassifier doesn't recognize by shape.
            Task {
                do {
                    try await wallet?.startPresentation(requestUri: uri)
                } catch {
                    setError(error.localizedDescription)
                }
            }
        }
    }

    // MARK: - Deep links

    func handleDeepLink(_ url: URL) {
        let linkType = DeepLinkClassifier.classify(url.absoluteString)
        switch linkType {
        case .authCallback(let code, let state):
            handleAuthRedirect(code: code, state: state)
        case .credentialOffer(let uri):
            Task { try? await wallet?.startIssuance(offerUri: uri) }
        case .presentationRequest(let uri):
            Task { try? await wallet?.startPresentation(requestUri: uri) }
        case .unknown(let uri):
            // Fallback: treat unclassified URIs as presentation requests -
            // matches handleQrResult's fallback for the same URI shapes
            // arriving via a same-device link instead of a QR scan.
            Task {
                do {
                    try await wallet?.startPresentation(requestUri: uri)
                } catch {
                    setError(error.localizedDescription)
                }
            }
        }
    }

    // MARK: - Error handling

    func clearError() {
        errorMessage = nil
        showError = false
    }

    func clearInfo() {
        infoMessage = nil
        showInfo = false
    }

    // MARK: - Private

    private var presentationContinuation: CheckedContinuation<[Int64], Never>?

    private func setError(_ message: String) {
        errorMessage = message
        showError = true
    }

    private func handleAuthRedirect(code: String, state: String) {
        guard let flowId = pendingAuthFlowId else {
            setError("Authorization failed: no pending flow")
            return
        }
        pendingAuthFlowId = nil
        wallet?.completeAuthorization(flowId: flowId, code: code, state: state)
    }

    private func rebuildWalletIfNeeded() {
        let config = WalletConfig(
            backendUrl: backendUrl,
            tenantId: tenantId,
            redirectUri: "\(redirectScheme)://callback",
            useWmpProtocol: useWmpProtocol
        )

        // Rebuild if wallet doesn't exist or is in Disconnected/Error state
        let needsRebuild: Bool
        if wallet == nil {
            needsRebuild = true
        } else {
            switch walletState {
            case .disconnected, .error:
                wallet?.destroy()
                wallet = nil
                needsRebuild = true
            default:
                needsRebuild = false
            }
        }

        guard needsRebuild else { return }

        // Build WSCD-backed keystore with selected plugin
        var keystore: KeystoreManager?
        #if canImport(siros_wscd_managerFFI)
        do {
            let wscdConfig = FfiWscdConfig(defaultPlugin: selectedPluginId)
            let signer = try UniFFISigner(config: wscdConfig)

            // Register R2PS plugin if selected
            if selectedPluginId == "r2ps" || r2psEnabled {
                let r2psConfig = FfiR2psConfig(
                    serverUrl: r2psServerUrl,
                    clientId: "sample-app",
                    context: "wallet",
                    authMode: "opaque",
                    rpId: "",
                    allowedCredentialIds: [],
                    clientKeyPem: "",
                    serverPublicKeyPem: ""
                )
                let transport = URLSessionR2psTransport(serverUrl: r2psServerUrl)
                let pake = SamplePakeClient()
                try signer.registerR2psPlugin(config: r2psConfig, transport: transport, pake: pake)
            }

            self.wscdSigner = signer
            keystore = WscdKeystoreAdapter(signer: signer)
        } catch {
            print("WSCD setup failed: \(error). Falling back to default keystore.")
            keystore = nil
        }
        #endif

        // ASAuthorizationAuthProvider is the real, OS-backed passkey provider
        // (Face ID/Touch ID/roaming security keys) and is used on every
        // platform it supports (iOS 16+ and macOS 13+, matching Package.swift's
        // declared platforms). LocalAuthProvider is an explicit, clearly
        // labeled dev/test-only fallback for anything else — never a silent
        // per-platform default for a "supported" platform.
        #if os(iOS)
        let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene
        let anchor = windowScene?.windows.first ?? UIWindow()
        let authProvider = ASAuthorizationAuthProvider(presentationAnchor: anchor)
        #elseif os(macOS)
        let anchor = NSApplication.shared.windows.first ?? NSWindow()
        let authProvider = ASAuthorizationAuthProvider(presentationAnchor: anchor)
        #else
        let authProvider = LocalAuthProvider()
        #endif
        wallet = SirosWallet(
            config: config,
            authProvider: authProvider,
            sessionStore: KeychainSessionStore(),
            keystore: keystore
        )
        wallet?.credentialConsumptionPolicy = credentialConsumptionPolicy
        wallet?.setEventListener(self)
        observeState()
    }

    private func observeState() {
        stateTask?.cancel()
        stateTask = Task { [weak self] in
            guard let self, let wallet = self.wallet else { return }
            for await state in wallet.stateStream() {
                guard !Task.isCancelled else { break }
                self.updateState(state)
            }
        }
    }

    private func updateState(_ state: WalletState) {
        switch state {
        case .disconnected(let accounts):
            walletState = .disconnected
            credentials = []
            displayName = nil
            userId = nil
            cachedAccounts = accounts
        case .connecting:
            walletState = .connecting
        case .ready(let uid, let name, let creds, let accounts):
            walletState = .ready
            credentials = creds
            displayName = name
            userId = uid
            cachedAccounts = accounts
            listPasskeysForUI()
        case .keystoreLocked(_, let name):
            walletState = .connecting
            displayName = name
        case .flowActive(_, _, _, let flowType, let status, let creds):
            walletState = .flowActive(flowType: flowType, status: status)
            credentials = creds
            lastFlowType = flowType
        case .error(let message):
            walletState = .error(message: message)
        }
    }
}

// MARK: - WalletEventListener

extension WalletViewModel: WalletEventListener {
    nonisolated func onCredentialSelectionRequired(request: PresentationRequest) async -> [Int64] {
        await withCheckedContinuation { continuation in
            Task { @MainActor in
                self.presentationContinuation = continuation
                self.pendingPresentation = request
            }
        }
    }

    nonisolated func onCredentialReceived(credential: StoredCredential) {
        Task { @MainActor in
            self.receivedCredentialCount += 1
        }
    }

    nonisolated func onFlowComplete(flowId: String) {
        Task { @MainActor in
            if self.receivedCredentialCount > 0 {
                self.infoMessage = L10n.string("flow.credentialsReceived", self.receivedCredentialCount)
                self.showInfo = true
                self.receivedCredentialCount = 0
            } else if self.lastFlowType == "presentation" {
                // Presentation has no analogous per-item count, so a plain
                // confirmation is the equivalent "something happened" signal
                // for a flow whose whole point is watching this screen after
                // a QR scan.
                self.infoMessage = L10n.string("flow.presentationSent")
                self.showInfo = true
            }
        }
    }

    nonisolated func onFlowError(flowId: String, errorMessage: String) {
        Task { @MainActor in
            self.receivedCredentialCount = 0
            self.setError(errorMessage)
        }
    }

    nonisolated func onAuthorizationRequired(flowId: String, authorizationUrl: String, redirectUri: String, state: String) {
        Task { @MainActor in
            self.pendingAuthFlowId = flowId
            guard let url = URL(string: authorizationUrl) else { return }
            #if canImport(UIKit)
            UIApplication.shared.open(url)
            #endif
        }
    }

    nonisolated func onTxCodeRequired(flowId: String, description: String?) -> String? {
        // Auto-extract PIN from description for testing
        guard let desc = description else { return nil }
        let pattern = #/<(\d+)>/#
        if let match = desc.firstMatch(of: pattern) {
            return String(match.1)
        }
        return nil
    }
}

// MARK: - View State

enum WalletViewState: Equatable {
    case disconnected
    case connecting
    case ready
    case flowActive(flowType: String, status: String)
    case error(message: String)
}

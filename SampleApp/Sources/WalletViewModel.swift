// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SwiftUI
import SirosWallet
import SirosCredentials
import SirosAuth
import SirosKeystore
#if canImport(SirosWscdFFI)
import SirosWscdFFI
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

    @Published var backendUrl: String = defaultBackendUrl
    @Published var tenantId: String = defaultTenantId
    @Published var r2psEnabled: Bool = false
    @Published var r2psServerUrl: String = defaultR2psUrl

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

    // MARK: - Wallet instance

    private var wallet: SirosWallet?
    private var stateTask: Task<Void, Never>?
    private var pendingAuthFlowId: String?
    #if canImport(SirosWscdFFI)
    private var wscdSigner: UniFFISigner?
    #endif
    private var lifecycleContextId: String?

    init() {}

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
        #if canImport(SirosWscdFFI)
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
        setError("WSCD not available (SirosWscdFFI not linked)")
        #endif
    }

    func rotateLifecycle() {
        #if canImport(SirosWscdFFI)
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
        #if canImport(SirosWscdFFI)
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
        #if canImport(SirosWscdFFI)
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
                try wallet?.startIssuance(offerUri: offerUri)
            } catch {
                setError(error.localizedDescription)
            }
        }
    }

    /// Start presentation from a request URI (for testing/automation).
    func startPresentation(_ requestUri: String) {
        Task {
            do {
                try wallet?.startPresentation(requestUri: requestUri)
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
    }

    func selectCredentialOffer(_ offer: CredentialOffer) {
        showAddCredential = false
        Task {
            try? await wallet?.startIssuanceByOffer(offer)
        }
    }

    func openCredentialDetail(_ credential: StoredCredential) {
        selectedCredential = credential
    }

    func closeCredentialDetail() {
        selectedCredential = nil
    }

    func deleteCredential(_ id: String) {
        Task {
            await wallet?.deleteCredential(id)
            selectedCredential = nil
        }
    }

    // MARK: - Presentation

    func acceptPresentation(_ selectedIds: [String]) {
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

    func handleQrResult(_ code: String) {
        showQrScanner = false
        let linkType = DeepLinkClassifier.classify(code)
        switch linkType {
        case .credentialOffer(let uri):
            Task { try? wallet?.startIssuance(offerUri: uri) }
        case .presentationRequest(let uri):
            Task { try? wallet?.startPresentation(requestUri: uri) }
        case .authCallback(let authCode, let state):
            handleAuthRedirect(code: authCode, state: state)
        case .unknown:
            setError("Unrecognised QR code")
        }
    }

    // MARK: - Deep links

    func handleDeepLink(_ url: URL) {
        let linkType = DeepLinkClassifier.classify(url.absoluteString)
        switch linkType {
        case .authCallback(let code, let state):
            handleAuthRedirect(code: code, state: state)
        case .credentialOffer(let uri):
            Task { try? wallet?.startIssuance(offerUri: uri) }
        case .presentationRequest(let uri):
            Task { try? wallet?.startPresentation(requestUri: uri) }
        case .unknown:
            break
        }
    }

    // MARK: - Error handling

    func clearError() {
        errorMessage = nil
        showError = false
    }

    // MARK: - Private

    private var presentationContinuation: CheckedContinuation<[String], Never>?

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
            redirectUri: "\(redirectScheme)://callback"
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
        #if canImport(SirosWscdFFI)
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

        #if os(iOS)
        let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene
        let anchor = windowScene?.windows.first ?? UIWindow()
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
            walletState = .flowActive(message: "\(flowType): \(status)")
            credentials = creds
        case .error(let message):
            walletState = .error(message: message)
        }
    }
}

// MARK: - WalletEventListener

extension WalletViewModel: WalletEventListener {
    nonisolated func onCredentialSelectionRequired(request: PresentationRequest) async -> [String] {
        await withCheckedContinuation { continuation in
            Task { @MainActor in
                self.presentationContinuation = continuation
                self.pendingPresentation = request
            }
        }
    }

    nonisolated func onCredentialReceived(credential: StoredCredential) {}
    nonisolated func onFlowComplete(flowId: String) {}

    nonisolated func onFlowError(flowId: String, errorMessage: String) {
        Task { @MainActor in
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
    case flowActive(message: String)
    case error(message: String)
}

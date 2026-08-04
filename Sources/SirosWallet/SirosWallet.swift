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
    let credentialStore: CredentialStore
    private let vctmFetcher: VctmFetcher
    let mddlSchemaFetcher: MddlSchemaFetcher
    private let accountRegistry: AccountRegistry

    private var apiClient: BackendApiClient?
    var engineSession: WalletEngineSession?
    /// Transport-independent notifier for OID4VCI §10 events.
    var credentialNotifier: CredentialNotifier?
    weak var eventListener: WalletEventListener?
    var activeOffer: CredentialOffer?
    var activeVctm: Vctm?
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

        self.vctmFetcher = VctmFetcher { url in
            guard let u = URL(string: url) else { return nil }
            do {
                let (data, response) = try await URLSession.shared.data(from: u)
                guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { return nil }
                return String(data: data, encoding: .utf8)
            } catch {
                return nil
            }
        }
        self.mddlSchemaFetcher = MddlSchemaFetcher()

        // Set up new AS-based auth
        let asClient = AuthServerClient(baseUrl: config.backendUrl, tenantId: config.tenantId, httpFn: Self.defaultHttpFn)
        self.authServerClient = asClient
        let tokens = AuthTokens(authServerClient: asClient, tenantId: config.tenantId)
        tokens.onSessionRejected = { [weak self] in
            self?.logout()
        }
        self.authTokens = tokens
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
            issuerLogoUri: issuerDisplay?.logo?.uri
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
        lock.lock(); activeOffer = offer; lock.unlock()

        // Try to fetch VCTM
        lock.lock()
        activeVctm = try? await vctmFetcher.fetch(
            issuerUrl: offer.credentialIssuerIdentifier,
            scope: offer.credentialConfigurationId
        )
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
    }

    /// Start issuance with a raw offer URI or JSON.
    public func startIssuance(offerUri: String) async throws {
        guard let engine = engineSession else {
            throw SirosError.wallet(message: "Not connected")
        }
        try await ensureEngineConnected(engine)
        if let offer = await resolveOfferForDisplay(offerUri) {
            lock.lock(); activeOffer = offer; lock.unlock()
            let vctm = try? await vctmFetcher.fetch(
                issuerUrl: offer.credentialIssuerIdentifier,
                scope: offer.credentialConfigurationId
            )
            lock.lock(); activeVctm = vctm; lock.unlock()
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
        let token = try await tokens.ensureAnonymousToken()
        engine.forceReconnect(appToken: token.raw)
        try await engine.awaitConnected()
    }

    /// Cancel the current flow.
    public func cancelCurrentFlow() {
        if case .flowActive(let userId, let displayName, let flowId, _, _, let creds) = state {
            try? engineSession?.cancelFlow(flowId: flowId)
            setState(.ready(userId: userId, displayName: displayName, credentials: creds))
        }
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
        let pending = pendingAuthorizations.removeValue(forKey: flowId)
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

        Task {
            do {
                guard let tokens else {
                    throw SirosError.wallet(message: "Not connected")
                }
                let token = try await tokens.ensureAnonymousToken()
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

    /// Connect engine using an anonymous token from the AS.
    private func connectEngineWithToken(_ tokens: AuthTokens) async throws {
        let token = try await tokens.ensureAnonymousToken()
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
                self?.eventListener?.onFlowComplete(flowId: flowId)
            },
            onError: { [weak self] flowId, code, message in
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
    private struct GeneratedProofData {
        var proofType: String
        var jwt: String?
        var attestation: String?
        var attestedKeyIds: [String]?
    }

    private struct BackendAttestationResult {
        var jwt: String
        var keyIds: [String]
    }

    /// Generate proofs for a `generate_proof` sign request - shared by both
    /// transports so proof generation (including real backend Key Attestation
    /// with a self-signed fallback) behaves identically regardless of which
    /// transport carried the request.
    private func generateProofs(
        audience: String,
        nonce: String,
        count: Int,
        proofTypesSupported: [String: AnyCodable]?,
        proofTypeHint: String?
    ) async throws -> [GeneratedProofData] {
        let chosen = selectProofType(proofTypesSupported: proofTypesSupported, proofTypeHint: proofTypeHint)
        if chosen == "attestation" {
            let backendAttestation = await requestBackendKeyAttestation(audience: audience, nonce: nonce, count: count)
            let attestationJwt: String
            if let backendAttestation {
                attestationJwt = backendAttestation.jwt
            } else {
                attestationJwt = try await keystore.generateKeyAttestation(nonce: nonce, count: count)
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
    /// Returns nil (caller falls back to the self-signed path) when there's
    /// no backend session, the keystore can't produce raw keypairs, or the
    /// backend doesn't support/expose the endpoint.
    private func requestBackendKeyAttestation(audience: String, nonce: String, count: Int) async -> BackendAttestationResult? {
        lock.lock(); let client = apiClient; lock.unlock()
        guard let client else { return nil }
        do {
            let keypairs = try await keystore.generateKeypairs(count: count)
            var secDict: [String: Any]?
            if let keyId = keypairs.first?.keyId, let props = await keystore.securityProperties(keyId: keyId) {
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
            return BackendAttestationResult(jwt: jwt, keyIds: keypairs.map { $0.keyId })
        } catch {
            return nil
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
                "action": ["name": "credential-issuer"],
            ]
            let response = try await client.evaluateTrust(evaluationRequest)
            let decision = response["decision"] as? Bool ?? false
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
        engine.connect(appToken: appToken)
        try await engine.awaitConnected()

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
        engineTasks = [signTask, matchTask, progressTask, completeTask, errorTask]
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
                validateAudience(flowId: msg.flowId, audience: audience)

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
        }
    }

    private func handleMatchRequest(engine: WalletEngineSession, msg: MatchRequestMessage) async {
        let allCreds = await credentialStore.getAll()
        lock.lock()
        let listener = eventListener
        let trustResult = lastTrustResults.removeValue(forKey: msg.flowId)
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
    /// Logs a warning if there's a mismatch (defense-in-depth against MITM).
    private func validateAudience(flowId: String, audience: String) {
        lock.lock()
        let trustResult = lastTrustResults[flowId]
        lock.unlock()

        guard let trustResult, let expectedId = trustResult.identifier else { return }
        if !audience.isEmpty && !expectedId.isEmpty && audience != expectedId {
            print("[SirosWallet] ⚠️ Audience mismatch for flow \(flowId): sign_request audience='\(audience)' != trusted identifier='\(expectedId)'")
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

    private func handleFlowError(msg: FlowErrorMessage) {
        let fid = msg.flowId ?? "unknown"
        lock.lock(); let listener = eventListener; lock.unlock()
        listener?.onFlowError(flowId: fid, errorMessage: msg.error.message)

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

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
private let logger = Logger(subsystem: "org.sirosfoundation.sdk", category: "SirosWallet")
#endif

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
    private var _state: WalletState = .disconnected
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

    // MARK: - Configuration & dependencies

    private let config: WalletConfig
    private let authProvider: AuthProvider
    private let sessionStore: SessionStoreProtocol
    private let keystore: KeystoreManager
    let credentialStore: CredentialStore
    private let vctmFetcher: VctmFetcher

    private var apiClient: BackendApiClient?
    var engineSession: WalletEngineSession?
    /// Transport-independent notifier for OID4VCI §10 events.
    var credentialNotifier: CredentialNotifier?
    weak var eventListener: WalletEventListener?
    var activeOffer: CredentialOffer?
    var activeVctm: Vctm?
    private var engineTasks: [Task<Void, Never>] = []
    private var _presentationHistory: [PresentationRecord] = []

    // New AS-based auth
    private var authServerClient: AuthServerClient?
    private var authTokens: AuthTokens?

    /// Presentation history — most recent first.
    public var presentationHistory: [PresentationRecord] {
        lock.lock(); defer { lock.unlock() }
        return _presentationHistory
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

            let prfOutput = try await authProvider.getPrfOutput(credentialId: Data(), salt: prfSalt)

            try await keystore.unlock(
                prfOutput: prfOutput.first,
                encryptedContainer: Data(),
                hkdfSalt: hkdfSalt,
                hkdfInfo: hkdfInfo
            )

            let encryptedContainer = try await keystore.exportEncryptedContainer()

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
            setState(.error(message: e.localizedDescription))
        } catch {
            #if canImport(os)
            logger.error("Registration failed: \(error.localizedDescription)")
            #endif
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

            let prfOutput = try await authProvider.getPrfOutput(credentialId: Data(), salt: storedPrfSalt ?? Self.randomBytes(32))

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

            sessionStore.userId = session.uuid
            sessionStore.displayName = session.displayName
            sessionStore.tenantId = config.tenantId
            sessionStore.prfSalt = Self.b64Encode(prfSaltBytes)
            sessionStore.hkdfSalt = Self.b64Encode(hkdfSalt)
            sessionStore.hkdfInfo = Self.b64Encode(hkdfInfo)

            try await connectEngineWithToken(tokens)

            let creds = await credentialStore.getAll()
            setState(.ready(userId: session.uuid, displayName: session.displayName, credentials: creds))
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
        engineSession = nil
        credentialNotifier = nil
        apiClient = nil
        lock.unlock()
        engine?.disconnect()
        cancelEngineTasks()
        keystore.lock()
        sessionStore.clear()
        authTokens?.clear()
        Task {
            try? await authServerClient?.logout()
        }
        setState(.disconnected)
    }

    // MARK: - Session resume

    /// Resume a previous session without requiring a new WebAuthn assertion.
    public func resumeSession() async {
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
                setState(.disconnected)
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
            setState(.disconnected)
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

            let prfOutput = try await authProvider.getPrfOutput(
                credentialId: Data(),
                salt: storedPrfSalt ?? Self.randomBytes(32)
            )

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
    public func deleteCredential(_ credentialId: String) async {
        await credentialStore.delete(credentialId)
        if case .ready(let userId, let displayName, _) = state {
            let creds = await credentialStore.getAll()
            setState(.ready(userId: userId, displayName: displayName, credentials: creds))
        }
        await persistAndSyncKeystore()
    }

    // MARK: - Issuance

    /// Start issuance with a credential offer object.
    public func startIssuanceByOffer(_ offer: CredentialOffer) async throws {
        guard let engine = engineSession else {
            throw SirosError.wallet(message: "Not connected")
        }
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

        engine.startIssuance(
            offer: offerJson,
            redirectUri: config.redirectUri.isEmpty ? nil : config.redirectUri
        )
    }

    /// Start issuance with a raw offer URI or JSON.
    public func startIssuance(offerUri: String) throws {
        guard let engine = engineSession else {
            throw SirosError.wallet(message: "Not connected")
        }
        if offerUri.hasPrefix("openid-credential-offer://") || !offerUri.hasPrefix("http") {
            engine.startIssuance(offer: offerUri)
        } else {
            engine.startIssuance(credentialOfferUri: offerUri)
        }
    }

    /// Start a presentation flow.
    public func startPresentation(requestUri: String) throws {
        guard let engine = engineSession else {
            throw SirosError.wallet(message: "Not connected")
        }
        engine.startPresentation(requestUri: requestUri)
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
        try startIssuance(offerUri: result.credentialOfferURI)
    }

    /// Complete an OAuth authorization flow.
    public func completeAuthorization(flowId: String, code: String, state: String) {
        guard let engine = engineSession else { return }
        engine.sendFlowAction(
            flowId: flowId,
            action: "authorization_complete",
            payload: [
                "code": .string(code),
                "state": .string(state),
            ]
        )
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
        try await connectEngine(appToken: token.raw)
    }

    func connectEngine(appToken: String) async throws {
        let engine = Self.createEngineSession(config.backendUrl, config.tenantId)
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
                let proofJwt = try await keystore.generateProof(
                    audience: msg.params.audience ?? "",
                    nonce: msg.params.nonce ?? ""
                )
                let count = msg.params.count ?? 1
                let proofs = (0..<count).map { _ in
                    ProofObject(proofType: "jwt", jwt: proofJwt)
                }
                engine.sendSignResponse(flowId: msg.flowId, proofs: proofs, messageId: msg.messageId)

            case "sign_presentation":
                let nonce = msg.params.nonce ?? ""
                let audience = msg.params.audience ?? ""
                let credsToInclude = msg.params.credentialsToInclude

                if let credsToInclude, !credsToInclude.isEmpty {
                    let allCreds = await credentialStore.getAll()
                    var vpParts: [String] = []
                    for ref in credsToInclude {
                        guard let cred = allCreds.first(where: { $0.id == ref.credentialId }) else { continue }
                        let vp = try await keystore.signVpToken(
                            credential: cred.raw,
                            disclosedClaims: ref.disclosedClaims,
                            nonce: nonce,
                            audience: audience
                        )
                        vpParts.append(vp)
                    }
                    let vpToken = vpParts.joined(separator: "\n")
                    engine.sendSignResponse(flowId: msg.flowId, vpToken: vpToken, messageId: msg.messageId)
                } else {
                    let vpToken = try await keystore.signPresentation(
                        nonce: nonce, audience: audience, credentialIds: []
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
        lock.lock(); let listener = eventListener; lock.unlock()

        let selectedIds: [String]
        if let listener, !allCreds.isEmpty {
            selectedIds = await listener.onCredentialSelectionRequired(
                request: PresentationRequest(candidates: allCreds)
            )
        } else {
            selectedIds = allCreds.map(\.id)
        }

        lock.lock()
        _presentationHistory.insert(PresentationRecord(
            id: UUID().uuidString,
            flowId: msg.flowId,
            credentialIds: selectedIds,
            credentialNames: selectedIds.compactMap { id in
                allCreds.first(where: { $0.id == id })?.metadata?.name
            },
            timestamp: Int64(Date().timeIntervalSince1970 * 1000)
        ), at: 0)
        lock.unlock()

        let matches: [CredentialMatch] = selectedIds.compactMap { id in
            guard let cred = allCreds.first(where: { $0.id == id }) else { return nil }
            return CredentialMatch(
                credentialId: cred.id,
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
        case .ready(let userId, let displayName, let creds),
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
            engine.sendTrustResult(flowId: flowId, trusted: decision)
        } catch {
            engine.sendTrustResult(flowId: flowId, trusted: false, reason: error.localizedDescription)
        }
    }

    private func handleFlowError(msg: FlowErrorMessage) {
        let fid = msg.flowId ?? "unknown"
        lock.lock(); let listener = eventListener; lock.unlock()
        listener?.onFlowError(flowId: fid, errorMessage: msg.error.message)

        switch state {
        case .flowActive(let userId, let displayName, _, _, _, _),
             .ready(let userId, let displayName, _):
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

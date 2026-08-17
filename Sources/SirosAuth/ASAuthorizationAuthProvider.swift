// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

#if canImport(AuthenticationServices)
import AuthenticationServices
import Foundation
import SirosCredentials
#if canImport(CryptoKit)
import CryptoKit
#endif

/// AuthProvider implementation using ASAuthorization (iOS 16+ / macOS 13+).
///
/// This provider bridges the SIROS SDK's `AuthProvider` protocol to Apple's
/// `ASAuthorizationPlatformPublicKeyCredentialProvider` (the built-in
/// platform authenticator — Face ID/Touch ID) **and**
/// `ASAuthorizationSecurityKeyPublicKeyCredentialProvider` (roaming FIDO2
/// security keys over USB/NFC/BLE, e.g. YubiKeys). Every `register`/
/// `authenticate` call offers both request kinds to a single
/// `ASAuthorizationController`, matching Apple's documented combined
/// platform + security-key pattern, so a roaming authenticator is always
/// available as a choice — not an opt-in flag. This is the direct analog of
/// the Kotlin SDK defaulting to a Credential-Manager-backed provider instead
/// of a from-scratch implementation with no CTAP2/roaming support.
///
/// Usage:
/// ```swift
/// let authProvider = ASAuthorizationAuthProvider(presentationAnchor: window)
/// let wallet = SirosWallet(config: config, authProvider: authProvider)
/// ```
@available(iOS 16.0, macOS 13.0, *)
public final class ASAuthorizationAuthProvider: NSObject, AuthProvider, WscdAutoEnrollHint, @unchecked Sendable {
    private let anchor: ASPresentationAnchor
    private let lock = NSLock()
    private var continuation: CheckedContinuation<ASAuthorization, Error>?

    /// The relying party ID from the most recent register/authenticate call.
    /// `getPrfOutput(credentialId:salt:)` needs an rpId to build a
    /// credential-scoped assertion request, but the `AuthProvider` protocol's
    /// `getPrfOutput` signature doesn't carry one — so we remember the last
    /// one used. `SirosWallet` always calls `register`/`authenticate` before
    /// `getPrfOutput`, so this is populated by the time it's needed.
    private var lastRpId: String?

    /// True when the most recent `authenticate` call resolved to a roaming
    /// security-key assertion (`ASAuthorizationSecurityKeyPublicKeyCredentialAssertion`)
    /// rather than the platform authenticator (Face ID/Touch ID) - exactly
    /// the kind of physical authenticator the fido2 previewSign plugin
    /// needs. See `WscdAutoEnrollHint`'s doc comment for why this is a
    /// heuristic, not confirmation that this specific key supports
    /// previewSign. Guarded by `lock`, same as `lastRpId`.
    private var lastWasSecurityKeyAssertion = false

    /// Create an ASAuthorization-based auth provider.
    ///
    /// - Parameter presentationAnchor: The window to present the passkey UI in.
    public init(presentationAnchor: ASPresentationAnchor) {
        self.anchor = presentationAnchor
        super.init()
    }

    // MARK: - AuthProvider

    public func register(options: RegisterOptions) async throws -> RegisterResult {
        setLastRpId(options.rpId)

        let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(
            relyingPartyIdentifier: options.rpId
        )
        let platformRequest = platformProvider.createCredentialRegistrationRequest(
            challenge: options.challenge,
            name: options.userName,
            userID: options.userId
        )

        let securityKeyProvider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(
            relyingPartyIdentifier: options.rpId
        )
        let securityKeyRequest = securityKeyProvider.createCredentialRegistrationRequest(
            challenge: options.challenge,
            displayName: options.userDisplayName,
            name: options.userName,
            userID: options.userId
        )
        // Unlike the platform authenticator, roaming security keys don't
        // implicitly negotiate a single algorithm — this must be explicit.
        securityKeyRequest.credentialParameters = [
            ASAuthorizationPublicKeyCredentialParameters(algorithm: .ES256),
        ]

        let authorization = try await performRequest([platformRequest, securityKeyRequest])

        switch authorization.credential {
        case let credential as ASAuthorizationPlatformPublicKeyCredentialRegistration:
            guard let attestationObject = credential.rawAttestationObject else {
                throw SirosError.auth(message: "Missing attestation object in registration response")
            }
            return RegisterResult(
                credentialId: credential.credentialID,
                attestationObject: attestationObject,
                clientDataJSON: credential.rawClientDataJSON
            )
        case let credential as ASAuthorizationSecurityKeyPublicKeyCredentialRegistration:
            guard let attestationObject = credential.rawAttestationObject else {
                throw SirosError.auth(message: "Missing attestation object in registration response")
            }
            return RegisterResult(
                credentialId: credential.credentialID,
                attestationObject: attestationObject,
                clientDataJSON: credential.rawClientDataJSON
            )
        default:
            throw SirosError.auth(message: "Unexpected credential type from ASAuthorization registration")
        }
    }

    public func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult {
        setLastRpId(options.rpId)

        let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(
            relyingPartyIdentifier: options.rpId
        )
        let platformRequest = platformProvider.createCredentialAssertionRequest(
            challenge: options.challenge
        )

        let securityKeyProvider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(
            relyingPartyIdentifier: options.rpId
        )
        let securityKeyRequest = securityKeyProvider.createCredentialAssertionRequest(
            challenge: options.challenge
        )

        if let allowCredentials = options.allowCredentials {
            platformRequest.allowedCredentials = allowCredentials.map {
                ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0.id)
            }
            securityKeyRequest.allowedCredentials = allowCredentials.map {
                ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(
                    credentialID: $0.id,
                    transports: ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport.allSupported
                )
            }
        }

        // Request the *real* WebAuthn PRF extension output in the same
        // ceremony, when a salt was supplied. Registration can only check
        // for PRF support (see below) — the actual salt-derived secret is
        // only obtainable via a PRF-enabled assertion, per Apple's API.
        if #available(iOS 18.0, macOS 15.0, *), let salt = options.prfSalt {
            let inputValues = ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues(
                saltInput1: salt, saltInput2: nil
            )
            let prfInput = ASAuthorizationPublicKeyCredentialPRFAssertionInput.inputValues(inputValues)
            platformRequest.prf = prfInput
            // CTAP2 hmac-secret (the security-key analog of PRF) support
            // varies by authenticator; requesting it is harmless when the
            // key doesn't support it (the output is simply absent). The
            // security-key request's own `.prf` setter only exists on
            // iOS/macOS 26.4+ (later than the platform authenticator's
            // equivalent) - the PRF input VALUE type itself is available
            // from 18.0/15.0, only this particular property is gated higher.
            if #available(iOS 26.4, macOS 26.4, *) {
                securityKeyRequest.prf = prfInput
            }
        }

        let authorization = try await performRequest([platformRequest, securityKeyRequest])

        switch authorization.credential {
        case let credential as ASAuthorizationPlatformPublicKeyCredentialAssertion:
            setLastWasSecurityKeyAssertion(false)
            var prfOutput: PrfOutput?
            if #available(iOS 18.0, macOS 15.0, *) {
                prfOutput = Self.prfOutput(from: credential.prf)
            }
            return AuthenticateResult(
                credentialId: credential.credentialID,
                authenticatorData: credential.rawAuthenticatorData,
                clientDataJSON: credential.rawClientDataJSON,
                signature: credential.signature,
                userHandle: credential.userID,
                prfOutput: prfOutput
            )
        case let credential as ASAuthorizationSecurityKeyPublicKeyCredentialAssertion:
            setLastWasSecurityKeyAssertion(true)
            var prfOutput: PrfOutput?
            // The security-key assertion result's `.prf` getter only exists
            // on iOS/macOS 26.4+ (later than the platform authenticator's
            // equivalent, which is 18.0/15.0).
            if #available(iOS 26.4, macOS 26.4, *) {
                prfOutput = Self.prfOutput(from: credential.prf)
            }
            return AuthenticateResult(
                credentialId: credential.credentialID,
                authenticatorData: credential.rawAuthenticatorData,
                clientDataJSON: credential.rawClientDataJSON,
                signature: credential.signature,
                userHandle: credential.userID,
                prfOutput: prfOutput
            )
        default:
            throw SirosError.auth(message: "Unexpected credential type from ASAuthorization assertion")
        }
    }

    // MARK: - WscdAutoEnrollHint

    public let hintedWscdPluginId: String = "fido2"

    public func suggestsWscdCapableDevice() -> Bool {
        lock.lock(); defer { lock.unlock() }
        return lastWasSecurityKeyAssertion
    }

    private func setLastWasSecurityKeyAssertion(_ value: Bool) {
        lock.lock()
        lastWasSecurityKeyAssertion = value
        lock.unlock()
    }

    /// Obtain the PRF output for `credentialId`/`salt`.
    ///
    /// On iOS 18+/macOS 15+, this performs a dedicated, credential-scoped
    /// assertion (allowedCredentials = [credentialId]) requesting the real
    /// WebAuthn PRF extension via `ASAuthorizationPublicKeyCredentialPRFAssertionInput`,
    /// and returns the authenticator-derived secret from
    /// `credential.prf`. This is a genuine user-facing ceremony (it may
    /// prompt Face ID/Touch ID/a security key tap) — callers that already
    /// have a fresh `AuthenticateResult.prfOutput` from a preceding
    /// `authenticate(options:)` call with the same salt should prefer that
    /// instead of calling this again, to avoid a redundant prompt.
    ///
    /// Falls back to a local HKDF-of-credentialId derivation — which is
    /// **not** secret and **not** gated by device authentication — only when
    /// the real PRF path is unavailable (pre-iOS-18/macOS-15, no prior
    /// register/authenticate call to learn the rpId from, or the
    /// authenticator completed the ceremony without returning a PRF value).
    public func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput {
        if #available(iOS 18.0, macOS 15.0, *), let rpId = currentRpId() {
            if let real = try? await requestRealPrfOutput(rpId: rpId, credentialId: credentialId, salt: salt) {
                return real
            }
        }
        return try hkdfFallback(credentialId: credentialId, salt: salt)
    }

    // MARK: - PRF helpers

    @available(iOS 18.0, macOS 15.0, *)
    private static func prfOutput(from output: ASAuthorizationPublicKeyCredentialPRFAssertionOutput?) -> PrfOutput? {
        guard let output else { return nil }
        let first = output.first.withUnsafeBytes { Data($0) }
        let second = output.second.map { $0.withUnsafeBytes { Data($0) } }
        return PrfOutput(first: first, second: second)
    }

    @available(iOS 18.0, macOS 15.0, *)
    private func requestRealPrfOutput(rpId: String, credentialId: Data, salt: Data) async throws -> PrfOutput? {
        // The challenge here is never verified by a server — this ceremony
        // exists purely to extract the PRF output for a specific
        // credential/salt pair, so any fresh random value is fine.
        let probeChallenge = Data((0..<32).map { _ in UInt8.random(in: .min ... .max) })
        let inputValues = ASAuthorizationPublicKeyCredentialPRFAssertionInput.InputValues(
            saltInput1: salt, saltInput2: nil
        )
        let prfInput = ASAuthorizationPublicKeyCredentialPRFAssertionInput.inputValues(inputValues)

        let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpId)
        let platformRequest = platformProvider.createCredentialAssertionRequest(challenge: probeChallenge)
        platformRequest.allowedCredentials = [
            ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: credentialId),
        ]
        platformRequest.prf = prfInput

        let securityKeyProvider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: rpId)
        let securityKeyRequest = securityKeyProvider.createCredentialAssertionRequest(challenge: probeChallenge)
        securityKeyRequest.allowedCredentials = [
            ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor(
                credentialID: credentialId,
                transports: ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport.allSupported
            ),
        ]
        // See the comment in authenticate(options:) - the security-key
        // request's `.prf` setter requires iOS/macOS 26.4+.
        if #available(iOS 26.4, macOS 26.4, *) {
            securityKeyRequest.prf = prfInput
        }

        let authorization = try await performRequest([platformRequest, securityKeyRequest])

        switch authorization.credential {
        case let credential as ASAuthorizationPlatformPublicKeyCredentialAssertion:
            return Self.prfOutput(from: credential.prf)
        case let credential as ASAuthorizationSecurityKeyPublicKeyCredentialAssertion:
            if #available(iOS 26.4, macOS 26.4, *) {
                return Self.prfOutput(from: credential.prf)
            }
            return nil
        default:
            return nil
        }
    }

    /// Weaker, non-real fallback used only when the real WebAuthn PRF
    /// extension is unavailable (pre-iOS-18/macOS-15, or the authenticator
    /// doesn't support `hmac-secret`/PRF). This derives a value from the
    /// credential ID via HKDF, which is **not secret** (a credential ID
    /// isn't a private value) and **not gated by device authentication at
    /// all**. It exists only so older OS versions get *a* deterministic
    /// value instead of an error — the real PRF path above should always be
    /// preferred when available.
    private func hkdfFallback(credentialId: Data, salt: Data) throws -> PrfOutput {
        #if canImport(CryptoKit)
        let key = SymmetricKey(data: credentialId)
        let derived = HKDF<SHA256>.deriveKey(inputKeyMaterial: key, salt: salt, outputByteCount: 32)
        let data = derived.withUnsafeBytes { Data($0) }
        return PrfOutput(first: data)
        #else
        throw SirosError.auth(message: "PRF output requires CryptoKit")
        #endif
    }

    private func setLastRpId(_ rpId: String) {
        lock.lock()
        lastRpId = rpId
        lock.unlock()
    }

    private func currentRpId() -> String? {
        lock.lock()
        defer { lock.unlock() }
        return lastRpId
    }

    // MARK: - Private

    private func performRequest(_ requests: [ASAuthorizationRequest]) async throws -> ASAuthorization {
        try await withCheckedThrowingContinuation { cont in
            lock.lock()
            self.continuation = cont
            lock.unlock()

            let controller = ASAuthorizationController(authorizationRequests: requests)
            controller.delegate = self
            controller.presentationContextProvider = self

            DispatchQueue.main.async {
                controller.performRequests()
            }
        }
    }
}

@available(iOS 16.0, macOS 13.0, *)
extension ASAuthorizationAuthProvider: ASAuthorizationControllerDelegate {
    public func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        lock.lock()
        let cont = continuation
        continuation = nil
        lock.unlock()
        cont?.resume(returning: authorization)
    }

    public func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithError error: Error
    ) {
        lock.lock()
        let cont = continuation
        continuation = nil
        lock.unlock()
        cont?.resume(throwing: SirosError.auth(message: "ASAuthorization failed", underlying: error))
    }
}

@available(iOS 16.0, macOS 13.0, *)
extension ASAuthorizationAuthProvider: ASAuthorizationControllerPresentationContextProviding {
    public func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        anchor
    }
}
#endif

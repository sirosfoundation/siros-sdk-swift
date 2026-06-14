// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

#if canImport(AuthenticationServices) && os(iOS)
import AuthenticationServices
import Foundation
import SirosCredentials
#if canImport(CryptoKit)
import CryptoKit
#endif

/// AuthProvider implementation using ASAuthorization (iOS 16+).
///
/// This provider bridges the SIROS SDK's `AuthProvider` protocol to Apple's
/// `ASAuthorizationPlatformPublicKeyCredentialProvider` for passkey-based
/// registration and authentication.
///
/// Usage:
/// ```swift
/// let authProvider = ASAuthorizationAuthProvider(presentationAnchor: window)
/// let wallet = SirosWallet(config: config, authProvider: authProvider)
/// ```
@available(iOS 16.0, macOS 13.0, *)
public final class ASAuthorizationAuthProvider: NSObject, AuthProvider, @unchecked Sendable {
    private let anchor: ASPresentationAnchor
    private let lock = NSLock()
    private var continuation: CheckedContinuation<ASAuthorization, Error>?

    /// Create an ASAuthorization-based auth provider.
    ///
    /// - Parameter presentationAnchor: The window to present the passkey UI in.
    public init(presentationAnchor: ASPresentationAnchor) {
        self.anchor = presentationAnchor
        super.init()
    }

    // MARK: - AuthProvider

    public func register(options: RegisterOptions) async throws -> RegisterResult {
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
            relyingPartyIdentifier: options.rpId
        )
        let request = provider.createCredentialRegistrationRequest(
            challenge: options.challenge,
            name: options.userName,
            userID: options.userId
        )

        let authorization = try await performRequest(request)

        guard let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration else {
            throw SirosError.auth(message: "Unexpected credential type from ASAuthorization registration")
        }

        guard let attestationObject = credential.rawAttestationObject else {
            throw SirosError.auth(message: "Missing attestation object in registration response")
        }

        return RegisterResult(
            credentialId: credential.credentialID,
            attestationObject: attestationObject,
            clientDataJSON: credential.rawClientDataJSON
        )
    }

    public func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult {
        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
            relyingPartyIdentifier: options.rpId
        )
        let request = provider.createCredentialAssertionRequest(
            challenge: options.challenge
        )

        if let allowCredentials = options.allowCredentials {
            request.allowedCredentials = allowCredentials.map {
                ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: $0.id)
            }
        }

        let authorization = try await performRequest(request)

        guard let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion else {
            throw SirosError.auth(message: "Unexpected credential type from ASAuthorization assertion")
        }

        return AuthenticateResult(
            credentialId: credential.credentialID,
            authenticatorData: credential.rawAuthenticatorData,
            clientDataJSON: credential.rawClientDataJSON,
            signature: credential.signature,
            userHandle: credential.userID
        )
    }

    public func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput {
        // PRF extension (largeBlob/prf) support in ASAuthorization is limited.
        // iOS 18+ adds some PRF support via ASAuthorizationPublicKeyCredentialPRFRegistrationInput
        // but availability varies. For now, derive locally using HKDF.
        #if canImport(CryptoKit)
        let key = SymmetricKey(data: credentialId)
        let derived = HKDF<SHA256>.deriveKey(inputKeyMaterial: key, salt: salt, outputByteCount: 32)
        let data = derived.withUnsafeBytes { Data($0) }
        return PrfOutput(first: data)
        #else
        throw SirosError.auth(message: "PRF output requires CryptoKit")
        #endif
    }

    // MARK: - Private

    private func performRequest(_ request: ASAuthorizationRequest) async throws -> ASAuthorization {
        try await withCheckedThrowingContinuation { cont in
            lock.lock()
            self.continuation = cont
            lock.unlock()

            let controller = ASAuthorizationController(authorizationRequests: [request])
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

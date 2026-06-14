// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials

/// Authenticator abstraction for FIDO2/WebAuthn operations.
/// SDK consumers provide their own platform-specific implementation
/// (e.g. ASAuthorizationController on iOS, CredentialManager on Android).
public protocol AuthProvider: AnyObject, Sendable {
    /// Create a new passkey credential (registration).
    func register(options: RegisterOptions) async throws -> RegisterResult

    /// Authenticate with an existing passkey (assertion).
    func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult

    /// Obtain PRF output for keystore key derivation.
    func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput
}

// MARK: - Registration types

public struct RegisterOptions: Sendable {
    public var rpId: String
    public var rpName: String
    public var userId: Data
    public var userName: String
    public var userDisplayName: String
    public var challenge: Data
    public var attestation: String
    public var authenticatorSelection: AuthenticatorSelection?
    public var prfSalt: Data?

    public init(
        rpId: String,
        rpName: String,
        userId: Data,
        userName: String,
        userDisplayName: String,
        challenge: Data,
        attestation: String = "none",
        authenticatorSelection: AuthenticatorSelection? = nil,
        prfSalt: Data? = nil
    ) {
        self.rpId = rpId
        self.rpName = rpName
        self.userId = userId
        self.userName = userName
        self.userDisplayName = userDisplayName
        self.challenge = challenge
        self.attestation = attestation
        self.authenticatorSelection = authenticatorSelection
        self.prfSalt = prfSalt
    }
}

public struct AuthenticatorSelection: Sendable {
    public var authenticatorAttachment: String?
    public var residentKey: String
    public var userVerification: String

    public init(
        authenticatorAttachment: String? = nil,
        residentKey: String = "required",
        userVerification: String = "preferred"
    ) {
        self.authenticatorAttachment = authenticatorAttachment
        self.residentKey = residentKey
        self.userVerification = userVerification
    }
}

public struct RegisterResult: Sendable {
    public var credentialId: Data
    public var attestationObject: Data
    public var clientDataJSON: Data
    public var prfOutput: PrfOutput?

    public init(credentialId: Data, attestationObject: Data, clientDataJSON: Data, prfOutput: PrfOutput? = nil) {
        self.credentialId = credentialId
        self.attestationObject = attestationObject
        self.clientDataJSON = clientDataJSON
        self.prfOutput = prfOutput
    }
}

// MARK: - Authentication types

public struct AuthenticateOptions: Sendable {
    public var rpId: String
    public var challenge: Data
    public var allowCredentials: [AllowCredential]?
    public var userVerification: String
    public var prfSalt: Data?

    public init(
        rpId: String,
        challenge: Data,
        allowCredentials: [AllowCredential]? = nil,
        userVerification: String = "preferred",
        prfSalt: Data? = nil
    ) {
        self.rpId = rpId
        self.challenge = challenge
        self.allowCredentials = allowCredentials
        self.userVerification = userVerification
        self.prfSalt = prfSalt
    }
}

public struct AllowCredential: Sendable {
    public var id: Data
    public var type: String

    public init(id: Data, type: String = "public-key") {
        self.id = id
        self.type = type
    }
}

public struct AuthenticateResult: Sendable {
    public var credentialId: Data
    public var authenticatorData: Data
    public var clientDataJSON: Data
    public var signature: Data
    public var userHandle: Data?
    public var prfOutput: PrfOutput?

    public init(
        credentialId: Data,
        authenticatorData: Data,
        clientDataJSON: Data,
        signature: Data,
        userHandle: Data? = nil,
        prfOutput: PrfOutput? = nil
    ) {
        self.credentialId = credentialId
        self.authenticatorData = authenticatorData
        self.clientDataJSON = clientDataJSON
        self.signature = signature
        self.userHandle = userHandle
        self.prfOutput = prfOutput
    }
}

public struct PrfOutput: Sendable {
    public var first: Data
    public var second: Data?

    public init(first: Data, second: Data? = nil) {
        self.first = first
        self.second = second
    }
}

// MARK: - Session

/// Session tokens returned after successful authentication.
public struct AuthSession: Codable, Sendable, Equatable {
    public var appToken: String
    public var uuid: String
    public var displayName: String?
    public var username: String?
    public var refreshToken: String?
    public var did: String?
    public var privateData: String?
    public var tenantId: String?

    public init(
        appToken: String,
        uuid: String,
        displayName: String? = nil,
        username: String? = nil,
        refreshToken: String? = nil,
        did: String? = nil,
        privateData: String? = nil,
        tenantId: String? = nil
    ) {
        self.appToken = appToken
        self.uuid = uuid
        self.displayName = displayName
        self.username = username
        self.refreshToken = refreshToken
        self.did = did
        self.privateData = privateData
        self.tenantId = tenantId
    }
}

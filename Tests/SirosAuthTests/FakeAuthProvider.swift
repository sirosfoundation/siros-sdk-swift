// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosAuth

/// A fake AuthProvider for testing WebAuthnAuthClient without real passkeys.
final class FakeAuthProvider: AuthProvider, @unchecked Sendable {
    var registerResult: RegisterResult
    var authenticateResult: AuthenticateResult
    var lastRegisterOptions: RegisterOptions?
    var lastAuthenticateOptions: AuthenticateOptions?

    init(registerResult: RegisterResult, authenticateResult: AuthenticateResult) {
        self.registerResult = registerResult
        self.authenticateResult = authenticateResult
    }

    func register(options: RegisterOptions) async throws -> RegisterResult {
        lastRegisterOptions = options
        return registerResult
    }

    func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult {
        lastAuthenticateOptions = options
        return authenticateResult
    }

    func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput {
        PrfOutput(first: credentialId + salt)
    }
}

// MARK: - Default test fixtures

func defaultRegisterResult() -> RegisterResult {
    RegisterResult(
        credentialId: Data([9, 9, 9]),
        attestationObject: Data("attestation".utf8),
        clientDataJSON: Data("client-data".utf8)
    )
}

func defaultAuthenticateResult() -> AuthenticateResult {
    AuthenticateResult(
        credentialId: Data([9, 9, 9]),
        authenticatorData: Data("auth-data".utf8),
        clientDataJSON: Data("client-data".utf8),
        signature: Data("sig".utf8)
    )
}

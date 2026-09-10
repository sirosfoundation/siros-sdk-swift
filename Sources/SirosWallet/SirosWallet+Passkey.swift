import Foundation
import SirosAuth
import SirosCredentials

// MARK: - Passkey assertion shared by login() and unlockKeystore()

extension SirosWallet {
    /// Outcome of one passkey assertion against the auth server's login
    /// challenge: what `loginFinish` needs, plus the PRF output already
    /// resolved so the caller can fail before touching the server session.
    struct PasskeyAssertion {
        let challengeId: String
        let credential: [String: Any]
        let prfOutput: PrfOutput
    }

    /// Runs `loginBegin` -> platform `authenticate` -> PRF resolution.
    ///
    /// Shared by `login()` and `unlockKeystore()`. The PRF output is resolved
    /// here, BEFORE the caller's `loginFinish`: `getPrfOutput` fails closed for
    /// an authenticator without PRF, and the server must not be handed a
    /// completed login for a session this side can never unlock.
    func performPasskeyAssertion(asClient: AuthServerClient) async throws -> PasskeyAssertion {
        let storedPrfSalt = sessionStore.prfSalt.flatMap { Self.b64Decode($0) }

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

        let result = try await authProvider.authenticate(options: AuthenticateOptions(
            rpId: rpId,
            challenge: challenge,
            prfSalt: storedPrfSalt
        ))

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
        let prfOutput = try await resolvePrfOutput(
            ceremonyPrf: result.prfOutput,
            credentialId: result.credentialId,
            salt: storedPrfSalt ?? Self.randomBytes(32)
        )
        return PasskeyAssertion(challengeId: challengeId, credential: credential, prfOutput: prfOutput)
    }

    /// Resolves the PRF output for a completed WebAuthn ceremony.
    ///
    /// Prefers the PRF output the ceremony itself produced (a real
    /// ASAuthorization PRF assertion, or LocalAuthProvider's locally computed
    /// value) so the user isn't prompted twice; otherwise runs a separate
    /// `getPrfOutput()` ceremony with the real credential ID — never an empty
    /// placeholder. `getPrfOutput` fails closed for authenticators without
    /// PRF, so callers resolve this BEFORE completing the server-side
    /// register/login step.
    func resolvePrfOutput(ceremonyPrf: PrfOutput?, credentialId: Data, salt: Data) async throws -> PrfOutput {
        if let ceremonyPrf { return ceremonyPrf }
        return try await authProvider.getPrfOutput(credentialId: credentialId, salt: salt)
    }
}

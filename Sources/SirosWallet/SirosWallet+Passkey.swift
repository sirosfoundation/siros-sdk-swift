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
        /// The salt `prfOutput` was evaluated for - what the session store must
        /// record, since the container's PRF key is bound to it.
        let prfSalt: Data
        /// The cached account whose passkey answered the ceremony, if known.
        let cachedAccount: CachedAccount?
    }

    /// Runs `loginBegin` -> platform `authenticate` -> PRF resolution.
    ///
    /// Shared by `login()` and `unlockKeystore()`. The PRF output is resolved
    /// here, BEFORE the caller's `loginFinish`: `getPrfOutput` fails closed for
    /// an authenticator without PRF, and the server must not be handed a
    /// completed login for a session this side can never unlock.
    func performPasskeyAssertion(asClient: AuthServerClient) async throws -> PasskeyAssertion {
        // After logout() the account-scoped session store is empty, so the
        // durable source of salts is the account registry: offer every
        // loginable credential with its own salt (WebAuthn evalByCredential)
        // and let the authenticator evaluate PRF for whichever one the user
        // picks. The session store's salt still covers the unlock-after-resume
        // case, where the active account is known.
        let storedPrfSalt = sessionStore.prfSalt.flatMap { Self.b64Decode($0) }
        let candidates = loginPrfCandidates()

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

        let options = AuthenticateOptions(
            rpId: rpId,
            challenge: challenge,
            prfSalt: storedPrfSalt,
            prfSaltsByCredential: candidates.isEmpty ? nil : candidates
        )
        let result = try await authProvider.authenticate(options: options)

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
        // The salt that applies to the credential the user actually used: its
        // registry entry first; else the session store's salt, but only when
        // the credential is not known to belong to a different cached account
        // (the session salt is the active account's - pairing it with another
        // account's credential would derive a real PRF under the wrong salt
        // and fail only later, at unwrap). A fresh random salt is only right
        // when nothing is known about this credential at all (first login on
        // a new install with no registry entry) - then no container could be
        // opened anyway and the unlock fails on unwrap rather than on a
        // silently wrong key.
        let cachedAccount = cachedAccount(owning: result.credentialId)
        let sessionSaltApplies = cachedAccount == nil || cachedAccount?.accountId == sessionStore.activeAccountId
        let prfSalt = options.prfSalt(for: result.credentialId)
            ?? (sessionSaltApplies ? storedPrfSalt : nil)
            ?? Self.randomBytes(32)
        let prfOutput = try await resolvePrfOutput(
            ceremonyPrf: result.prfOutput,
            credentialId: result.credentialId,
            salt: prfSalt
        )
        return PasskeyAssertion(
            challengeId: challengeId,
            credential: credential,
            prfOutput: prfOutput,
            prfSalt: prfSalt,
            cachedAccount: cachedAccount
        )
    }

    /// `(credentialId, prfSalt)` for every passkey login should offer - every
    /// loginable account's, since which one the user picks is only known once
    /// the ceremony completes. Mirrors the Kotlin SDK's `loginCandidates`.
    func loginPrfCandidates() -> [Data: Data] {
        var candidates: [Data: Data] = [:]
        for account in accountRegistry.listLoginableAccounts() {
            for passkey in account.passkeys where !passkey.prfSalt.isEmpty {
                guard let credentialId = Self.b64UrlDecode(passkey.credentialId),
                      let salt = Self.b64Decode(passkey.prfSalt) else { continue }
                candidates[credentialId] = salt
            }
        }
        return candidates
    }

    /// The cached account that registered `credentialId`, if any.
    func cachedAccount(owning credentialId: Data) -> CachedAccount? {
        let credIdB64url = Self.b64UrlEncode(credentialId)
        return accountRegistry.listAccounts().first { account in
            account.passkeys.contains { $0.credentialId == credIdB64url }
        }
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

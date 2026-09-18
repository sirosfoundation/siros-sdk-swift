// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosAuth
import SirosCredentials

#if canImport(os)
import os
private let logger = Logger(subsystem: "org.siros.sdk", category: "SirosWallet")
#endif

/// Which cached account a lifecycle refusal is about - the question only a
/// `.deactivated` refusal has to answer, because it is the only one that
/// forgets anything.
enum LifecycleRefusalSubject: Sendable, Equatable {
    /// The account this session is logged in as. Right for `resumeSession()`,
    /// `unlockKeystore()` and the SDK's own re-login after a token cut-off:
    /// all three are already scoped to one account, and the registry names it.
    case activeAccount

    /// Exactly this account, or nothing when the caller could not work out
    /// which one the refusal was about.
    ///
    /// `login()` uses this and must never fall back to the active account.
    /// Its refusal comes out of `loginFinish`, before the registry's active
    /// account is moved (that only happens once the keystore unlock has
    /// succeeded), so the account that *is* active belongs to the previous
    /// session - possibly a different user entirely. And a login from the
    /// picker may complete with a platform passkey that has no registry entry
    /// at all, in which case the honest answer is "unknown": keeping a stale
    /// entry on the login screen is a blemish, forgetting the wrong account
    /// destroys a working wallet.
    case resolved(String?)

    /// The account to forget, if any.
    func accountId(in registry: AccountRegistry) -> String? {
        switch self {
        case .activeAccount: return registry.activeAccountId
        case .resolved(let id): return id
        }
    }
}

/// The wallet instance lifecycle's effect on *this* session (SID-AUTH-06):
/// recognising a refusal, the single self-driven re-login after a token
/// cut-off, and the session generation that keeps both of those from acting on
/// a session that is already gone.
///
/// Split out of `SirosWallet.swift` for size - that file is against SwiftLint's
/// `file_length` limit - but it is a cohesive seam: everything here is about
/// when a session ends and what may replace it.
extension SirosWallet {

    // MARK: - Lifecycle refusals and the cut-off re-login (SID-AUTH-06)

    /// Drop everything the backend's lifecycle cut-off just invalidated - the
    /// cached tokens, the API client built on them and the engine WebSocket,
    /// which the backend re-checks at every flow start - and log in once.
    /// `login()` itself routes the outcome: a lifecycle `403` to
    /// `.lifecycleBlocked`, a success to `.ready`, anything else to `.error`.
    ///
    /// Not `private`: `SirosWallet+Engine.swift` reaches it through
    /// `handleReauthenticationRequired` - same cross-file-extension-access
    /// reason as `keystore` above.
    /// - Parameter generation: the session generation this re-login is
    ///   replacing, from `beginSelfDrivenRelogin()`. Captured when the signal
    ///   was accepted rather than when this task happens to start, so a logout
    ///   racing the task is caught however the two are scheduled.
    func reloginAfterCutOff(replacing generation: Int) async {
        lock.lock()
        let engine = engineSession
        // The WMP transport holds its own live WebSocket, and the backend
        // re-checks the cut-off at every flow start - leaving it connected
        // would keep a socket authenticated by a token the backend has already
        // stopped accepting, and `connectViaWmp` would overwrite the reference
        // on a successful re-login without ever closing it.
        let peer = wmpPeer
        engineSession = nil
        wmpPeer = nil
        credentialNotifier = nil
        apiClient = nil
        lock.unlock()
        engine?.disconnect()
        if let peer { try? await peer.close() }
        cancelEngineTasks()
        authTokens?.clear()
        // AuthServerClient keeps its own token cache, and a token minted
        // before the cut-off is refused with 401 however fresh it looks. Clear
        // it explicitly - logout() would clear it too but ends the session
        // first, which is the opposite of what a re-login needs.
        await authServerClient?.clearTokenCache()
        // Lock the key material too, the way logout() does. The session is
        // already gone server-side; if the replacement login then fails (a
        // cancelled passkey ceremony, no network, or a lifecycle refusal) the
        // wallet must not be left holding an unlocked keystore whose
        // credentials are still signable. A successful login() unlocks it
        // again as part of its normal path.
        keystore.lock()
        // The teardown above awaits the WMP peer's shutdown, and the caller
        // may have logged out or destroyed the wallet in the meantime. Logging
        // back in then would resurrect a session the user explicitly ended -
        // and race the asynchronous AS logout.
        lock.lock()
        let superseded = sessionGeneration != generation
        lock.unlock()
        if superseded {
            #if canImport(os)
            logger.info("Self-driven re-login abandoned: the session it was replacing is already gone")
            #endif
            return
        }
        // login() puts every outcome in the state itself; its `throw` is only
        // for the unexpected branch and must not escape a self-driven attempt.
        // This one replaces a session the registry still names, so a refusal
        // that arrives before the passkey ceremony completes (the AS can refuse
        // `loginBegin` too) is unambiguously about that account - unlike a
        // user-driven login, which may be for someone else entirely.
        try? await login(refusalFallback: .activeAccount)
        // The check above cannot be atomic with the call - login() is a long
        // async operation and logout()/destroy() are synchronous and can land
        // anywhere inside it. So undo rather than prevent: a session
        // established after the user ended the one it was replacing is torn
        // down again here, which is the outcome they asked for.
        lock.lock()
        let endedUnderneath = sessionGeneration != generation + 1 || isDestroyed
        lock.unlock()
        if endedUnderneath, case .ready = state {
            #if canImport(os)
            logger.info("Self-driven re-login undone: the session it replaced was ended while it ran")
            #endif
            endSessionLocally()
            setState(.disconnected(cachedAccounts: accountRegistry.listLoginableAccounts()))
        }
    }

    /// `reloginAfterCutOff(replacing:)` under the once-only guard.
    func reloginAfterLifecycleChange() async {
        guard let generation = beginSelfDrivenRelogin() else { return }
        await reloginAfterCutOff(replacing: generation)
        endSelfDrivenRelogin()
    }

    /// Claims the right to run the SDK's own re-login, at most once per
    /// session. Refuses when one is already running, when one has already been
    /// run for this session generation (late 401s from requests issued before
    /// the cut-off), or when the wallet no longer believes it has a session to
    /// replace - after a logout, an error or a lifecycle block, a silent
    /// WebAuthn prompt is never the right answer.
    /// - Returns: the session generation the re-login is replacing, or nil
    ///   when it must not run.
    func beginSelfDrivenRelogin() -> Int? {
        lock.lock(); defer { lock.unlock() }
        if isDestroyed { return nil }
        if reloginInProgress { return nil }
        if reloginDoneForGeneration { return nil }
        // `_state` directly: `state` takes the same non-recursive lock.
        guard Self.isReplaceableSession(_state) else { return nil }
        reloginDoneForGeneration = true
        reloginInProgress = true
        return sessionGeneration
    }

    /// Whether [state] describes a session worth replacing. After a logout, an
    /// error or a lifecycle block there is nothing to replace, and a silent
    /// WebAuthn prompt would be the wrong answer.
    private static func isReplaceableSession(_ state: WalletState) -> Bool {
        switch state {
        // Deliberately NOT `.connecting`: that is also where the initial
        // `login()` and `resumeSession()` sit before their own session setup
        // finishes, and a 401 from `/auth/token` fires `onSessionRejected`
        // immediately. Treating it as replaceable would let a second WebAuthn
        // ceremony start underneath the first and race its state, its API
        // client and its keystore. There is no session to replace until one
        // has been established.
        case .ready, .flowActive, .keystoreLocked: return true
        case .connecting, .disconnected, .error, .lifecycleBlocked: return false
        }
    }

    /// Ends the current session generation and returns the new one. Call
    /// whenever a session ends or is replaced.
    @discardableResult
    func bumpSessionGeneration() -> Int {
        lock.lock(); defer { lock.unlock() }
        sessionGeneration += 1
        reloginDoneForGeneration = false
        return sessionGeneration
    }

    func endSelfDrivenRelogin() {
        lock.lock(); reloginInProgress = false; lock.unlock()
    }

    /// Route `error` into `WalletState.lifecycleBlocked` when it is a
    /// SID-AUTH-06 refusal. Returns true when it handled the error, so callers
    /// can leave their own error handling untouched for everything else.
    ///
    /// What happens to the cached account follows the EUDI wallet-unit
    /// lifecycle, which SIROS adopts exactly, and turns on the refusal's
    /// `scope` (go-wallet-backend#340) - never on the human-readable
    /// `message`:
    ///
    /// - `.suspended` and `.revoked` are scoped to *this* wallet instance. The
    ///   user's other devices and passkeys keep working, so the cached account
    ///   and the cached credentials stay: forgetting them on a per-instance
    ///   revocation would destroy passkeys that are still perfectly valid.
    /// - `.deactivated` is the whole wallet: every instance revoked and the
    ///   data erased server-side, so the cached account decrypts a vault that
    ///   no longer exists and a new enrollment is the only way forward. That
    ///   one is forgotten here, exactly as `deactivateWallet()` forgets it
    ///   when the user asks for the same thing from this device.
    ///
    /// A backend older than #340 sends no `scope`, and `WALLET_REVOKED` then
    /// resolves to the per-instance `.revoked` - see
    /// `SirosError.WalletLifecycleRefusal.resolve(errorCode:scope:)`. Against
    /// such a backend this path behaves exactly as it did before #340.
    ///
    /// - Parameter subject: which cached account the refusal is about. Only
    ///   consulted for `.deactivated`; see `LifecycleRefusalSubject` for why
    ///   `login()` must not settle for the registry's active account.
    @discardableResult
    func handleLifecycleRefusal(
        _ error: Error, subject: LifecycleRefusalSubject = .activeAccount
    ) async -> Bool {
        guard let sirosError = error as? SirosError,
              let reason = sirosError.walletLifecycleRefusal else { return false }
        let message = sirosError.serverMessage
        #if canImport(os)
        logger.warning("Wallet lifecycle refusal: \(reason.errorCode) (\(sirosError.serverScope ?? "no scope")) — \(message ?? "(no message from the backend)")")
        #endif
        // Read before the teardown: `endSessionLocally()` clears the registry's
        // active account id, so asking afterwards always answers nil and a
        // deactivated wallet would keep its now-useless cached account.
        let accountToForget: String? = reason == .deactivated ? subject.accountId(in: accountRegistry) : nil
        // End the session either way - nothing this installation holds can be
        // used until someone else acts - and do not schedule the remote
        // DELETE: a retry after the instance is reactivated reuses the same AS
        // session cookie, and the DELETE could land after its loginFinish. See
        // `endSessionLocally()`.
        endSessionLocally()
        // `endSessionLocally()` clears `AuthTokens`, but `AuthServerClient`
        // keeps its own cache: a backend token minted just before the 403
        // arrived (during the private-data fetch or the engine connect) would
        // otherwise be served straight back to the retry without the AS ever
        // being asked, and it is already cut off. Awaited here, so it cannot
        // race the retry the app may make the moment this state is published.
        await authServerClient?.clearTokenCache()
        if let accountToForget {
            // The same path `deactivateWallet()` takes. The active id is
            // already nil by now, so this removes the entry and publishes
            // `.disconnected` rather than running a second `logout()` (and its
            // `DELETE /auth/session`, which must not race anything here); the
            // `.lifecycleBlocked` set immediately below is the state that
            // stands, now without this account in `cachedAccounts`.
            forgetAccount(accountId: accountToForget)
        }
        setState(.lifecycleBlocked(
            reason: reason,
            message: message,
            cachedAccounts: accountRegistry.listLoginableAccounts()
        ))
        lock.lock(); let listener = eventListener; lock.unlock()
        listener?.onWalletLifecycleBlocked(reason: reason, message: message)
        return true
    }
}

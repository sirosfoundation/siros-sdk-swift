// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Base error type for the SIROS SDK.
///
/// Each case exposes a machine-readable ``errorCode`` that consuming
/// applications can use to look up localized user-facing messages:
///
/// ```swift
/// let key = "error_\(error.errorCode)"
/// let localized = NSLocalizedString(key, comment: "")
/// ```
public enum SirosError: Error, Sendable {
    case network(message: String, underlying: Error? = nil)
    case auth(message: String, underlying: Error? = nil)
    case keystore(message: String, underlying: Error? = nil)
    case wallet(message: String, underlying: Error? = nil)
    case backendApi(code: Int, message: String, body: String? = nil)
    /// `SirosWallet.renewCredential(batchId:)`'s one specifically
    /// recoverable failure: no refresh_token is on file for this batch (it
    /// was never captured, or already consumed by a prior renewal) - a
    /// distinct case (rather than folding this into `.wallet`) so a caller
    /// can tell "fall back to full re-issuance" apart from every other
    /// failure (not connected, another issuance in progress, network
    /// error), which should surface to the user instead of being silently
    /// retried as a full re-issuance.
    case renewalUnavailable(batchId: Int64)

    /// Why a SIROS backend refused this installation with `403` for wallet
    /// lifecycle reasons (SID-AUTH-06, go-wallet-backend#319/#340). None is
    /// retryable with the same passkey; what differs is how much is over.
    ///
    /// The wire carries two fields, an `error` code and a `scope`
    /// (go-wallet-backend#340), and the SDK folds them into one value here -
    /// see `resolve(errorCode:scope:)`, which is the only supported way to
    /// build one from a refusal body. SIROS follows the EUDI wallet-unit
    /// lifecycle exactly: revoking one wallet instance ends that device and
    /// nothing else, and only deactivating the wallet is terminal for the
    /// whole wallet.
    public enum WalletLifecycleRefusal: Sendable, Hashable, CaseIterable {
        /// `WALLET_SUSPENDED`, scope `instance`. Reversible: another device or
        /// the provider reactivates this instance and a later `login()`
        /// succeeds. Nothing local is lost.
        case suspended

        /// `WALLET_REVOKED`, scope `instance`. Terminal for *this*
        /// installation's wallet instance only - the user's other devices and
        /// passkeys keep working, and this one needs a fresh enrollment.
        /// Nothing local is lost, because the account still exists.
        case revoked

        /// `WALLET_REVOKED`, scope `wallet`. Terminal for the whole wallet in
        /// this tenant: every instance is revoked and the wallet's data was
        /// erased server-side, so nothing the user holds here can be used
        /// again and a new enrollment is required. This is the one refusal
        /// that makes the cached account worthless, and the SDK forgets it.
        ///
        /// `scope` is per-tenant: this says the wallet cannot be opened in
        /// this tenant, not that nothing of the user's is left anywhere.
        case deactivated

        /// The wire `error` code this refusal arrives as. `.revoked` and
        /// `.deactivated` deliberately share `WALLET_REVOKED`: the code alone
        /// cannot tell them apart, only the accompanying `scope` can.
        public var errorCode: String {
            switch self {
            case .suspended: return "WALLET_SUSPENDED"
            case .revoked, .deactivated: return "WALLET_REVOKED"
            }
        }

        /// The refusal an `error`/`scope` pair from a refusal body names, or
        /// nil when `errorCode` is not a lifecycle refusal at all.
        ///
        /// Resolution is deliberately conservative. `scope` only arrived with
        /// go-wallet-backend#340, so a `WALLET_REVOKED` with no `scope` - an
        /// older backend, which is every deployment until that ships - MUST
        /// resolve to the per-instance `.revoked`: treating it as
        /// `.deactivated` would forget an account whose other passkeys still
        /// work. An unrecognised `scope` falls back the same way. The
        /// human-readable `message` is never consulted; guessing from prose
        /// would be worse than not knowing.
        ///
        /// The `scope` match is exact, not case-folded: the backend emits the
        /// literal `"wallet"`, and the one value that costs the user their
        /// cached account should be recognised only as the protocol spells it.
        public static func resolve(errorCode: String, scope: String?) -> WalletLifecycleRefusal? {
            guard let base = WalletLifecycleRefusal(rawValue: errorCode) else { return nil }
            guard base == .revoked, scope == walletLifecycleScopeWallet else { return base }
            return .deactivated
        }
    }

    /// The lifecycle refusal carried by a `403 .backendApi` error, or nil for
    /// every other error. Kept as a helper rather than a new enum case so
    /// exhaustive `switch`es over `SirosError` keep compiling.
    ///
    /// Resolved from both `error` and `scope` in the body - see
    /// `WalletLifecycleRefusal.resolve(errorCode:scope:)` for why a missing
    /// `scope` resolves to the per-instance case.
    public var walletLifecycleRefusal: WalletLifecycleRefusal? {
        guard case let .backendApi(code, _, _) = self, code == 403,
              let body = errorBody, let error = body["error"] as? String else { return nil }
        return WalletLifecycleRefusal.resolve(errorCode: error, scope: body["scope"] as? String)
    }

    /// The machine-readable `scope` of a lifecycle refusal (`instance` or
    /// `wallet`, go-wallet-backend#340), carried raw next to `serverMessage`
    /// so a host app can see exactly what the backend said. Nil on an older
    /// backend, which sends no `scope` at all. Prefer
    /// `walletLifecycleRefusal`, which resolves this into a typed case.
    public var serverScope: String? {
        errorBody?["scope"] as? String
    }

    /// The backend's stable `error` code from this error's JSON body (e.g.
    /// `ERASURE_INCOMPLETE`, `CREDENTIAL_NOT_OWNED`), or nil when this is not
    /// a `.backendApi` error or its body carries none. Lets callers branch on
    /// the protocol's error codes without each re-parsing the body.
    public var apiErrorCode: String? {
        errorBody?["error"] as? String
    }

    /// The server's own user-facing explanation (`message` in the error body),
    /// when it sent one - e.g. the text a SID-AUTH-06 `WALLET_SUSPENDED` /
    /// `WALLET_REVOKED` refusal carries for the user, which may say more than
    /// the app can (who suspended it, why). It is prose meant for display, not
    /// a signal to branch on: `serverScope` and `walletLifecycleRefusal` are
    /// what tell the refusals apart. `localizedDescription` stays the
    /// developer-facing diagnostic.
    public var serverMessage: String? {
        errorBody?["message"] as? String
    }

    private var errorBody: [String: Any]? {
        guard case let .backendApi(_, _, body) = self, let body,
              let data = body.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return json
    }

    /// Machine-readable error code for i18n mapping.
    public var errorCode: String {
        switch self {
        case .network: return "network_error"
        case .auth: return "auth_failed"
        case .keystore: return "keystore_error"
        case .wallet: return "wallet_error"
        case .backendApi(let code, _, _): return "backend_api_\(code)"
        case .renewalUnavailable: return "renewal_unavailable"
        }
    }
}

/// The `scope` a lifecycle refusal carries (go-wallet-backend#340): the
/// refusal ends this wallet instance only.
public let walletLifecycleScopeInstance = "instance"

/// The `scope` a lifecycle refusal carries (go-wallet-backend#340): the
/// refusal ends the whole wallet in this tenant - every instance revoked, the
/// data erased server-side, a new enrollment required.
public let walletLifecycleScopeWallet = "wallet"

public extension SirosError.WalletLifecycleRefusal {
    /// The wire `error` code, under the name it had when this was a
    /// `String`-backed enum. Kept so existing call sites keep compiling;
    /// `errorCode` is the name to use.
    ///
    /// Note this is **not** injective any more - `.revoked` and `.deactivated`
    /// both answer `WALLET_REVOKED` - which is exactly why the type does not
    /// conform to `RawRepresentable`: reconstructing a refusal needs the
    /// `scope` too. Use `resolve(errorCode:scope:)`.
    var rawValue: String { errorCode }

    /// The refusal a bare `error` code names, with no `scope` to go on. Kept
    /// for source compatibility and resolves conservatively - `WALLET_REVOKED`
    /// becomes the per-instance `.revoked`, never `.deactivated`. Prefer
    /// `resolve(errorCode:scope:)`, which can see the difference.
    init?(rawValue: String) {
        switch rawValue {
        case SirosError.WalletLifecycleRefusal.suspended.errorCode: self = .suspended
        case SirosError.WalletLifecycleRefusal.revoked.errorCode: self = .revoked
        default: return nil
        }
    }
}

extension SirosError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .network(let message, _): return message
        case .auth(let message, _): return message
        case .keystore(let message, _): return message
        case .wallet(let message, _): return message
        case .backendApi(let code, let message, _): return "\(code): \(message)"
        case .renewalUnavailable(let batchId):
            return "No refresh_token stored for batch \(batchId) - it may not be renewable, or was already renewed"
        }
    }
}

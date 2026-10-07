// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosTransport

extension SirosWallet {
    /// Runtime switch for EC TS12 payment-SCA `transaction_data` handling.
    /// Default `false` (`WalletConfig.transactionDataEnabled`). Readable and
    /// writable at any time from any thread; a change applies to flows
    /// started after it, a flow already in progress keeps the setting it
    /// started with. WMP offers capabilities per session, so a change takes
    /// effect on the WMP transport at the next session (reconnect).
    public var transactionDataEnabled: Bool {
        get { lock.lock(); defer { lock.unlock() }; return transactionDataEnabledValue }
        set { lock.lock(); transactionDataEnabledValue = newValue; lock.unlock() }
    }

    /// Effective enablement: the flag is on AND a consent handler is
    /// registered (`transactionConsentHandlerRegistered`: no handler API
    /// exists yet, so it is `false` and TS12 can never be effectively
    /// enabled). Without a handler the wallet cannot show the transaction, so
    /// it behaves as disabled.
    var transactionDataEffectivelyEnabled: Bool {
        lock.lock(); defer { lock.unlock() }
        return transactionDataEnabledValue && transactionConsentHandlerRegistered
    }

    /// `flow_start.features` for a flow started now (legacy engine).
    var transactionDataEngineFeatures: [String]? {
        TransactionDataDeclaration.engineFeatures(enabled: transactionDataEffectivelyEnabled)
    }

    /// `capabilities_offered` for a WMP session created now.
    var transactionDataWmpCapabilities: [String: AnyCodable]? {
        TransactionDataDeclaration.wmpCapabilitiesOffered(enabled: transactionDataEffectivelyEnabled)
    }
}

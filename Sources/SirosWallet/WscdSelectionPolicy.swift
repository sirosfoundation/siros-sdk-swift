// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosKeystore

/// The host app's answer to a `RequestWscdChoice` prompt - mirrors
/// `ProximityConsentResult`'s "chosen or cancelled" shape (see
/// `MdocProximitySession.RequestProximityConsent` in `SirosKeystore`), the
/// established pattern in this SDK for an async host-UI bridge callback.
public enum WscdChoiceResult: Sendable {
    case chosen(pluginId: String)
    case cancelled
}

/// Asks the user to pick which registered WSCD plugin to use for an
/// about-to-be-issued credential, invoked only when more than one plugin
/// the host app has registered (`WalletConfig.availableKeystores`) meets
/// the credential type's declared key-storage assurance requirement - see
/// `WscdSelectionPolicy.resolve`. Implemented by the host app as an async
/// bridge to its own picker UI.
///
/// Only a plugin ID is returned (not a `KeystoreManager` instance) - the
/// SDK already holds the concrete instance via
/// `WalletConfig.availableKeystores`, since that dictionary is how the host
/// app registers what's available in the first place.
///
/// - Parameters:
///   - issuer: the credential issuer URL.
///   - credentialType: the vct (SD-JWT) or doctype (mdoc) being issued.
///   - eligiblePluginIds: every registered plugin ID whose static nominal
///     tier (`WscdPluginCapabilities`) meets the requirement - always 2 or
///     more when this callback is invoked (exactly one match is auto-picked
///     without a prompt, and zero matches is a hard error instead - see
///     `WscdSelectionError.noEligiblePlugin`).
public typealias RequestWscdChoice = @Sendable (
    _ issuer: String,
    _ credentialType: String,
    _ eligiblePluginIds: [String]
) async -> WscdChoiceResult

/// Thrown by `WscdSelectionPolicy.resolve` when zero registered plugins'
/// static nominal tier meets the credential type's declared requirement.
/// Deliberately a distinct thrown signal rather than a soft `nil` return:
/// silently proceeding with an insufficient plugin (or falling back to
/// whatever the default keystore happens to be) would defeat this feature's
/// entire purpose - the issuer would still reject the resulting Key
/// Attestation, just later and less clearly than surfacing it here.
public enum WscdSelectionError: Error, Sendable, Equatable {
    case noEligiblePlugin(issuer: String, credentialType: String, requiredTier: String)
}

extension WscdSelectionError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .noEligiblePlugin(let issuer, let credentialType, let requiredTier):
            return "No available authenticator meets the required key-storage tier " +
                "(\(requiredTier)) for credential type \(credentialType) from issuer \(issuer)"
        }
    }
}

/// Resolves which registered WSCD plugin (`WalletConfig.availableKeystores`)
/// should back credential-issuance key generation for a given (issuer,
/// credential type) pair, BEFORE those keys are generated - so the wallet
/// finds out a plugin is insufficient up front instead of only when the
/// issuer later rejects a Key Attestation.
///
/// Phase-1 scope decision: no live plugin enumeration, no live per-plugin
/// capability query - eligibility is decided from `WscdPluginCapabilities`'s
/// static table alone, over whichever `KeystoreManager` instances the host
/// app has already constructed and registered. This type never constructs
/// or mutates a `KeystoreManager` itself, and never touches
/// siros-wscd-manager (Rust/UniFFI).
///
/// Resolution order (mirrors the Kotlin SDK's identical policy so both SDKs
/// behave the same way for host apps integrating either one):
/// 1. No declared requirement -> no-op (`nil`, use the existing default).
/// 2. A persisted TOFU choice for this (issuer, credentialType) that's
///    still sufficient -> reuse it, no prompt.
/// 3. The host app's `WalletConfig.defaultWscdMapping` for this pair, if
///    sufficient -> persist as the new TOFU entry, no prompt.
/// 4. Exactly one registered plugin meets the requirement -> auto-pick,
///    persist as TOFU, no prompt.
/// 5. More than one meets the requirement -> ask the user via
///    `RequestWscdChoice`; `.chosen` persists as TOFU, `.cancelled` returns
///    `nil` (best-effort - the caller's existing fallback/error handling
///    takes over, matching `requestBackendKeyAttestation`'s established
///    "best effort, never block issuance outright without a clear reason"
///    convention).
/// 6. Zero registered plugins meet the requirement -> throws
///    `WscdSelectionError.noEligiblePlugin` (a distinct, unambiguous
///    signal - never silently falls through to step 5's `nil`/best-effort
///    handling, since there's nothing usable to fall back to).
public final class WscdSelectionPolicy {
    private let sessionStore: SessionStoreProtocol
    private let defaultMapping: [String: String]
    private let requestChoice: RequestWscdChoice?

    public init(
        sessionStore: SessionStoreProtocol,
        defaultMapping: [String: String]? = nil,
        requestChoice: RequestWscdChoice? = nil
    ) {
        self.sessionStore = sessionStore
        self.defaultMapping = defaultMapping ?? [:]
        self.requestChoice = requestChoice
    }

    /// - Parameters:
    ///   - issuer: the credential issuer URL - half of the TOFU/default-mapping key.
    ///   - credentialType: the vct/doctype being issued - the other half.
    ///   - requiredTier: the credential type's declared `attestation_los`
    ///     (`Vctm.requiredKeyStorage` / `MddlSchema.requiredKeyStorage`), or
    ///     `nil` if the type declared no requirement.
    ///   - availablePluginIds: `WalletConfig.availableKeystores.keys` - the
    ///     plugin IDs the host app has actually registered a ready
    ///     `KeystoreManager` instance for.
    /// - Returns: a plugin ID the caller should use instead of the default
    ///   keystore for this call, or `nil` meaning "no change needed."
    /// - Throws: `WscdSelectionError.noEligiblePlugin` - see its doc comment.
    public func resolve(
        issuer: String,
        credentialType: String,
        requiredTier: String?,
        availablePluginIds: [String]
    ) async throws -> String? {
        // 1. No declared requirement - no-op.
        guard let requiredTier else { return nil }

        let key = Self.tofuKey(issuer: issuer, credentialType: credentialType)

        // 2. TOFU hit, still sufficient.
        if let cached = readTofu()[key], isSufficient(cached, for: requiredTier) {
            return cached
        }

        // 3. Host-app-supplied default mapping.
        if let mapped = defaultMapping[key], isSufficient(mapped, for: requiredTier) {
            persistTofu(key: key, pluginId: mapped)
            return mapped
        }

        // 4/5/6. Compute eligibility over what's actually registered.
        let eligible = availablePluginIds.filter { isSufficient($0, for: requiredTier) }

        if eligible.count == 1 {
            persistTofu(key: key, pluginId: eligible[0])
            return eligible[0]
        }

        if eligible.count > 1 {
            guard let requestChoice else { return nil }
            switch await requestChoice(issuer, credentialType, eligible) {
            case .chosen(let pluginId):
                persistTofu(key: key, pluginId: pluginId)
                return pluginId
            case .cancelled:
                return nil
            }
        }

        // Zero eligible.
        throw WscdSelectionError.noEligiblePlugin(issuer: issuer, credentialType: credentialType, requiredTier: requiredTier)
    }

    private func isSufficient(_ pluginId: String, for requiredTier: String) -> Bool {
        guard let tier = WscdPluginCapabilities.tier(forPluginId: pluginId) else { return false }
        return WscdPluginCapabilities.meets(actual: tier, required: requiredTier)
    }

    static func tofuKey(issuer: String, credentialType: String) -> String {
        "\(issuer)|\(credentialType)"
    }

    // MARK: - TOFU persistence

    private func readTofu() -> [String: String] {
        guard let json = sessionStore.wscdTofuMappingJson,
              let data = json.data(using: .utf8),
              let decoded = try? JSONDecoder().decode([String: String].self, from: data) else {
            return [:]
        }
        return decoded
    }

    private func persistTofu(key: String, pluginId: String) {
        var map = readTofu()
        map[key] = pluginId
        guard let data = try? JSONEncoder().encode(map), let json = String(data: data, encoding: .utf8) else { return }
        sessionStore.wscdTofuMappingJson = json
    }
}

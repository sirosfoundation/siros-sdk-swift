// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Static, SDK-side read-only facade over `Iso18045AssuranceScheme.default`'s
/// nominal key-storage assurance tier for each known WSCD plugin, used by
/// `WscdSelectionPolicy` to pick a plugin capable of meeting a credential
/// type's declared `attestation_los` requirement BEFORE the wallet
/// generates issuance keys, instead of finding out only when the issuer
/// later rejects a Key Attestation for insufficient key storage.
///
/// The actual mapping data lives on `Iso18045AssuranceScheme` (this type's
/// `scheme`, fixed to `.default`), not a table hardcoded here - see
/// `WscdAssuranceScheme`'s doc comment for why: a previous version of this
/// type hardcoded its own `pluginTiers` table, independently from
/// `WscdKeystoreAdapter`'s own (also now-removed) ISO-18045 guess, and the
/// two silently disagreed.
///
/// This type's static members are kept only as a read-only convenience
/// facade over `Iso18045AssuranceScheme.default` for callers that predate
/// `WscdAssuranceScheme` (the sample app's plugin chooser). It is
/// deliberately NOT configurable itself (no process-wide "set the default"
/// knob here) - a deployment wanting a different mapping (or a wholly
/// different `WscdAssuranceScheme` implementation) passes its own instance
/// to `WscdSelectionPolicy`'s (or `WscdKeystoreAdapter`'s) initializer
/// instead, which is the ONE place such a choice actually takes effect. A
/// second, independent "configure the default here too" surface on this
/// type would recreate exactly the two-places-to-configure-the-same-thing
/// problem this type exists to fix.
///
/// Phase-1 scope decision unchanged: no changes to siros-wscd-manager
/// (Rust/UniFFI) - no live plugin enumeration, no live per-plugin
/// capability query.
public enum WscdPluginCapabilities {
    /// The `Iso18045AssuranceScheme` instance this facade's static members delegate to.
    public static var scheme: Iso18045AssuranceScheme { .default }

    /// ISO 18045 assurance tier vocabulary, ascending order (each entry
    /// meets every requirement at or below its own index).
    public static var tierOrder: [String] { Iso18045AssuranceScheme.defaultTierOrder }

    /// Known plugin ID -> nominal ISO 18045 tier, as `scheme` currently maps
    /// it - see `Iso18045AssuranceScheme.defaultNominalPluginLabels` for the
    /// default values and their rationale. Plugin IDs match the ones
    /// `FfiWscdConfig(defaultPlugin:)` accepts and the sample app's plugin
    /// chooser offers (`WscaDeveloperView`): `"softkey"`, `"r2ps"`,
    /// `"fido2"`, `"apple-se"`.
    public static var pluginTiers: [String: String] { Iso18045AssuranceScheme.defaultNominalPluginLabels }

    /// Plugins with an enrollment ("onboarding") step: the user must register a
    /// token/key before the plugin can sign anything (and before a PIN means
    /// anything). `softkey` has none; `r2ps` enrolment is server-side lifecycle
    /// state this SDK does not track here, so it is not gated by this set.
    public static let onboardingRequiredPluginIds: Set<String> = ["fido2"]

    /// The nominal tier for a known plugin ID under `scheme`, or `nil` if
    /// the ID isn't known (an unknown/future plugin ID is never eligible
    /// for anything - see `meets`).
    public static func tier(forPluginId pluginId: String) -> String? {
        scheme.nominalLabel(forPluginId: pluginId)
    }

    /// Whether `actual` meets or exceeds `required` under `scheme`. Either
    /// value being unrecognized is treated as "does not meet" rather than a
    /// crash - callers should surface that as "not eligible", not fail hard.
    public static func meets(actual: String, required: String) -> Bool {
        scheme.meets(actual: actual, required: required)
    }
}

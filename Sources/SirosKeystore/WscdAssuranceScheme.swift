// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// A pluggable assurance-label VOCABULARY the wallet SDK (never
/// `siros-wscd-manager`, which stays label-agnostic forever - it only ever
/// deals in its own objective `CertificationLevel`/`FfiCertificationLevel`
/// facts, none of which is any kind of label) uses to express an objective
/// WSCD fact - e.g. the raw key-storage-type string `Signer.securityProperties`
/// reports for an already-generated key - in whatever vocabulary a given
/// deployment's compliance posture / issuer ecosystem actually speaks.
///
/// This protocol exists because, before it, TWO independently-authored
/// static tables silently disagreed about what the same underlying hardware
/// fact meant - a real bug found during the TEE/Secure-Enclave plugin work,
/// not a hypothetical one: `WscdPluginCapabilities`'s plugin-id table and
/// `WscdKeystoreAdapter`'s now-removed private `toIso18045AttackPotential`
/// switch. Collapsing both into calls through exactly one injected
/// `WscdAssuranceScheme` instance eliminates that drift risk: there is now
/// exactly one place a deployment decides what an objective WSCD fact means
/// for assurance-labeling purposes, supplied as data (constructor
/// parameters on `Iso18045AssuranceScheme`, or a wholly different
/// implementation of this protocol) rather than compiled into the SDK.
///
/// `siros-wscd-manager` itself never sees a label, ISO 18045 or otherwise -
/// this protocol, and everything that calls through it
/// (`WscdSelectionPolicy`, `WscdPluginCapabilities`), lives entirely on the
/// SDK side, by design: different deployments auditing the SAME wallet (SDK
/// + wscd-manager together) may legitimately reach different conclusions
/// about what a given hardware fact is worth, so that judgment must not be
/// baked into wscd-manager, which is shared by every deployment.
///
/// `Iso18045AssuranceScheme` ships as the DEFAULT implementation because ISO
/// 18045 is the vocabulary today's credential catalogs
/// (`Vctm.requiredKeyStorage`/`MddlSchema.requiredKeyStorage`, wire field
/// `attestation_los`) and the OID4VCI Key Attestation JWT's registered
/// `key_storage`/`user_authentication` claims actually use - but nothing in
/// `WscdSelectionPolicy` or `WscdPluginCapabilities` hardcodes ISO 18045 as
/// THE vocabulary: a deployment whose issuer ecosystem speaks a different
/// one (NIST SP 800-63 AAL, eIDAS LoA, an internal scale) implements this
/// protocol itself and passes an instance to `WscdSelectionPolicy`'s
/// initializer; candidate selection keeps working unchanged, since it only
/// ever compares two labels via `meets` and never assumes what they look
/// like.
///
/// The OID4VCI Key Attestation JWT is the one call site that is NOT free to
/// swap vocabularies: `key_storage`/`user_authentication` are a registered
/// external wire format whose values ARE the four ISO 18045 AVA_VAN tiers
/// `iso_18045_basic`/`iso_18045_enhanced-basic`/`iso_18045_moderate`/
/// `iso_18045_high` (OID4VCI Appendix D.2, "Attack Potential Resistance") by
/// spec, not a deployment's choice - so `WscdKeystoreAdapter` always builds
/// those two claims through an `Iso18045AssuranceScheme` specifically (never
/// an arbitrary `WscdAssuranceScheme` a deployment might otherwise be using
/// for plugin selection), even though exactly which key-storage type maps to
/// which of those four real ISO 18045 tiers remains deployment-configurable
/// DATA on that type. Note this four-tier wire vocabulary is BROADER than
/// the three-tier scale (`Iso18045AssuranceScheme.defaultTierOrder`: basic/
/// moderate/high) plugin SELECTION uses - a credential catalog here never
/// REQUIRES enhanced-basic, but a confirmed hardware fact may legitimately
/// be REPORTED as it.
///
/// This SDK does not yet wrap `siros-wscd-manager`'s
/// `generate_key_for_level`/`FfiCertificationLevel` the way the Kotlin SDK
/// does (no `WscdManager.generateKeyForLevel` here yet - a separate,
/// larger piece of feature-parity work), so unlike the Kotlin SDK's
/// `WscdAssuranceScheme`, this protocol has no `label(forCertificationLevel:)`
/// entry point - there is nothing in this SDK yet that would call it. Add
/// one here, mirroring the Kotlin SDK's shape, when that wrapper is ported.
public protocol WscdAssuranceScheme: Sendable {
    /// This scheme's label for the raw key-storage-type string
    /// `Signer.securityProperties` reports (`"software"`/`"hardware"`/
    /// `"trusted_execution"`/`"remote_hsm"`), the real, per-key, confirmed
    /// storage classification wscd-manager reports for an already-generated
    /// key. A raw type string already in this scheme's own vocabulary (e.g.
    /// already `"iso_18045_*"`) is returned unchanged.
    func label(forKeyStorageType rawKeyStorageType: String) -> String

    /// This scheme's a-priori (BEFORE any key is generated) label for a
    /// known plugin id - used by `WscdSelectionPolicy` to decide which
    /// registered plugins are even worth trying for a credential type's
    /// declared requirement. `nil` for a plugin id this scheme has no
    /// opinion on (an unrecognized/future plugin id), distinct from "the
    /// lowest tier", so a caller can tell "no data" from "known and weak."
    func nominalLabel(forPluginId pluginId: String) -> String?

    /// True if `actual` (one of this scheme's own labels) is at least as
    /// strong an assurance claim as `required` (also this scheme's own
    /// vocabulary). MUST fail closed: a label either side doesn't recognize
    /// (a typo, a future tier this scheme's own table hasn't been updated
    /// for) never satisfies anything.
    func meets(actual: String, required: String) -> Bool
}

/// The DEFAULT `WscdAssuranceScheme`: ISO 18045 (Common Criteria evaluation
/// assurance methodology) `AVA_VAN`-flavored tiers, ascending
/// `basic` < `moderate` < `high`, matching the wire's `attestation_los`
/// field and the OID4VCI Key Attestation JWT's registered
/// `key_storage`/`user_authentication` values.
///
/// Every mapping table here is an INITIALIZER PARAMETER, not a compiled-in
/// constant: a deployment whose audit should treat e.g. `"fido2"` as merely
/// `moderate` (not this type's own default of `high`) constructs
/// `Iso18045AssuranceScheme(nominalPluginLabels: Iso18045AssuranceScheme.defaultNominalPluginLabels.merging(["fido2": Iso18045AssuranceScheme.moderate]) { _, new in new })`
/// and passes that instance wherever a `WscdAssuranceScheme` is accepted.
/// `default` is this type's own best-effort, documented default, used
/// automatically unless a deployment supplies its own instance.
public struct Iso18045AssuranceScheme: WscdAssuranceScheme {
    public static let basic = "iso_18045_basic"
    public static let enhancedBasic = "iso_18045_enhanced-basic"
    public static let moderate = "iso_18045_moderate"
    public static let high = "iso_18045_high"

    /// Ascending assurance order for plugin-SELECTION eligibility
    /// (`meets`/`rank(ofTier:)`) - the SDK's own three-tier scale, matching
    /// the wire's `attestation_los` field and `WscdPluginCapabilities`'s
    /// original, deliberate scope: this ecosystem's credential catalog/
    /// issuers never declare `enhancedBasic` as a REQUIREMENT, so it is
    /// intentionally absent from this list - NOT the same thing as
    /// `wireLabels` below, which is what a CONFIRMED hardware fact may be
    /// reported AS.
    public static let defaultTierOrder = [basic, moderate, high]

    /// The full OID4VCI-registered ISO 18045 AVA_VAN wire vocabulary
    /// (Appendix D.2, "Attack Potential Resistance") `label(forKeyStorageType:)`
    /// is allowed to emit - see `validated(_:)`. FOUR tiers, not three:
    /// broader than `defaultTierOrder` (the SDK's own narrower plugin-
    /// SELECTION scale) because the external wire format defines
    /// `enhancedBasic` as a real, registered tier between `basic` and
    /// `moderate` that a confirmed hardware fact can legitimately be
    /// reported as, even though no credential catalog in this ecosystem ever
    /// REQUIRES it.
    private static let wireLabels: Set<String> = [basic, enhancedBasic, moderate, high]

    /// The raw key-storage-type strings `Signer.securityProperties` reports
    /// (`software`/`hardware`/`trusted_execution`/`remote_hsm`), as this
    /// DEFAULT scheme reads them for the Key Attestation JWT's
    /// `key_storage`/`user_authentication` claims. Unrecognized strings (a
    /// typo, or a real but non-hardware-class value like a
    /// `userAuthentication` method name) fall through to `basic` via
    /// `label(forKeyStorageType:)`'s default - the same conservative
    /// behavior the mapping this replaced had, since overclaiming
    /// resistance this scheme can't back up is worse than underclaiming it.
    ///
    /// `"trusted_execution"` reads as `enhancedBasic` here - a REAL,
    /// registered OID4VCI tier (VAN.3, between `basic`/VAN.2 and
    /// `moderate`/VAN.4), not a stray string: a TEE-backed key is real
    /// hardware isolation from the OS, clearly above a pure software key,
    /// but (unlike a dedicated secure element) a TEE shares silicon with the
    /// main CPU and has its own attack surface, so this default does not
    /// overclaim it as fully `moderate` either - `enhancedBasic` is the
    /// precise, correct fit, not a compromise between two coarser choices.
    public static let defaultKeyStorageTypeLabels: [String: String] = [
        "software": basic,
        "hardware": moderate,
        "trusted_execution": enhancedBasic,
        "remote_hsm": high,
    ]

    /// Nominal (pre-key-generation) tier for each known plugin id -
    /// unchanged from `WscdPluginCapabilities`'s original table:
    /// `"softkey"` -> `basic` (no hardware-backing claim); `"fido2"` ->
    /// `high` (CTAP2 hardware-backed, a real per-key attestation statement
    /// from the authenticator); `"r2ps"` -> `high`, best-effort/
    /// config-dependent (a remote-HSM-backed plugin, so its real assurance
    /// depends entirely on which HSM a given deployment's R2PS server is
    /// backed by - this is a nominal ceiling, not a guarantee); `"apple-se"`
    /// -> `moderate` (Secure Enclave-backed, a real hardware-isolated key,
    /// more than `softkey`'s `basic` - but, as of this writing, with NO
    /// per-key attestation chain backing that claim: confirmed on real
    /// Xcode 26.6 / iOS 26.5 SDK headers that `SecKeyCreateAttestation`
    /// does not exist on this SDK at all, and no CryptoKit type exposes any
    /// attestation API, unlike `fido2`'s real per-key attestation - see
    /// `SecureEnclaveKeystoreBackend`'s doc comment and
    /// sirosfoundation/siros-wscd-manager#134. Raise this once a real
    /// attestation path exists and is wired through a confirmed,
    /// post-generation security property, not before).
    public static let defaultNominalPluginLabels: [String: String] = [
        "softkey": basic,
        "fido2": high,
        "r2ps": high,
        "apple-se": moderate,
    ]

    /// This scheme's own default instance - see this type's doc comment.
    public static let `default` = Iso18045AssuranceScheme()

    private let keyStorageTypeLabels: [String: String]
    private let nominalPluginLabels: [String: String]
    private let tierOrder: [String]

    public init(
        keyStorageTypeLabels: [String: String] = Iso18045AssuranceScheme.defaultKeyStorageTypeLabels,
        nominalPluginLabels: [String: String] = Iso18045AssuranceScheme.defaultNominalPluginLabels,
        tierOrder: [String] = Iso18045AssuranceScheme.defaultTierOrder
    ) {
        self.keyStorageTypeLabels = keyStorageTypeLabels
        self.nominalPluginLabels = nominalPluginLabels
        self.tierOrder = tierOrder
    }

    public func label(forKeyStorageType rawKeyStorageType: String) -> String {
        let candidate: String?
        if rawKeyStorageType.hasPrefix("iso_18045_") {
            // Already claims to be spec-compliant - still validated below, not trusted blindly.
            candidate = rawKeyStorageType
        } else {
            candidate = keyStorageTypeLabels[rawKeyStorageType.lowercased()]
        }
        return Self.validated(candidate)
    }

    /// `candidate` if it is one of the four real, registered ISO-18045 wire
    /// labels (`basic`/`enhancedBasic`/`moderate`/`high`), else `basic`.
    ///
    /// This type ALWAYS emits one of exactly those four strings, however
    /// `keyStorageTypeLabels` was configured - `WscdKeystoreAdapter` builds
    /// the OID4VCI Key Attestation JWT's `key_storage`/`user_authentication`
    /// claims from this type specifically (never the generic
    /// `WscdAssuranceScheme` protocol) precisely because that wire format's
    /// registered values ARE these four strings by spec, not a deployment's
    /// free choice - a misconfigured map entry (a typo, or a value copied
    /// from a different vocabulary entirely) must never reach an issuer as
    /// an unrecognized `key_storage` value, which a real conformance-test
    /// issuer has already been confirmed to reject once (see
    /// `defaultKeyStorageTypeLabels`'s doc comment).
    private static func validated(_ candidate: String?) -> String {
        guard let candidate, wireLabels.contains(candidate) else { return basic }
        return candidate
    }

    public func nominalLabel(forPluginId pluginId: String) -> String? {
        nominalPluginLabels[pluginId]
    }

    public func meets(actual: String, required: String) -> Bool {
        guard let actualIndex = tierOrder.firstIndex(of: actual),
              let requiredIndex = tierOrder.firstIndex(of: required) else {
            return false
        }
        return actualIndex >= requiredIndex
    }

    /// `tier`'s position in this instance's own tier order (higher =
    /// stronger assurance), or -1 for an unrecognized tier string.
    public func rank(ofTier tier: String) -> Int {
        tierOrder.firstIndex(of: tier) ?? -1
    }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore

/// `Iso18045AssuranceScheme` is the single configurable source
/// `WscdPluginCapabilities` and `WscdKeystoreAdapter` both now read through -
/// see `WscdAssuranceScheme`'s doc comment for the bug (two independently-
/// guessed tables silently disagreeing) this collapses. These tests prove
/// two things: (a) `Iso18045AssuranceScheme.default`'s practical values match
/// what the two tables it replaces used to produce, and (b) a deployment can
/// genuinely override every axis with its own data, not just read a
/// hardcoded default under a new name.
final class WscdAssuranceSchemeTests: XCTestCase {

    // MARK: - default matches the previous (now-removed) tables' practical values

    func testDefaultNominalPluginLabelsMatchPreviousPluginTiersTable() {
        let scheme = Iso18045AssuranceScheme.default
        XCTAssertEqual(scheme.nominalLabel(forPluginId: "softkey"), "iso_18045_basic")
        XCTAssertEqual(scheme.nominalLabel(forPluginId: "fido2"), "iso_18045_high")
        XCTAssertEqual(scheme.nominalLabel(forPluginId: "r2ps"), "iso_18045_high")
        XCTAssertEqual(scheme.nominalLabel(forPluginId: "apple-se"), "iso_18045_moderate")
        XCTAssertNil(scheme.nominalLabel(forPluginId: "some-future-plugin"))
    }

    func testDefaultKeyStorageTypeLabelsMatchPreviousAttackPotentialMapping() {
        let scheme = Iso18045AssuranceScheme.default
        // Unchanged from the previous `toIso18045AttackPotential` switch:
        XCTAssertEqual(scheme.label(forKeyStorageType: "software"), "iso_18045_basic")
        XCTAssertEqual(scheme.label(forKeyStorageType: "hardware"), "iso_18045_moderate")
        XCTAssertEqual(scheme.label(forKeyStorageType: "remote_hsm"), "iso_18045_high")
        // Also unchanged: "iso_18045_enhanced-basic" is a REAL, registered
        // OID4VCI value (Appendix D.2, VAN.3) - not a stray string. A TEE
        // shares silicon with the main CPU, so it is precisely
        // enhanced-basic, not the coarser "moderate" a dedicated secure
        // element ("hardware") reads as.
        XCTAssertEqual(scheme.label(forKeyStorageType: "trusted_execution"), "iso_18045_enhanced-basic")
        // Already-spec-compliant strings pass through unchanged.
        XCTAssertEqual(scheme.label(forKeyStorageType: "iso_18045_high"), "iso_18045_high")
        // Unrecognized raw strings fail closed to the lowest tier, same as before.
        XCTAssertEqual(scheme.label(forKeyStorageType: "pin"), "iso_18045_basic")
    }

    func testMisconfiguredKeyStorageTypeLabelFallsBackToBasic() {
        // Regression test for a real Copilot finding: a deployment
        // misconfiguring Iso18045AssuranceScheme with a non-ISO-18045 value
        // (a typo, or a label copied from a different vocabulary) must never
        // reach the OID4VCI Key Attestation JWT as an unrecognized
        // key_storage value.
        let misconfigured = Iso18045AssuranceScheme(keyStorageTypeLabels: ["hardware": "aal2"])
        XCTAssertEqual(misconfigured.label(forKeyStorageType: "hardware"), "iso_18045_basic")
    }

    func testARawStringAlreadyClaimingIso18045PrefixIsStillValidated() {
        // The "already spec-compliant, pass through" fast path must not
        // trust an arbitrary "iso_18045_"-prefixed string blindly - only one
        // of the four REAL, OID4VCI-registered tiers passes through
        // unchanged; a made-up one (even with the right prefix) does not.
        let scheme = Iso18045AssuranceScheme.default
        XCTAssertEqual(scheme.label(forKeyStorageType: "iso_18045_bogus"), "iso_18045_basic")
        // "enhanced-basic" IS one of the four real tiers - it passes through
        // unchanged, not clamped to basic.
        XCTAssertEqual(scheme.label(forKeyStorageType: "iso_18045_enhanced-basic"), "iso_18045_enhanced-basic")
        XCTAssertEqual(scheme.label(forKeyStorageType: "iso_18045_high"), "iso_18045_high")
    }

    func testDefaultMeetsIsReflexiveAndFailsClosedForUnrecognizedTiers() {
        let scheme = Iso18045AssuranceScheme.default
        XCTAssertTrue(scheme.meets(actual: "iso_18045_basic", required: "iso_18045_basic"))
        XCTAssertTrue(scheme.meets(actual: "iso_18045_high", required: "iso_18045_basic"))
        XCTAssertFalse(scheme.meets(actual: "iso_18045_basic", required: "iso_18045_high"))
        XCTAssertFalse(scheme.meets(actual: "bogus", required: "iso_18045_basic"))
        XCTAssertFalse(scheme.meets(actual: "iso_18045_high", required: "bogus"))
    }

    // MARK: - WscdPluginCapabilities facade delegates to the default scheme

    func testWscdPluginCapabilitiesFacadeDelegatesToDefaultScheme() {
        XCTAssertEqual(WscdPluginCapabilities.tier(forPluginId: "fido2"), "iso_18045_high")
        XCTAssertTrue(WscdPluginCapabilities.meets(actual: "iso_18045_high", required: "iso_18045_basic"))
    }

    // MARK: - Genuinely deployment-configurable: NOT still hardcoded anywhere

    func testCustomSchemeOverridesNominalPluginLabel_fido2ToSubstantial() {
        // One deployment's audit: "fido2" should count as iso_18045_moderate
        // (NOT this type's own default of iso_18045_high) - leifj's own
        // example of why this mapping had to become deployment data rather
        // than a single compiled-in guess.
        let lenient = Iso18045AssuranceScheme(nominalPluginLabels: ["fido2": Iso18045AssuranceScheme.high])
        let strict = Iso18045AssuranceScheme(nominalPluginLabels: ["fido2": Iso18045AssuranceScheme.moderate])

        XCTAssertEqual(lenient.nominalLabel(forPluginId: "fido2"), "iso_18045_high")
        XCTAssertEqual(strict.nominalLabel(forPluginId: "fido2"), "iso_18045_moderate")
        // Each instance is independent - overriding one does not mutate the
        // shared default or the other custom instance.
        XCTAssertEqual(Iso18045AssuranceScheme.default.nominalLabel(forPluginId: "fido2"), "iso_18045_high")
    }

    func testCustomSchemeOverridesKeyStorageTypeLabel() {
        let custom = Iso18045AssuranceScheme(keyStorageTypeLabels: ["hardware": Iso18045AssuranceScheme.high])
        XCTAssertEqual(custom.label(forKeyStorageType: "hardware"), "iso_18045_high")
        XCTAssertEqual(Iso18045AssuranceScheme.default.label(forKeyStorageType: "hardware"), "iso_18045_moderate")
    }

    func testCustomSchemeOverridesTierOrder_changesMeetsResult() {
        // A deployment using a different (or reordered) label set entirely -
        // meets() must compare through whatever order THIS instance was
        // configured with, not a fixed internal constant.
        let custom = Iso18045AssuranceScheme(tierOrder: ["low", "mid", "crit"])
        XCTAssertTrue(custom.meets(actual: "crit", required: "low"))
        XCTAssertFalse(custom.meets(actual: "low", required: "crit"))
        // The default instance's own order is untouched.
        XCTAssertFalse(Iso18045AssuranceScheme.default.meets(actual: "crit", required: "low"))
    }

    /// A non-ISO-18045 vocabulary entirely: proves the protocol itself is
    /// scheme-agnostic, not just the data within one scheme.
    private struct FixedLabelScheme: WscdAssuranceScheme {
        let label: String
        func label(forKeyStorageType rawKeyStorageType: String) -> String { label }
        func nominalLabel(forPluginId pluginId: String) -> String? { label }
        func meets(actual: String, required: String) -> Bool { actual == required }
    }

    func testWscdAssuranceSchemeIsNotIso18045Specific_aDifferentVocabularyImplementationWorksToo() {
        let nistStyle = FixedLabelScheme(label: "aal2")
        XCTAssertEqual(nistStyle.nominalLabel(forPluginId: "fido2"), "aal2")
        XCTAssertTrue(nistStyle.meets(actual: "aal2", required: "aal2"))
        XCTAssertFalse(nistStyle.meets(actual: "aal2", required: "iso_18045_high"))
    }
}

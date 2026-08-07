// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosWallet

/// Pure logic, no keystore/CryptoKit dependency - unlike
/// `SirosWalletKeyAttestationTests`, this doesn't need a real `SirosWallet`
/// instance, so it isn't gated behind `#if canImport(CryptoKit)`.
final class WscdSelectionPolicyTests: XCTestCase {

    private func makePolicy(
        store: SessionStoreProtocol = InMemorySessionStore(),
        defaultMapping: [String: String]? = nil,
        requestChoice: RequestWscdChoice? = nil
    ) -> WscdSelectionPolicy {
        if let mem = store as? InMemorySessionStore {
            mem.activeAccountId = "test:account"
        }
        return WscdSelectionPolicy(sessionStore: store, defaultMapping: defaultMapping, requestChoice: requestChoice)
    }

    // 1. No declared requirement.
    func testNoRequirementIsNoOp() async throws {
        let policy = makePolicy()
        let result = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: nil,
            availablePluginIds: ["softkey", "fido2"]
        )
        XCTAssertNil(result)
    }

    // 2. TOFU hit.
    func testTofuHitReusesPersistedChoiceWithoutPrompting() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        var promptCount = 0
        let policy = WscdSelectionPolicy(
            sessionStore: store,
            requestChoice: { _, _, eligible in
                promptCount += 1
                return .chosen(pluginId: eligible.first ?? "softkey")
            }
        )
        // First call has 2 eligible plugins ("fido2" and "r2ps" both meet "iso_18045_high"),
        // so it must ask - seed the TOFU entry via that first resolution.
        let first = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "org.iso.18013.5.1.mDL",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["softkey", "fido2", "r2ps"]
        )
        XCTAssertNotNil(first)
        XCTAssertEqual(promptCount, 1)

        // Second call for the same (issuer, credentialType) must reuse the
        // TOFU entry without prompting again.
        let second = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "org.iso.18013.5.1.mDL",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["softkey", "fido2", "r2ps"]
        )
        XCTAssertEqual(second, first)
        XCTAssertEqual(promptCount, 1, "must not prompt again once TOFU is persisted")
    }

    func testTofuEntryNoLongerSufficientIsIgnored() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        // Pre-seed a TOFU mapping pointing at "softkey" (basic tier only).
        let key = "https://issuer.example.com|urn:eu.europa.ec.eudi:pid:1"
        let json = try! JSONEncoder().encode([key: "softkey"])
        store.wscdTofuMappingJson = String(data: json, encoding: .utf8)

        let policy = WscdSelectionPolicy(sessionStore: store)
        // Now the credential type demands "iso_18045_high" - softkey no
        // longer qualifies, so it must fall through instead of blindly reusing it.
        let result = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["softkey", "fido2"]
        )
        XCTAssertEqual(result, "fido2", "must fall through to the one still-sufficient plugin, not the stale TOFU entry")
    }

    func testTofuEntryNoLongerRegisteredIsIgnored() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        // Pre-seed a TOFU mapping pointing at "fido2", which meets the tier
        // but is no longer in `availablePluginIds` below (e.g. the host app
        // unregistered it since the TOFU entry was persisted).
        let key = "https://issuer.example.com|urn:eu.europa.ec.eudi:pid:1"
        let json = try! JSONEncoder().encode([key: "fido2"])
        store.wscdTofuMappingJson = String(data: json, encoding: .utf8)

        let policy = WscdSelectionPolicy(sessionStore: store)
        let result = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["r2ps"]
        )
        XCTAssertEqual(result, "r2ps", "a TOFU entry for an unregistered plugin must not be reused - must fall through to what's actually registered")
    }

    // 3. Default-mapping hit.
    func testDefaultMappingHitIsUsedAndPersistedAsTofu() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let key = "https://issuer.example.com|urn:eu.europa.ec.eudi:pid:1"
        let policy = WscdSelectionPolicy(sessionStore: store, defaultMapping: [key: "fido2"])

        let result = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["softkey", "fido2", "r2ps"]
        )
        XCTAssertEqual(result, "fido2")

        // Persisted as TOFU: a fresh policy over the same store (no default
        // mapping this time) must still resolve to "fido2".
        let policyWithoutMapping = WscdSelectionPolicy(sessionStore: store)
        let second = try await policyWithoutMapping.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["softkey", "fido2", "r2ps"]
        )
        XCTAssertEqual(second, "fido2")
    }

    func testInsufficientDefaultMappingIsIgnored() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let key = "https://issuer.example.com|urn:eu.europa.ec.eudi:pid:1"
        // Mapped plugin ("softkey") doesn't meet the required tier - must be skipped.
        let policy = WscdSelectionPolicy(sessionStore: store, defaultMapping: [key: "softkey"])

        let result = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["softkey", "fido2"]
        )
        XCTAssertEqual(result, "fido2", "insufficient default mapping must fall through to auto single-match")
    }

    func testDefaultMappingEntryNoLongerRegisteredIsIgnored() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let key = "https://issuer.example.com|urn:eu.europa.ec.eudi:pid:1"
        // Mapped plugin ("fido2") meets the tier but isn't actually registered.
        let policy = WscdSelectionPolicy(sessionStore: store, defaultMapping: [key: "fido2"])

        let result = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["r2ps"]
        )
        XCTAssertEqual(result, "r2ps", "a default mapping entry for an unregistered plugin must not be used - must fall through to what's actually registered")
        XCTAssertFalse(store.wscdTofuMappingJson?.contains("fido2") ?? false, "the unregistered mapped plugin must not be persisted as TOFU")
    }

    // 4. Auto single-match.
    func testAutoPicksSingleEligiblePluginWithoutPrompting() async throws {
        var promptCount = 0
        let policy = makePolicy(requestChoice: { _, _, eligible in
            promptCount += 1
            return .chosen(pluginId: eligible.first ?? "softkey")
        })

        let result = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_basic",
            availablePluginIds: ["softkey"]
        )
        XCTAssertEqual(result, "softkey")
        XCTAssertEqual(promptCount, 0, "exactly one eligible plugin must not trigger a user prompt")
    }

    // 5. Ask-user, multiple eligible - chosen.
    func testMultipleEligibleAsksUserAndPersistsChoice() async throws {
        var capturedEligible: [String]?
        let policy = makePolicy(requestChoice: { issuer, credentialType, eligible in
            capturedEligible = eligible
            XCTAssertEqual(issuer, "https://issuer.example.com")
            XCTAssertEqual(credentialType, "org.iso.18013.5.1.mDL")
            return .chosen(pluginId: "r2ps")
        })

        let result = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "org.iso.18013.5.1.mDL",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["softkey", "fido2", "r2ps"]
        )
        XCTAssertEqual(result, "r2ps")
        XCTAssertEqual(Set(capturedEligible ?? []), Set(["fido2", "r2ps"]))
    }

    // 5. Ask-user, multiple eligible - cancelled.
    func testMultipleEligibleCancelledReturnsNilAndDoesNotPersist() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let policy = WscdSelectionPolicy(sessionStore: store, requestChoice: { _, _, _ in .cancelled })

        let result = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "org.iso.18013.5.1.mDL",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["softkey", "fido2", "r2ps"]
        )
        XCTAssertNil(result)
        XCTAssertNil(store.wscdTofuMappingJson, "a cancelled choice must not be persisted as TOFU")
    }

    // 5. Ask-user, host callback returns a pluginId outside the eligible
    // list it was given (e.g. a host UI bug) - must be treated like
    // `.cancelled`, not trusted and persisted as-is.
    func testMultipleEligibleChoiceOutsideEligibleListIsTreatedAsCancelled() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        // "softkey" doesn't meet the required tier, so it's never in `eligible`.
        let policy = WscdSelectionPolicy(sessionStore: store, requestChoice: { _, _, _ in .chosen(pluginId: "softkey") })

        let result = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "org.iso.18013.5.1.mDL",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["softkey", "fido2", "r2ps"]
        )
        XCTAssertNil(result)
        XCTAssertNil(store.wscdTofuMappingJson, "an invalid choice must not be persisted as TOFU")
    }

    // 5. No callback configured at all - best-effort nil, not a crash.
    func testMultipleEligibleWithNoCallbackConfiguredReturnsNil() async throws {
        let policy = makePolicy(requestChoice: nil)
        let result = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "org.iso.18013.5.1.mDL",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["softkey", "fido2", "r2ps"]
        )
        XCTAssertNil(result)
    }

    // 6. Zero eligible - hard error.
    func testZeroEligibleThrowsNoEligiblePlugin() async {
        let policy = makePolicy()
        do {
            _ = try await policy.resolve(
                issuer: "https://issuer.example.com",
                credentialType: "urn:eu.europa.ec.eudi:pid:1",
                requiredTier: "iso_18045_high",
                availablePluginIds: ["softkey"]
            )
            XCTFail("expected WscdSelectionError.noEligiblePlugin")
        } catch WscdSelectionError.noEligiblePlugin(let issuer, let credentialType, let requiredTier) {
            XCTAssertEqual(issuer, "https://issuer.example.com")
            XCTAssertEqual(credentialType, "urn:eu.europa.ec.eudi:pid:1")
            XCTAssertEqual(requiredTier, "iso_18045_high")
        } catch {
            XCTFail("unexpected error type: \(error)")
        }
    }

    func testZeroEligibleWithEmptyAvailablePluginsThrows() async {
        let policy = makePolicy()
        do {
            _ = try await policy.resolve(
                issuer: "https://issuer.example.com",
                credentialType: "urn:eu.europa.ec.eudi:pid:1",
                requiredTier: "iso_18045_basic",
                availablePluginIds: []
            )
            XCTFail("expected WscdSelectionError.noEligiblePlugin")
        } catch WscdSelectionError.noEligiblePlugin {
            // Expected.
        } catch {
            XCTFail("unexpected error type: \(error)")
        }
    }

    // Independent (issuer, credentialType) pairs must not clobber each other's TOFU entries.
    func testTofuIsScopedPerIssuerAndCredentialType() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let policy = WscdSelectionPolicy(sessionStore: store)

        let resultA = try await policy.resolve(
            issuer: "https://issuer-a.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_basic",
            availablePluginIds: ["softkey"]
        )
        let resultB = try await policy.resolve(
            issuer: "https://issuer-b.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["fido2"]
        )
        XCTAssertEqual(resultA, "softkey")
        XCTAssertEqual(resultB, "fido2")

        // Re-resolving issuer A must still get "softkey" from its own TOFU entry.
        let resultAAgain = try await policy.resolve(
            issuer: "https://issuer-a.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_basic",
            availablePluginIds: ["softkey", "fido2"]
        )
        XCTAssertEqual(resultAAgain, "softkey")
    }

    // MARK: - TOFU inspection/management (host-app settings UI)

    func testCurrentTofuMappingReflectsPersistedEntries() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let policy = WscdSelectionPolicy(sessionStore: store)
        XCTAssertEqual(policy.currentTofuMapping(), [:])

        _ = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_basic",
            availablePluginIds: ["softkey"]
        )
        XCTAssertEqual(
            policy.currentTofuMapping(),
            ["https://issuer.example.com|urn:eu.europa.ec.eudi:pid:1": "softkey"]
        )
    }

    func testClearTofuMappingForKeyRemovesOnlyThatEntry() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let policy = WscdSelectionPolicy(sessionStore: store)

        _ = try await policy.resolve(
            issuer: "https://issuer-a.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_basic",
            availablePluginIds: ["softkey"]
        )
        _ = try await policy.resolve(
            issuer: "https://issuer-b.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["fido2"]
        )
        XCTAssertEqual(policy.currentTofuMapping().count, 2)

        policy.clearTofuMapping(forKey: "https://issuer-a.example.com|urn:eu.europa.ec.eudi:pid:1")

        XCTAssertEqual(
            policy.currentTofuMapping(),
            ["https://issuer-b.example.com|urn:eu.europa.ec.eudi:pid:1": "fido2"]
        )
    }

    func testClearAllTofuMappingsRemovesEverything() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let policy = WscdSelectionPolicy(sessionStore: store)

        _ = try await policy.resolve(
            issuer: "https://issuer-a.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_basic",
            availablePluginIds: ["softkey"]
        )
        _ = try await policy.resolve(
            issuer: "https://issuer-b.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["fido2"]
        )
        XCTAssertEqual(policy.currentTofuMapping().count, 2)

        policy.clearAllTofuMappings()

        XCTAssertEqual(policy.currentTofuMapping(), [:])
    }
}

# WSCA Parity Plan: Swift SDK vs Kotlin SDK

> **Status:** Planned — pending validation of Kotlin SDK WSCA integration.

This document tracks the gaps between the Swift and Kotlin SDKs for WSCA
(Wallet Secure Cryptographic Application) integration testing support, and
the plan for bringing the Swift SDK and sample app up to parity.

## Gap Analysis

### SDK Library Layer (SirosKeystore)

| Feature | Kotlin | Swift | Gap |
|---------|--------|-------|-----|
| `Signer` protocol | ✅ | ✅ | Parity |
| `securityProperties(keyId:)` | ✅ | ✅ | Parity |
| `SignerSecurityProperties` / `CertificationInfo` | ✅ | ✅ | Parity |
| UniFFI bridge (`UniFFISigner`) | ✅ | ✅ | Parity |
| Lifecycle types & protocol | ✅ | ✅ `SignerLifecycleManager` | Parity |
| UniFFI lifecycle bridge | ✅ | ✅ `UniFFISigner+Lifecycle` | Parity |
| `DetailedKeyInfo` (keyId, alg, pluginId, createdAt) | ✅ | ❌ `SignerKeyInfo` only has keyId + algorithm | **Gap** |
| `listKeysDetailed()` | ✅ | ❌ only `listKeys()` | **Gap** |

### Sample App — ViewModel

| Feature | Kotlin `WalletViewModel` | Swift `WalletViewModel` | Gap |
|---------|--------------------------|------------------------|-----|
| `selectedPluginId` state | ✅ `StateFlow<String>` | ❌ only `r2psEnabled: Bool` | **Gap** |
| `selectPlugin(pluginId:)` | ✅ | ❌ | **Gap** |
| `enrollWscd()` | ✅ uses `activePluginId` | ❌ no lifecycle ops | **Gap** |
| `rotateLifecycle()` | ✅ | ❌ | **Gap** |
| `destroyLifecycle(mode:)` | ✅ | ❌ | **Gap** |
| `refreshWscdInfo()` (keys + security props) | ✅ | ❌ | **Gap** |
| `wscdKeys` state | ✅ `List<DetailedKeyInfo>` | ❌ | **Gap** |
| `wscdKeySecurityProps` state | ✅ `Map<String, SignerSecurityProperties>` | ❌ | **Gap** |
| `wscdLifecycleStatus` state | ✅ | ❌ | **Gap** |
| `showWscaDeveloper` state | ✅ | ❌ | **Gap** |
| WSCD signer always initialized | ✅ for all plugins | ❌ only when `r2psEnabled` | **Gap** |

### Sample App — UI

| Feature | Kotlin | Swift | Gap |
|---------|--------|-------|-----|
| WSCA Developer Screen | ✅ `WscaDeveloperScreen.kt` | ❌ missing entirely | **Gap** |
| Plugin selector (softkey/r2ps/fido2) | ✅ FilterChip row | ❌ | **Gap** |
| Enroll / Rotate / Destroy buttons | ✅ | ❌ | **Gap** |
| Per-key security metadata display | ✅ key storage, certification, auth, AMR | ❌ | **Gap** |
| WSCA section in Settings | ✅ | ❌ | **Gap** |

### Test Automation

| Feature | Kotlin (Android) | Swift (iOS) | Gap |
|---------|-------------------|-------------|-----|
| Test action dispatch | ✅ ADB intents via `dispatchWscaTestAction()` | ❌ | **Gap** |
| Debug manifest/entitlements | ✅ `AndroidManifest.xml` WSCA_TEST action | ❌ | **Gap** |
| Structured JSON output for test harness | ✅ logcat `WSCA_TEST_RESULT` tag | ❌ | **Gap** |

## Implementation Plan

### Phase 1 — SDK types

1. Add `DetailedKeyInfo` struct to `Signer.swift` with fields: `keyId`,
   `algorithm`, `pluginId`, `createdAt`.
2. Add `listKeysDetailed()` to `Signer` protocol.
3. Implement `listKeysDetailed()` in `UniFFISigner.swift`, mapping from
   FFI `KeyInfo` which already carries `plugin_id` and `created_at`.

### Phase 2 — ViewModel lifecycle

4. Replace `r2psEnabled: Bool` with `selectedPluginId: String` and
   `selectPlugin(pluginId:)` method.
5. Add `enrollWscd()`, `rotateLifecycle()`, `destroyLifecycle()` methods.
6. Add `@Published` state: `wscdKeys`, `wscdKeySecurityProps`,
   `wscdLifecycleStatus`.
7. Add `refreshWscdInfo()` that fetches keys and per-key security
   properties.
8. Always initialize WSCD signer (not conditional on R2PS).

### Phase 3 — Developer UI

9. Create `WscaDeveloperView.swift` with:
   - Plugin Picker (softkey / r2ps / fido2)
   - Enroll / Rotate / Destroy buttons
   - Key list with per-key security properties display
10. Add WSCA Developer navigation entry to `SettingsView.swift`.
11. Wire view to ViewModel state.

### Phase 4 — Test automation

12. Add URL scheme handler (`siros-sample://wsca-test?action=enroll&plugin_id=softkey`)
    as iOS equivalent of Android ADB intents.
13. Add `os_log`-based structured JSON output (iOS equivalent of logcat
    `WSCA_TEST_RESULT` tag).
14. Add `xcrun simctl openurl` support in `sirosid-tests` for iOS test
    automation.
15. Add iOS WSCA lifecycle spec alongside the existing Android one.

## Notes

- The Rust `KeyInfo` struct in `siros-wscd-manager` already has `plugin_id`
  and `created_at` fields — the Swift SDK simply drops them in the current
  `listKeys()` mapping. Phase 1 is straightforward.
- The `SignerLifecycleManager` protocol and `UniFFISigner+Lifecycle`
  extension already provide full lifecycle bindings — Phase 2 is about
  wiring these into the ViewModel, not implementing new FFI.
- iOS has no direct ADB-intent equivalent. URL schemes via `xcrun simctl
  openurl` are the standard approach for headless test automation on iOS
  simulators.

# Platform Differences: Swift SDK (iOS/macOS) vs Kotlin SDK (Android)

> **Scope:** differences that exist because the two host platforms differ —
> what each OS lets a third-party app do, and which APIs it exposes to do it
> with. Features that are merely further along on one side because testing
> was prioritised there are listed separately at the end, and are **not**
> platform limits.
>
> **Baseline:** `siros-sdk-swift` @ `84ee7a1`, `siros-sdk-kotlin` @ `b933790`.

## TL;DR

The real divergence is all at the OS boundary. Android lets the SDK own
things iOS reserves for the system: a Credential Manager registry with a
swappable WASM matcher, a passkey-provider service, HCE-based NFC static
handover for mdoc engagement (iOS is QR-only), and USB HID for FIDO2 keys
(iOS gets CoreNFC only, so there is no transport race either). Apple pushes
back in the other direction with version cliffs and different primitives —
security-key PRF needs iOS 26.4+ and degrades to a non-secret HKDF fallback
below that, App Attest behaves nothing like Play Integrity despite the shared
interface, CoreBluetooth demands explicit backpressure, and Keychain +
`LAContext` replaces Android KeyStore. The deployment surface differs too:
Kotlin is Android-only (minSdk 28), while Swift covers iOS 16+/macOS 13+ plus
a degraded Linux mode with no CryptoKit.

## 1. OS credential-picker integration

The largest structural difference. **Android has a registry model; iOS does
not.**

On Android, `sdk/wallet/dcapi/SirosCredentialRegistry.kt` and
`StockEntryBuilder.kt` pre-register the wallet's credentials with Credential
Manager as a blob, together with a **swappable WebAssembly matcher** that the
platform runs inside the picker to decide which credentials to offer. We ship
our own matcher rather than the one AndroidX's `OpenId4VpRegistry` supplies,
because Google's build understands `mso_mdoc` and `dc+sd-jwt` and nothing
else — without the swap, a verifier asking for `mso_mdoc_zk` gets no entry at
all and the ZK presentation path is unreachable from a browser.

None of that has an iOS counterpart. Apple queries a provider extension live,
so there is nothing to pre-register and no matcher to swap. The Swift SDK
instead performs the whole request cycle in-process:
`Sources/SirosWallet/DCAPIRequestParser.swift` and
`Sources/SirosWallet/SirosWallet+DCAPI.swift` parse the request (including
signed/multisigned JAR signature verification), evaluate trust, match
candidates and build the response. What the SDK cannot contain is the OS
entry point itself, which on iOS must be an app-extension target owned by the
host app rather than a library.

**Passkey provider role.** `sdk:passkey-provider`
(`SirosCredentialProviderService`, `@RequiresApi(34)`) lets a wallet surface
its passkeys in Android's system credential picker. This is not portable: the
iOS equivalent is an AutoFill/credential-provider *extension target*, which by
construction cannot ship as an SDK module.

## 2. FIDO2 external-authenticator transports

| Transport | Kotlin (Android) | Swift (iOS/macOS) |
|-----------|------------------|-------------------|
| USB HID | `UsbCtap2Transport` — full CTAPHID framing over `android.hardware.usb` | **Not possible** — no USB HID host access for third-party iOS apps |
| NFC | `NfcCtap2Transport` — `enableReaderMode` | `NfcCtap2Transport` — CoreNFC `NFCTagReaderSession` / `NFCISO7816Tag` |
| Race both | `CompositeCtap2Transport` (AUTO/USB/NFC, sticky once a race is won) | N/A — only one transport exists to race |

As documented in `Sources/SirosKeystore/NfcCtap2Transport.swift`, CoreNFC is
the only viable transport on iOS: USB HID host mode is unavailable to
third-party apps, and no YubiKey implements BLE-FIDO2. The CTAP2/CBOR layer
itself is shared — both SDKs are thin raw-byte transports over
`siros-wscd-manager`'s Rust `preview_sign_protocol`.

## 3. WebAuthn PRF availability

Android's Credential Manager accepts the `prf` extension as plain request
JSON, uniformly for platform authenticators and security keys. Apple gates it
in two separate steps (`Sources/SirosAuth/ASAuthorizationAuthProvider.swift`):

- platform authenticator PRF → **iOS 18 / macOS 15**
- **security-key** PRF (the CTAP2 `hmac-secret` analog) → the request's `.prf`
  setter and the assertion's `.prf` getter only exist on **iOS/macOS 26.4+**,
  later than the platform-authenticator equivalent

Below those versions the Swift provider falls back to a local
HKDF-of-credentialId derivation, which is explicitly **not** secret and
**not** gated by device authentication. The Kotlin SDK has no equivalent
version cliff. This is also why the Swift CI requires Xcode 26.4+.

## 4. Device / app attestation for WIA

Both SDKs implement the same `NativeAttestationProvider` interface, but the
underlying platform services are structurally different:

| | `PlayIntegrityProvider` (Kotlin) | `AppAttestProvider` (Swift) |
|---|---|---|
| Service | Google Play Integrity | Apple `DCAppAttestService` |
| Prerequisites | Play Services present, cloud project number | App Attest entitlement, real device |
| Availability probe | `isAvailable = true` always — no cheap synchronous check exists; real unavailability surfaces as an exception | Real `isSupported`, and it is `false` on Simulator and in CI |
| Key model | Per-request integrity token | One key per install; re-attesting an existing key is not meaningful (a distinct error case with no Play Integrity analogue) |
| Evidence type | `google_play_integrity` | Apple attestation / assertion |

## 5. mdoc proximity (ISO 18013-5)

**NFC static handover is Android-only.** The Kotlin sample app serves device
engagement as an NFC Forum Type 4 Tag through `MdocHostApduService`
(`HostApduService`). iOS gives third-party apps no host card emulation at all
— that capability is restricted to system frameworks (transit/ID passes via
PassKit). `Sources/SirosKeystore/Mdoc/NfcHandoverSelect.swift` therefore
builds the Handover Select NDEF message as pure, testable CBOR/NDEF
construction so the `SessionTranscript` NFCHandover path can still be
exercised, but there is no `MdocHostApduService` equivalent and none is
planned. **On iOS, device engagement is QR-only.**

**BLE works on both** (central client mode and peripheral server mode), but
the platform APIs force materially different implementations:

- CoreBluetooth requires explicit transmit-queue backpressure — `updateValue`
  returning `false` must be resumed from
  `peripheralManagerIsReady(toUpdateSubscribers:)`, or chunks are silently
  lost. Android's `notifyCharacteristicChanged` needs no such handling.
- CoreBluetooth adds the Client Characteristic Configuration Descriptor
  (CCCD, `0x2902`) automatically for `.notify`/`.indicate` characteristics;
  Android's `BluetoothGattServer` requires it to be added manually.
- Permission handling differs in kind: `CBPeripheralManager.state` is read
  fresh on every delegate callback (including after the user later grants
  access), whereas the Android side tracks runtime-permission state
  separately — which is what produced a real stale-flag bug there.
- Chunk sizing must respect both the negotiated ATT MTU and the Bluetooth
  Core Specification's 512-byte attribute ceiling on both platforms; this was
  found on real hardware on the Android side and carried across.

## 6. Local authenticator fallback

`LocalAuthProvider` exists on both sides as a dev/test authenticator that
implements the WebAuthn authenticator model on-device, but the key store
differs:

- **Kotlin:** Android KeyStore (hardware-backed where available), API 28+, no
  Play Services or external credential provider required.
- **Swift:** Keychain with `kSecAttrAccessControl` plus `LAContext` /
  `kSecUseAuthenticationContext`, so the signing key stays gated behind real
  device authentication. Where `Security` is unavailable (Linux) it throws
  rather than silently signing.

## 7. Deployment surface

- **Kotlin: Android only.** Every module is an Android library, `minSdk 28`
  (Android 9) / `compileSdk 36`. There is no desktop-JVM target.
- **Swift: iOS 16+ and macOS 13+ first-class, plus partial Linux.** On Linux
  there is no CryptoKit, so the wallet's failable initialiser returns `nil`
  unless the host supplies a custom `KeystoreManager`; `swift-crypto` covers
  SHA-256 for circuit-artifact hash verification and `FoundationNetworking`
  covers URLSession. The Kotlin SDK has no analogous degraded mode.

## 8. Minor API-shape differences

- **TLS pinning.** URLSession has no built-in pinning, so the Swift SDK
  provides `TLSPinningConfig` (SPKI SHA-256 pins, optional strict mode). The
  Kotlin SDK simply hands the host app's OkHttp client its
  `CertificatePinner` and owns no pinning code of its own.
- **Test-harness dispatch.** Android drives WSCA lifecycle test actions via
  ADB intents; iOS has no equivalent, so the harness must go through a URL
  scheme driven by `xcrun simctl openurl`. (Tracked as Phase 4 of
  `WSCA-PARITY-PLAN.md`, but the *reason* it looks different is platform, not
  priority.)

## Explicitly not platform differences

The following are Kotlin-first sequencing, not iOS limits, and are expected
to close:

- **ZK proof systems.** Kotlin carries `zk_cred_vega` and `zk_cred_bbs`
  bindings (plus `VegaProofSystem`, `BbsProofSystem`,
  `BbsIssuanceParticipant`); Swift currently has `zk_cred_longfellow` only.
- **DC matcher FFI.** Kotlin has the `siros_dc_matcher_ffi` binding and
  `SharedDcqlMatcher`; the Swift side is pending. (Note that the *registry +
  WASM matcher architecture* in §1 is genuinely Android-specific — this entry
  is about the shared matcher crate binding, not the registry.)
- **WSCA developer surface.** `DetailedKeyInfo` / `listKeysDetailed()`, the
  plugin selector, lifecycle operations in the ViewModel and the WSCA
  developer screen — all enumerated in `WSCA-PARITY-PLAN.md`.

WSCD plugin support itself is at parity: both SDKs know the same
`softkey` / `fido2` / `r2ps` plugin IDs and the same nominal ISO 18045
assurance tiers (`WscdPluginCapabilities`), and both drive them through the
same `siros-wscd-manager` UniFFI bindings.

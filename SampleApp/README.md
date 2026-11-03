# SIROS SDK Sample App (iOS)

A sample iOS wallet app demonstrating the SIROS Swift SDK.

## Features

- **Passkey Authentication** — Register and sign in with WebAuthn passkeys
- **Credential Issuance** — Accept OID4VCI credential offers
- **Credential Presentation** — Respond to OID4VP presentation requests
- **QR Code Scanner** — Scan credential offer / presentation QR codes
- **Deep Link Handling** — `siros-sample://`, `openid-credential-offer://`, `openid4vp://`
- **Presentation History** — View past credential presentations
- **Account-free mdoc verification** — Scan QR or read NFC static handover, connect over BLE, and display names only after core verification and go-trust permit

## Requirements

- Xcode 16+
- iOS 18.0+
- [XcodeGen](https://github.com/yonaskolb/XcodeGen) (for project generation)

## Setup

```bash
# Install XcodeGen if needed
brew install xcodegen

# Generate Xcode project
cd SampleApp
xcodegen generate

# Open in Xcode
open SirosSampleApp.xcodeproj
```

The generated project references the SDK package at `../` (the parent directory).

## Configuration

The app connects to the SIROS wallet backend. Configure the backend URL on the
login screen:

| Build   | Default Backend URL            |
|---------|-------------------------------|
| Debug   | `http://192.168.240.1:8090`   |
| Release | `https://wallet.sirosid.dev`  |

## Architecture

| Layer        | Implementation |
|-------------|----------------|
| UI          | SwiftUI        |
| State       | `@Published` + `ObservableObject` |
| Auth        | Passkey via `SirosWallet.login()` / `.register()` |
| Deep links  | `onOpenURL` + `DeepLinkClassifier` |
| QR scanning | AVFoundation `AVCaptureMetadataOutput` |
| SDK         | `SirosWallet`, `SirosCredentials`, `SirosAuth`, `SirosVerifier` |

## Project Structure

```
SampleApp/
├── project.yml              # XcodeGen project spec
├── Resources/
│   ├── Info.plist
│   └── Assets.xcassets/
└── Sources/
    ├── SampleApp.swift      # @main entry point
    ├── ContentView.swift    # Root view + navigation
    ├── WalletViewModel.swift
    ├── VerifierViewModel.swift # Account-free QR/NFC → core → BLE verifier flow
    ├── Theme/
    │   └── SirosTheme.swift
    └── Views/
        ├── LoginView.swift
        ├── MdocVerifierView.swift
        ├── CredentialsView.swift
        ├── CredentialCardView.swift
        ├── CredentialDetailView.swift
        ├── AddCredentialView.swift
        ├── PresentationConsentView.swift
        ├── PresentationHistoryView.swift
        ├── QRScannerView.swift
        └── SettingsView.swift
```

## Account-free nearby mdoc verification

The verifier is independent of login and `WalletState`. On the logged-out screen,
choose **Verify nearby mdoc (no account required)**. A logged-in user can choose
**Verify nearby mdoc** on Home. Neither path uses wallet credentials, account
tokens, cookies, or an authenticated backend session.

The sample requests one `org.iso.18013.5.1.mDL` document and only
`given_name`/`family_name` in `org.iso.18013.5.1`, with `intentToRetain: false`.
Claims appear only after verifier-core accepts the complete response and
go-trust explicitly permits every returned document. Denial, PDP outage,
session termination, malformed engagement, cancellation, and transport errors
show no claims.

### go-trust configuration

Configure these fields directly on the verifier screen:

- **Complete evaluation URL**: the full AuthZEN evaluation endpoint; no path or
  query is appended. Debug defaults to `http://localhost:9095/v1/evaluate` for
  Simulator. On a physical phone, `localhost` means the phone itself, so use a
  reachable go-trust URL instead.
- **Tenant**: sent as `X-Tenant-ID`.

Release builds start with both values empty and require configuration. For
session-scoped overrides, set `SIROS_VERIFIER_EVALUATION_ENDPOINT` and
`SIROS_VERIFIER_TENANT_ID` in the launch environment. Values entered in the UI
are persisted separately from the wallet backend and tenant.

Real verification also needs the matching native
`SirosVerifierCore.xcframework`. Set `SIROS_VERIFIER_CORE_XCFRAMEWORK_PATH` to
its absolute path whenever the package is resolved/built, for example:

```bash
cd SampleApp
xcodegen generate
SIROS_VERIFIER_CORE_XCFRAMEWORK_PATH=/absolute/path/SirosVerifierCore.xcframework \
  xcodebuild -project SirosSampleApp.xcodeproj -scheme SirosSampleApp \
  -destination 'generic/platform=iOS' build
```

Without it, engagement parsing can still run, but starting a real reader reports
that native verifier core is unavailable.

### Logged-out two-device demo (QR + BLE)

1. On a physical wallet device, sign in and hold an mDL credential suitable for
   the request. Open **Activate**, switch to proximity engagement, and display
   its QR code.
2. On a second physical device running this sample, remain logged out and choose
   **Verify nearby mdoc (no account required)**.
3. Enter a complete go-trust evaluation URL reachable from the verifier device
   and its tenant, then choose **Scan mdoc engagement QR** and scan the wallet.
4. Keep Bluetooth enabled and the devices nearby. The app elects one offered BLE
   role, sends SessionEstablishment, receives one complete SessionData response,
   and shows the two names only after verification and all PDP permits.

**Tap wallet (NFC)** is an alternative engagement producer for a compatible
wallet/tag that offers ISO 18013-5 NFC static handover. NFC is used only to read
the Type 4 NDEF Handover Select message; SessionData still travels over the
same elected BLE transport as QR. The sample wallet's holder Activate screen
does not itself emulate an NFC tag.

The host configuration preserves the existing FaceTec ISO 7816 application IDs
and adds `D2760000850101` (NDEF Type 4 application) and `A0000002480400` (mdoc
application). The existing TAG reader entitlement is required. NFC timeout,
unavailability, malformed handover, and cancellation fail closed without
claims. A compatible NFC wallet/tag and physical hardware are required for an
end-to-end NFC demo.

`VerifierViewModelTests` uses injected engagement/session/election/transport
fakes for QR/NFC errors, stale-claim clearing, and deterministic cancellation
cleanup. Those sample tests do **not** validate native cryptography, a real
PDP, CoreNFC, BLE radios, or two-device interoperability; run those separately
on iOS hardware.

## TestFlight distribution

`.github/workflows/testflight-upload.yml` builds a signed IPA and uploads it to
TestFlight. It runs automatically on every `v*` tag push, and can be run manually
from the Actions tab — with a `dry_run` option that builds and exports the IPA as a
workflow artifact without uploading, which is the safe way to validate signing the
first time.

The version comes from the tag (`v0.6.1` → `0.6.1`) rather than from
`project.yml`, so a stale `MARKETING_VERSION` can't ship under the wrong number.
The build number is the GitHub run number, which is monotonic and unique — App
Store Connect rejects a re-used (version, build) pair, including on a re-run of
the same tag.

### One-time setup

None of this can be done from CI; it needs a Developer Program account.

**1. App ID.** In the Apple Developer portal, register `org.siros.sdk.sample` and
enable the capabilities the app's entitlements request:

- **Near Field Communication Tag Reading** (`com.apple.developer.nfc.readersession.formats`)
- **App Attest** (`com.apple.developer.devicecheck.appattest-environment`)

If these aren't enabled on the App ID, provisioning-profile creation fails during
the archive step.

**2. App record.** Create the app in App Store Connect under the same bundle ID.
TestFlight uploads are rejected until the record exists.

**3. App Store Connect API key.** Users and Access → Integrations → App Store
Connect API. Create a key with the **App Manager** role and download the `.p8`
once — Apple won't let you download it again.

**4. Distribution certificate.** Export your *Apple Distribution* certificate and
private key from Keychain Access as a `.p12` with a password, then base64 it:

```bash
base64 -i Distribution.p12 | pbcopy
```

### Repository secrets

| Secret | What it is |
| --- | --- |
| `APPSTORE_ISSUER_ID` | Issuer ID (a UUID) shown above the key list in App Store Connect |
| `APPSTORE_KEY_ID` | The API key's Key ID |
| `APPSTORE_PRIVATE_KEY` | Full contents of the `.p8`, including the BEGIN/END lines |
| `IOS_DIST_CERT_P12_BASE64` | Base64 of the Apple Distribution `.p12` |
| `IOS_DIST_CERT_PASSWORD` | Password set when exporting the `.p12` |

The workflow checks all five up front. With none of them set it skips with a
warning - the pipeline is simply not enabled yet, and a release tag should not
carry a red check for that. With some set and some missing it fails immediately
with a list of the missing ones, rather than dying inside `codesign` twenty
minutes later.

### App Attest environment

`SampleApp.entitlements` sets `com.apple.developer.devicecheck.appattest-environment`
to `development`. That is correct for local builds. If App Store Connect rejects a
TestFlight build over it, change that value to `production` for distribution
builds — but be aware this switches which App Attest environment the wallet's key
attestation talks to, so verify attestation still works after the change rather
than assuming it.

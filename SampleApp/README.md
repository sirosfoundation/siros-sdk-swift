# SIROS SDK Sample App (iOS)

A sample iOS wallet app demonstrating the SIROS Swift SDK.

## Features

- **Passkey Authentication** — Register and sign in with WebAuthn passkeys
- **Credential Issuance** — Accept OID4VCI credential offers
- **Credential Presentation** — Respond to OID4VP presentation requests
- **QR Code Scanner** — Scan credential offer / presentation QR codes
- **Deep Link Handling** — `siros-sample://`, `openid-credential-offer://`, `openid4vp://`
- **Presentation History** — View past credential presentations

## Requirements

- Xcode 16+
- iOS 16.0+
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
| SDK         | `SirosWallet`, `SirosCredentials`, `SirosAuth` |

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
    ├── Theme/
    │   └── SirosTheme.swift
    └── Views/
        ├── LoginView.swift
        ├── CredentialsView.swift
        ├── CredentialCardView.swift
        ├── CredentialDetailView.swift
        ├── AddCredentialView.swift
        ├── PresentationConsentView.swift
        ├── PresentationHistoryView.swift
        ├── QRScannerView.swift
        └── SettingsView.swift
```

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

- **Near Field Communication Tag Reading** (`com.apple.developer.nfc.readerSession.formats`)
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

The workflow checks all five up front and fails immediately with a list of any
that are missing, rather than dying inside `codesign` twenty minutes later.

### App Attest environment

`SampleApp.entitlements` sets `com.apple.developer.devicecheck.appattest-environment`
to `development`. That is correct for local builds. If App Store Connect rejects a
TestFlight build over it, change that value to `production` for distribution
builds — but be aware this switches which App Attest environment the wallet's key
attestation talks to, so verify attestation still works after the change rather
than assuming it.

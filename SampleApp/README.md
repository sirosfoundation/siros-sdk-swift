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

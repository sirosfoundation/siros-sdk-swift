# SIROS SDK for iOS/macOS (Swift)

[![Swift CI](https://github.com/sirosfoundation/siros-sdk-swift/actions/workflows/swift.yml/badge.svg)](https://github.com/sirosfoundation/siros-sdk-swift/actions/workflows/swift.yml)
[![codecov](https://codecov.io/gh/sirosfoundation/siros-sdk-swift/graph/badge.svg)](https://codecov.io/gh/sirosfoundation/siros-sdk-swift)
[![Swift 5.10+](https://img.shields.io/badge/Swift-5.10+-orange.svg)](https://swift.org)
[![Platform](https://img.shields.io/badge/platform-iOS%2016%2B%20%7C%20macOS%2013%2B-lightgrey.svg)](https://developer.apple.com)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sirosfoundation/siros-sdk-swift/badge)](https://scorecard.dev/viewer/?uri=github.com/sirosfoundation/siros-sdk-swift)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue.svg)](LICENSE)

Native Swift SDK for integrating SIROS ID wallet infrastructure into iOS and macOS apps.

## Modules

| Module | Description |
|--------|-------------|
| `SirosTransport` | WMP client (WebSocket), JSON-RPC codec, engine session |
| `SirosAuth` | WebAuthn/passkey authentication, backend API client |
| `SirosKeystore` | JWE-encrypted keystore, HKDF key derivation, VP signing |
| `SirosFlow` | OID4VCI/OID4VP flow orchestration over WMP |
| `SirosCredentials` | Credential storage, DCQL matching, VCTM, SD-JWT utilities |
| `SirosWallet` | Top-level wallet API combining all modules |

## Requirements

- iOS 16+ / macOS 13+
- Swift 5.10+
- Xcode 16+ (for Apple platforms)

## Installation

Add the package to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/sirosfoundation/siros-sdk-swift.git", from: "0.1.0"),
]
```

Or in Xcode: File → Add Package Dependencies → enter the repository URL.

## Quick Start

```swift
import SirosWallet
import SirosAuth

let config = WalletConfig(
    backendUrl: "https://wallet.example.com",
    tenantId: "your-tenant-id"
)

// On iOS, use the built-in ASAuthorization provider:
let authProvider = ASAuthorizationAuthProvider(presentationAnchor: window)

// Use Keychain for persistent session storage:
let sessionStore = KeychainSessionStore(service: "com.example.wallet")

guard let wallet = SirosWallet(
    config: config,
    authProvider: authProvider,
    sessionStore: sessionStore
) else {
    fatalError("Failed to initialize wallet (missing keystore on this platform)")
}

// Register / login
try await wallet.register(userName: "alice")
try await wallet.login()
```

## Key Features

### WMP (Wallet Messaging Protocol) Support

Full WMP implementation as an alternative to the legacy WebSocket engine protocol:

- **`WmpPeer`** — JSON-RPC 2.0 dispatch with profile-based routing
- **`OpenID4xProfile`** — OID4VCI/OID4VP flow handling (sign, match, trust evaluation)
- **`WmpHttpSseTransport`** — HTTP+SSE transport (Apple platforms)
- **`WmpWebSocketTransport`** — WebSocket transport with `wmp.v1` subprotocol

Enable via `WalletConfig(useWmpProtocol: true)`. Requires backend with WMP endpoint.

### Engine URL Auto-Discovery

The SDK auto-discovers the engine WebSocket URL from `/.well-known/wallet-configuration`:

```swift
let config = WalletConfig(
    backendUrl: "https://wallet.example.com"
    // engineUrl defaults to "" → auto-discovered at runtime
)
```

### Batch Credential Issuance

`KeystoreManager.generateProof(freshKey:)` supports batch VCI conformance — each credential in a batch is bound to a unique key to prevent verifier linkability.

## Architecture

```
┌─────────────────────────────────────────┐
│           Your iOS/macOS App            │
│  ┌───────────────────────────────────┐  │
│  │          SIROS SDK                │  │
│  │  ┌─────────┐  ┌───────────────┐  │  │
│  │  │  Flow   │  │  Credentials  │  │  │
│  │  ├─────────┤  ├───────────────┤  │  │
│  │  │Keystore │  │   Transport   │  │  │
│  │  ├─────────┤  ├───────────────┤  │  │
│  │  │  Auth   │  │    Wallet     │  │  │
│  │  └─────────┘  └───────────────┘  │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

## Build & Test

```bash
# Run all tests
swift test --parallel

# Build for iOS Simulator
swift build \
  --sdk "$(xcrun --sdk iphonesimulator --show-sdk-path)" \
  --triple arm64-apple-ios16.0-simulator
```

## Documentation

API documentation is generated using [DocC](https://www.swift.org/documentation/docc/).

```bash
# Generate documentation
swift package generate-documentation --target SirosWallet
```

## License

BSD 2-Clause License. See [LICENSE](LICENSE) for details.

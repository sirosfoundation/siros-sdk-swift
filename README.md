# SIROS SDK for iOS/macOS (Swift)

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

## License

BSD 2-Clause License. See [LICENSE](LICENSE) for details.

# Architecture

## Module Dependency Graph

```
┌──────────────────────────────────────────────────┐
│               Your iOS/macOS App                 │
└──────────┬───────────────────────────────────────┘
           │
┌──────────▼───────────────────────────────────────┐
│               SirosWallet                        │
│  SirosWallet — top-level orchestrator            │
│  Combines all modules into a single API          │
├──────────┬──────┬──────┬──────┬──────────────────┤
│          │      │      │      │                  │
│  ┌───────▼──┐ ┌─▼────┐│┌─────▼─────┐┌───────────▼┐
│  │SirosFlow │ │Siros ││ │Siros      ││Siros       │
│  │FlowClient│ │Auth  ││ │Keystore   ││Credentials │
│  └────┬─────┘ └──┬───┘│ └───────────┘└────────────┘
│       │          │     │                           │
│  ┌────▼──────────▼─────▼───────────────────────┐  │
│  │          SirosTransport                     │  │
│  │  WmpSession, WmpCodec, WebSocketTransport   │  │
│  └─────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────┘
```

## Module Responsibilities

### SirosTransport
- WMP (Wallet Message Protocol) client over WebSocket
- JSON-RPC 2.0 codec with request-response correlation
- Automatic reconnection with session resumption
- Engine session management (WalletEngineSession)
- AnyCodable type for dynamic JSON values

### SirosAuth
- WebAuthn/FIDO2 registration and authentication
- AuthProvider protocol for platform-specific passkey implementations
- ASAuthorizationAuthProvider for iOS (ASAuthorizationController)
- BackendApiClient for REST communication with wallet backend
- WebAuthnAuthClient for WebAuthn challenge/response flows

### SirosKeystore
- JWE-encrypted credential storage (requires CryptoKit)
- HKDF key derivation from WebAuthn PRF output
- SD-JWT VP token signing with key binding
- EncryptedContainer for AES-GCM/ECB operations
- KeystoreManager protocol for custom implementations

### SirosFlow
- OID4VCI (credential issuance) flow handling
- OID4VP (credential presentation) flow handling
- FlowClient bridges WMP messages to flow events

### SirosCredentials
- Credential storage (CredentialStore protocol)
- DCQL (Digital Credentials Query Language) matching
- VCTM (Verifiable Credential Type Metadata) fetching
- SD-JWT parsing and validation utilities
- Base error hierarchy (SirosError)

### SirosWallet
- SirosWallet: top-level API for host applications
- Session management (login, logout, token refresh)
- Flow orchestration (accept/reject issuance/presentation)
- KeychainSessionStore for persistent iOS/macOS storage
- Event listener pattern for UI updates

## Concurrency Model

- All SDK operations are `async throws` functions
- WmpSession uses AsyncStream for message routing
- Send serialization via a private actor (SendSerializer)
- Transport state delivered via AsyncStream
- Platform-conditional: `#if canImport(CryptoKit)` for crypto,
  `#if canImport(FoundationNetworking)` for Linux URLSession

## Error Model

All errors conform to `Error`, `Sendable`, and `LocalizedError`:

- `SirosError` — top-level SDK errors (.network, .auth, .keystore, .wallet, .backendApi)
- `KeystoreError` — crypto and key material errors
- `WmpSessionError` — WMP protocol errors
- `WmpTimeoutError` — request timeout
- `WmpCodecError` — JSON codec errors
- `TransportError` — WebSocket transport errors
- `EngineSessionError` — engine connection errors

## Security Model

1. **Key derivation**: WebAuthn PRF → HKDF-SHA256 → AES-256 main key
2. **Credential storage**: JWE-encrypted containers (A256GCM)
3. **Session storage**: Keychain with `afterFirstUnlockThisDeviceOnly` protection
4. **Token handling**: Short-lived app tokens, refresh tokens in session store
5. **Transport**: WSS (WebSocket Secure) with TLS
6. **Init safety**: Failable init (returns nil) when platform crypto unavailable

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| iOS 16+  | Full   | CryptoKit, ASAuthorization, Keychain |
| macOS 13+| Full   | CryptoKit, ASAuthorization, Keychain |
| Linux    | Partial| No CryptoKit — provide custom KeystoreManager |

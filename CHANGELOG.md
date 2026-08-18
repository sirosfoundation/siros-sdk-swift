# Changelog

All notable changes to the SIROS SDK for iOS/macOS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0]

Highlights since v0.3.0 (41 commits):
- Longfellow ZKP Phase 3: `ZkProofSystem` + `LongfellowZkProofSystem` integration, wired into
  the DC API ZK presentation path, plus cross-port ZK/pseudonym fixes (order-independent
  pseudonym re-derivation lookup, `pseudonym_seed` acceptance) (#94)
- OID4VCI Phase 2 credential renewal (refresh_token flow), extracted into
  `SirosWallet+Renewal.swift`, with data-loss/crash fixes and immediate re-auth on a 401 from
  the AS token endpoint (#91, #93)
- WSCD Settings UI consolidation (task #214) and AutoEnroll hint mechanism ported from Kotlin,
  including a race fix in the offered-once guard
- FIDO2 CTAP2 transport wired into the sample app, with recovery from transient CTAP2
  disconnects instead of wedging
- TS11 registry discovery: `Ts11RegistryClient` wired into `WscdSettingsView`, including a
  wildcard-issuer override resolution fix
- Credential-type registry service integration (`go-wallet-backend`) with TTL-cached
  type-metadata fetches scoped to registry calls (#83, #84)
- Security/architecture review pass: SDK/sample-app boundary refactor, WSCD key sync,
  audience-validation enforcement, and immediate sign-failure reporting (#86)
- Presentation flow parity fixes: `redirect_uri` on error, verifier display name/chrome,
  `CredentialCardView` reuse, per-credential-type wizard steps (#89, #90)
- WS-engine transport: DCQL matching + ZK presentation wiring, `sign_presentation` VP-part
  builder extraction
- Sample app: QR-detection/message-banner localization across remaining views, NFC usage
  description/entitlement fixes, real test target wiring for `WalletViewModelTests`/
  `MessageBannerTests` (#98, #100, #101)
- Dependency bumps: `siros-wscd-manager` to v0.7.2 (#85)

## [0.1.0]

### Added
- Initial SDK with 6 modules: SirosTransport, SirosAuth, SirosKeystore, SirosFlow, SirosCredentials, SirosWallet
- ASAuthorizationAuthProvider for iOS passkey support
- KeychainSessionStore for persistent session storage on Apple platforms
- CI pipeline with macOS test, iOS build, Linux test, and coverage gate (25%)
- README, CONTRIBUTING.md, ARCHITECTURE.md, CHANGELOG.md

### Fixed
- Replaced fatalError calls with failable init and thrown errors
- Eliminated NSLock-held-across-await deadlock in WmpSession (SendSerializer actor)
- Added Sendable conformance to WmpCodecError
- Added LocalizedError conformance to all error types

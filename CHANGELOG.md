# Changelog

All notable changes to the SIROS SDK for iOS/macOS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

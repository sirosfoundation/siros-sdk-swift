# Contributing to SIROS SDK for iOS/macOS (Swift)

Thank you for your interest in contributing to the SIROS SDK.

## Development Setup

1. Clone the repository
2. Build: `swift build`
3. Run tests: `swift test --parallel`

### Linux Development

The SDK builds and tests on Linux using Swift 6.0+. CryptoKit-dependent features
(JweKeystore, EncryptedContainer AES operations) are unavailable on Linux — provide
custom implementations via the `KeystoreManager` protocol.

## Code Style

- Follow Swift API Design Guidelines
- Use `internal` visibility by default; only expose `public` API intentionally
- All public API must have documentation comments
- All error types must conform to `Error`, `Sendable`, and `LocalizedError`
- Use `#if canImport(...)` for platform-conditional code

## Testing

- All new code must include unit tests
- Coverage gate: **25% minimum** (enforced in CI, target 70%+)
- Use fakes/mocks for network and platform dependencies
- No tests that depend on external/shared environments

## Pull Requests

1. Create a feature branch from `main`
2. Keep commits focused and well-described
3. Ensure CI passes (macOS test + iOS build + Linux test + coverage gate)
4. Request review from a maintainer

## Security

If you discover a security vulnerability, please report it privately to security@siros.org.
Do **not** open a public issue for security vulnerabilities.

## License

By contributing, you agree that your contributions will be licensed under the BSD 2-Clause License.

# Changelog

All notable changes to the SIROS SDK for iOS/macOS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0] - 2026-09-10

First public SDK release, alongside siros-sdk-kotlin 0.14.0. The 0.7.0 tag
(2026-09-07) never rolled this section, so some entries below shipped in 0.7.0
already; everything since 0.6.1 is here. Consumers must raise their deployment
target to iOS 18 / macOS 15.

### Fixed
- **Login after logout could never unlock the wallet.** `logout()` clears the
  account-scoped session store, so the next `login()` had no PRF salt to
  offer: the ceremony carried no PRF and the separate probe derived one for
  a fresh random salt the container was never sealed with. Login now offers
  every cached account's passkey with its own salt in the single ceremony
  (WebAuthn `prf.evalByCredential`; `AuthenticateOptions.prfSaltsByCredential`,
  Apple's `perCredentialInputValues`), uses the salt of the credential the
  user actually picked for the probe, and restores that account's
  `hkdfSalt`/`hkdfInfo` from the registry - the Kotlin SDK's
  `loginCandidates` pattern. Surfaced by review on #139.

### Added
- `AuthenticateOptions.prfSaltsByCredential` and `prfSalt(for:)`; custom
  `AuthProvider`s should evaluate PRF for the salt of the credential used.
- `AccountRegistry.inMemory()` and a `SirosWallet.init(accountRegistry:)`
  parameter, so tests and previews do not touch the Keychain.

### Changed
- **`ASAuthorizationAuthProvider.getPrfOutput` fails closed.** It no longer
  falls back to `HKDF(credentialId, salt)` when the authenticator returns no
  PRF output; it throws `SirosError.auth("PRF extension not supported by
  this authenticator")`, as the Kotlin SDK's production provider always has.
  The credential ID is public, so a container sealed under that fallback was
  protected by nothing the user holds. Containers sealed under it - a
  security key on iOS/macOS below 26.4, where the security-key PRF API does
  not exist - can no longer be opened; there is deliberately no migration.
  The dev-only `LocalAuthProvider`s keep their own software PRF (Kotlin's
  keys the HMAC with `credentialId || "SIROS-LOCAL-PRF-v1"`, Swift's with
  `credentialId` alone); they never roam, so the divergence is documented
  rather than reconciled.
- **Platform floor is now iOS 18 / macOS 15** (was iOS 16 / macOS 13). The
  wallet's key material is derived from the login passkey's WebAuthn PRF
  output, and Apple's PRF extension exists from iOS 18; on 16 and 17 the
  package built and ran but login could not unlock the wallet. The
  `#available(iOS 18)` branches around PRF are gone (security-key PRF stays
  gated at 26.4); macOS is a build/test platform only. Consumers on an older
  deployment target must raise it to adopt this release.

### Added
- `HostAppRequirements`: what a host app must declare for each SDK feature
  (Info.plist usage descriptions, `CFBundleURLTypes` schemes, entitlements)
  and an `audit(bundle:)` that reports what the bundle is missing. iOS has
  no manifest merging, so this is the SDK's side of the integration
  contract; the sample app runs it at startup in debug builds.
- `URLSessionR2psTransport` moved into `SirosKeystore` as the default
  `R2psTransportProvider`, so a host app no longer copies it from the
  sample app.
- `DeepLinkClassifier.handledSchemes` (with `credentialOfferSchemes` /
  `presentationRequestSchemes`); `mdoc-openid4vp`, `haip-vp` and `haip-vci`
  are now classified by scheme, as the Kotlin SDK does.
- Wallet instance lifecycle (SID-AUTH-06, go-wallet-backend#319):
  `SirosWallet.listWalletInstances()`, `setWalletInstanceStatus(instanceId:status:reason:)`
  and `deactivateWallet(reason:)` (revokes every instance server-side, then
  forgets the local account), backed by the new `WalletInstance` type and
  `BackendApiClient` methods. WIA generation now sends the logged-in passkey's
  `credential_id` so the backend can link the instance to the passkey.
  `SirosError.walletLifecycleRefusal` reads the `WALLET_SUSPENDED` /
  `WALLET_REVOKED` codes off a 403 login refusal without adding an enum case.
- `PresentationRecord.zkProof` (`zk_proof`): whether a presentation was a
  zero-knowledge proof rather than a raw disclosure, set on the DC API and both
  engine selection paths; sample-app history shows a lock badge for it
- `SirosWallet.availableKeyIds` and an `isZkPresentation` resolver on
  `SirosWallet.eligibleInstances(from:)` / `CredentialUtils.eligibleInstances`

### Changed
- `CredentialUtils.eligibleInstances`/`isBelowRenewThreshold` now require
  `availableKeyIds` and, under every policy, exclude an instance whose bound
  signing key the keystore no longer holds
- `CredentialConsumptionPolicy.consumeNonZkp` now actually distinguishes a
  `mso_mdoc_zk` presentation (never consumed) from a raw one (consumed), decided
  by the first-match query per credential

### Fixed
- `PresentationRecord` decoding tolerates the enrichment fields being absent, so
  records reloaded from the encrypted container (which only carries the
  privatedata-spec-normative fields) no longer fail to decode

## [0.6.1]

Re-release of 0.6.0. No SDK or sample-app source changes.

v0.6.0's release build hung and was cancelled, so that release carries only an
SBOM — the same failure that left v0.3.0, v0.4.0 and v0.5.0 without artifacts.
The cause was the Release workflow's `Configure vendor package access` step,
whose global git `insteadOf` rewrite broke SwiftPM's binary-artifact downloader:
the three xcframework downloads stalled at zero bytes indefinitely. Nothing in
this repository needs that token — every dependency and binary target is public
— so the step was removed (#116), and both macOS jobs gained a 45-minute
timeout so a future stall fails fast instead of burning the 6-hour job limit.

### Changed
- Sample app: MARKETING_VERSION 0.6.1, build 4

## [0.6.0]

Highlights since v0.5.0 (4 commits). Sample app: MARKETING_VERSION 0.6.0, build 3.

### Added
- `BbsProofSystem`: the blind BBS presentation path (#113), plus the wallet's half
  of blind BBS issuance (#114)
- VICAL-based issuer-trust evaluation for mdoc presentation (#111)

### Changed
- `ZkProofSystem` generalized beyond mdoc-only, so non-mdoc credential formats can
  plug into the same proving interface (#112)

### Fixed
- BLE session-establishment race during proximity presentation (#111)
- SVG `<image>` height normalization in credential logo rendering (#111)
- `SampleApp/project.yml` hardcoded `CFBundleShortVersionString`/`CFBundleVersion`
  in its `info:` block, so `xcodegen generate` overwrote `Resources/Info.plist` and
  reset the built app to 0.1.0/1 — undoing the v0.4.0 fix. Both now substitute
  `$(MARKETING_VERSION)`/`$(CURRENT_PROJECT_VERSION)`.

## [0.5.0]

Highlights since v0.4.0 (10 commits).

### Added
- RICAL reader authentication: `MdocCose.verify1` plus `readerAuth` parsing and
  trust evaluation (ISO 18013-5 Annex F), with an AuthZEN reader-trust call, a
  local fallback, and a settings toggle (#110)

### Changed
- `SirosWallet.swift` split into focused files to clear SwiftLint
  `type_body_length`/`file_length` errors (#106)
- Sample app UX: unified SIROS ID identity-verification path and long-press offer
  detail (#105)
- `siros-wscd-manager` bumped to v0.7.4 (#109)

### Fixed
- `AddCredentialView` offer identity collision across issuers (#108)
- Three wallet bugs surfaced by the PR #106 review and deferred there (#107)

## [0.4.0]

Highlights since v0.3.0 (41 commits):

### Added
- Longfellow ZKP Phase 3: `ZkProofSystem` + `LongfellowZkProofSystem` integration, wired into
  the DC API ZK presentation path (#94)
- OID4VCI Phase 2 credential renewal (refresh_token flow), extracted into
  `SirosWallet+Renewal.swift` (#91, #93)
- FIDO2 CTAP2 transport wired into the sample app
- TS11 registry discovery: `Ts11RegistryClient` wired into `WscdSettingsView`
- Credential-type registry service integration (`go-wallet-backend`) with TTL-cached
  type-metadata fetches scoped to registry calls (#83, #84)
- WS-engine transport: DCQL matching + ZK presentation wiring
- WSCD AutoEnroll hint mechanism ported from Kotlin

### Changed
- WSCD Settings UI consolidation (task #214)
- Security/architecture review pass: SDK/sample-app boundary refactor, WSCD key sync
- Sample app: QR-detection/message-banner localization across remaining views
- Dependency bumps: `siros-wscd-manager` to v0.7.2 (#85)

### Fixed
- Cross-port ZK/pseudonym fixes: order-independent pseudonym re-derivation lookup,
  `pseudonym_seed` acceptance
- OID4VCI renewal data-loss/crash fixes; immediate re-auth on a 401 from the AS token endpoint
- Race fix in WSCD AutoEnroll's offered-once guard
- Recovery from transient CTAP2 disconnects instead of wedging
- TS11 wildcard-issuer override resolution fix
- Audience-validation enforcement; immediate sign-failure reporting (#86)
- Presentation flow parity: `redirect_uri` on error, verifier display name/chrome,
  `CredentialCardView` reuse, per-credential-type wizard steps (#89, #90)
- `sign_presentation` VP-part builder extraction
- NFC usage description/entitlement fixes
- Real test target wiring for `WalletViewModelTests`/`MessageBannerTests` (#98, #100, #101)

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

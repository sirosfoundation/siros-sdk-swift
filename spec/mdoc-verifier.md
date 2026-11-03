# Cross-platform mdoc verifier contract

Kotlin `sdk:verifier` and Swift `SirosVerifier` implement the same behavior with idiomatic public APIs. Generated UniFFI types are not public API.

## Independence and trust

- A verifier does not construct or require `SirosWallet`, a wallet account, an app token, or a logged-in session.
- The sample verifier is available before login and uses a complete, configurable go-trust/AuthZEN evaluation URL and tenant ID without `Authorization` or `Cookie` headers.
- Every document's exact core-produced AuthZEN request must receive an explicit JSON boolean `decision: true`. Denial, malformed/missing/duplicate decisions, HTTP errors, and PDP unavailability fail closed. No local trust fallback or partial accepted-document list is permitted.

## Bytes and request policy

- DeviceEngagement and tag-24 `EDeviceKeyBytes` are retained verbatim. QR handover is the single byte `0xF6`. NFC static handover preserves the complete original NDEF Handover Select message and encodes `[HandoverSelectBytes, null]`.
- DeviceRequest, ReaderAuth, session encryption, DeviceResponse verification, and retained request policy are implemented by verifier-core. Ordered document types, namespaces, elements, and `intentToRetain` are forwarded unchanged.
- ReaderAuth uses a dedicated P-256 verifier identity key and leaf-first DER chain. The signer receives exact COSE input and returns raw 64-byte `r || s`, not DER or a compact JWS. The ephemeral session key never leaves core.
- A response must satisfy the requested document types and every required namespace/element. Extra disclosed claims are allowed. Claims are mapped for display only after all request and PDP checks pass.

## Transport

- A transport sends and receives only complete CBOR SessionEstablishment/SessionData messages. BLE chunks and NFC APDUs stay below that boundary; reassembly is limited to 2 MiB.
- When the wallet offers both BLE modes, both reader discovery roles may run, but exactly one ready transport is elected before SessionEstablishment is sent. Losing roles and all resources are closed deterministically.
- NFC in the first profile means static NFC handover followed by BLE. It does not mean NFC SessionData transport or negotiated handover. Address-only or ambiguous carrier metadata is unsupported rather than guessed.

## Failure and lifecycle

- Core errors preserve stable broad codes (`malformed`, `integrity`, `policy`, `crypto`) where available. Peer session termination retains its numeric status; status 20 is normal termination.
- Starting a new verification clears previous claims. Any failure produces no accepted claims and closes the elected transport, losing candidates, and Reader. Caller cancellation remains cancellation.
- Public verified-element/document values contain only the disclosed CBOR value, docType, issuer evidence, and validity information. Authentication alone is not a trust decision.

## Sample demonstration

Both samples request one `org.iso.18013.5.1.mDL` document with `given_name` and `family_name`, `intentToRetain = false`, and one request/response round trip. They show QR engagement and, where supported, NFC static handover. A result screen is shown only after full acceptance; denial and outage screens contain no disclosed values.

JVM/macOS/Linux tests do not establish radio interoperability. Android ABI tests, iOS Simulator loading tests, and physical-device tests for both BLE roles and NFC static handover are required before release.

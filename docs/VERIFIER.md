# Standalone mdoc verification

`SirosVerifier` adds ISO/IEC 18013-5 reader capabilities without changing the wallet's holder APIs. It does not construct `SirosWallet`, unlock a credential container, or require an account.

## Trust boundary

The verifier-core UniFFI `Reader` owns the SessionTranscript, DeviceRequest and optional ReaderAuth, session encryption, DeviceResponse verification, and request-policy enforcement. Swift owns engagement parsing and transport. go-trust alone decides whether each authenticated issuer is authorized.

`MdocReaderSession.openResponse` returns claims only after:

1. the complete SessionData message decrypts and verifies;
2. the response satisfies the retained document, namespace, and element request;
3. every document's exact AuthZEN request receives an explicit permit.

Denial, a malformed PDP response, an HTTP failure, or an unavailable PDP yields no accepted claims. There is no local trust fallback.

## Account-free PDP configuration

`HttpAuthZenPdp` posts to a complete evaluation URL with `X-Tenant-ID`. Its default session is ephemeral and has no credential or cookie storage:

```swift
let pdp = HttpAuthZenPdp(
    evaluationEndpoint: URL(string: "http://localhost:9095/v1/evaluate")!,
    tenantId: "default"
)
let verifier = MdocProximityVerifier(
    pdp: pdp,
    mdocIssuerRole: "pid-provider"
)
```

A simulator can use `localhost` for go-trust on the host. A physical device needs the host's reachable address. Production applications may supply their own `AuthZenPdp` with deployment-appropriate authentication; the trust decision must still come from go-trust.

## Starting a session

```swift
let engagement = try MdocQrEngagement.parse(scannedValue)
let request = [MdocDocumentRequest(
    docType: "org.iso.18013.5.1.mDL",
    namespaces: [MdocRequestedNamespace(
        namespace: "org.iso.18013.5.1",
        elements: [
            MdocRequestedElement(identifier: "given_name"),
            MdocRequestedElement(identifier: "family_name"),
        ]
    )]
)]
let session = try await verifier.start(engagement: engagement, documents: request)
```

Use an elected `MdocMessageTransport` to send `session.establishmentMessage()` and receive one complete SessionData message. BLE chunks and APDUs never cross the transport boundary. Call `openResponse` and display values only for `MdocReaderInbound.verified`. Await session and transport closure when finished.

ReaderAuth uses a dedicated P-256 verifier identity key and leaf-first DER certificate chain. Its synchronous signer receives exact COSE input and returns raw `r || s`; it must not be a holder credential key, an issuer key, or a compact JWS.

## Native dependency

The production adapter uses `SirosVerifierCore.xcframework` and generated Swift bindings from the same core revision. For a local build, run `ffi/scripts/ios-xcframework.sh` on macOS and set this before resolving the package:

```sh
export SIROS_VERIFIER_CORE_XCFRAMEWORK_PATH=/path/to/SirosVerifierCore.xcframework
```

Tagged core releases publish the XCFramework, Swift bindings, and Swift Package Manager checksum together. Release artifacts never enable verifier-core's `vector-tests` feature.

## Validation boundary

Portable tests cover engagement parsing, request/session orchestration, exact AuthZEN forwarding, fail-closed decisions, and transport state machines. They do not prove native iOS loading or radio interoperability. Run the XCFramework on iOS Simulator and the physical-device BLE/NFC matrix before release.

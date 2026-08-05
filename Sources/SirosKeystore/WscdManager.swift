// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Hardware-key-specific WSCD operations not part of the generic
/// ``Signer``/``KeystoreManager`` surface: additional-plugin registration
/// (FIDO2 rawSign, R2PS remote HSM) and hardware-key lifecycle
/// (enroll/rotate/destroy).
///
/// Only a WSCD-backed keystore (one wrapping a ``UniFFISigner``) supports
/// this - obtain it via `SirosWallet.wscdManager`, which is `nil` for the
/// default JWE-encrypted keystore or any other ``KeystoreManager`` that
/// isn't WSCD-backed.
public protocol WscdManager: SignerLifecycleManager {
    /// Register the FIDO2 previewSign (rawSign) plugin for hardware
    /// authenticators (e.g. a YubiKey). All CTAP2 CBOR request-building/
    /// response-parsing happens in Rust - `transport` only needs to move
    /// raw command/response bytes over USB/BLE/NFC.
    func registerFido2Plugin(transport: Ctap2TransportProvider) throws

    /// Register the R2PS remote HSM plugin.
    func registerR2psPlugin(config: R2psConfig, transport: R2psTransportProvider) throws
}

/// R2PS server connection parameters.
public struct R2psConfig: Sendable {
    public var serverUrl: String
    public var clientId: String
    public var context: String
    /// PEM-encoded P-256 client private key for the R2PS message envelope's
    /// JWS signing. Required for every session regardless of `authMode` -
    /// this identifies the client's own message channel, not the
    /// user-level authentication factor.
    public var clientKeyPem: String
    /// PEM-encoded P-256 server public key for JWE envelope encryption.
    /// Required for every session regardless of `authMode`.
    public var serverPublicKeyPem: String
    public var authMode: R2psAuthMode

    public init(
        serverUrl: String,
        clientId: String,
        context: String,
        clientKeyPem: String,
        serverPublicKeyPem: String,
        authMode: R2psAuthMode
    ) {
        self.serverUrl = serverUrl
        self.clientId = clientId
        self.context = context
        self.clientKeyPem = clientKeyPem
        self.serverPublicKeyPem = serverPublicKeyPem
        self.authMode = authMode
    }
}

/// R2PS user-authentication mode. OPAQUE (RFC 9807) PAKE crypto is handled
/// entirely in Rust (`r2ps-client`) - no PAKE client is needed here.
public enum R2psAuthMode: Sendable {
    /// Password-based OPAQUE authentication.
    case opaque
    /// WebAuthn/FIDO2-based authentication (SCAL2-compliant SAD binding).
    case webAuthn(rpId: String, allowedCredentialIds: [String])
}

/// HTTP transport for R2PS protocol messages.
public protocol R2psTransportProvider: Sendable {
    func send(body: Data) async throws -> Data
}

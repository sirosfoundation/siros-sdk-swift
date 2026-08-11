// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(Security)
import Security
#endif

/// Thrown when a W3C Digital Credentials API request cannot be parsed, or
/// (for the signed/multisigned protocol variant) its JWS signature fails
/// verification against the key material advertised in its own header.
public struct DCAPIRequestException: Error, CustomStringConvertible, Sendable {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var description: String { message }
}

/// Key material a signed/multisigned DC API JAR request conveyed in its JWS
/// header, for trust evaluation - the same shape (x5c or jwk) `SirosWallet`'s
/// engine-relayed trust evaluation (`handleTrustEvaluation`) already uses.
///
/// `[String: Any]` isn't `Sendable` by the compiler's own analysis even
/// though this JSON-derived data never actually escapes across concurrency
/// domains unsafely - matches `KeypairInfo`'s existing `@unchecked Sendable`
/// precedent for the same shape of value.
public struct DCAPIRequestKeyMaterial: @unchecked Sendable {
    public let x5c: [String]?
    public let jwk: [String: Any]?

    public init(x5c: [String]? = nil, jwk: [String: Any]? = nil) {
        self.x5c = x5c
        self.jwk = jwk
    }
}

/// A parsed W3C Digital Credentials API OpenID4VP request (OpenID4VP 1.0
/// Appendix A). `clientId` is `nil` for the unsigned protocol variant (the
/// verified browser origin stands in for it - see `SirosWallet.handleDCAPIRequest`).
public struct DCAPIRequest: @unchecked Sendable {
    public let clientId: String?
    public let responseMode: String
    public let nonce: String
    public let dcqlQuery: [String: Any]?
    public let clientMetadata: [String: Any]?
    /// Present only for the signed/multisigned protocol variant.
    public let keyMaterial: DCAPIRequestKeyMaterial?
    /// The protocol identifier from the incoming request's `requests[0].protocol`
    /// (e.g. "openid4vp-v1-signed") - the platform's own reference wallet
    /// (https://github.com/digitalcredentialsdev/CMWallet) echoes this back
    /// verbatim in the final response envelope (`{"protocol": ..., "data":
    /// ...}`), so it must be threaded through from the request. Named
    /// `protocolIdentifier` rather than `protocol` since the latter is a
    /// reserved keyword in Swift.
    public let protocolIdentifier: String
    /// OAuth2/OIDC `state` (OpenID4VP 1.0 §5.1) - the verifier's only means of
    /// correlating this response back to the right authorization session,
    /// since the response arrives via a wholly separate channel (the DC API
    /// callback) with no other correlator. The wallet MUST echo this back
    /// unchanged in its response body.
    public let state: String?

    public init(
        clientId: String?,
        responseMode: String,
        nonce: String,
        dcqlQuery: [String: Any]?,
        clientMetadata: [String: Any]?,
        keyMaterial: DCAPIRequestKeyMaterial? = nil,
        protocolIdentifier: String,
        state: String?
    ) {
        self.clientId = clientId
        self.responseMode = responseMode
        self.nonce = nonce
        self.dcqlQuery = dcqlQuery
        self.clientMetadata = clientMetadata
        self.keyMaterial = keyMaterial
        self.protocolIdentifier = protocolIdentifier
        self.state = state
    }
}

/// Parses the raw request data string handed to the wallet by the OS/browser
/// for a `navigator.credentials.get({digital: {requests: [{protocol, data}]}})`
/// call - either a raw OpenID4VP authorization request JSON object (the
/// `openid4vp-v1-unsigned` protocol variant) or `{"request": "<JWT>"}` (the
/// `openid4vp-v1-signed`/`-multisigned` JAR variant).
///
/// For the signed variant, the JWS signature IS verified here against the key
/// material embedded in the JWT's own header (x5c or jwk) - an unverified
/// "signed" request would otherwise provide false assurance of authenticity.
/// Whether that key is itself trustworthy (i.e. actually belongs to a
/// legitimate relying party) is a separate, later step - the existing AuthZEN
/// trust-evaluation call, unchanged from the redirect-flow presentation path.
///
/// Only ES256 (P-256) signing keys are supported for the signed variant, for
/// both the `x5c` and bare `jwk` header shapes - the Kotlin SDK's Nimbus-based
/// port also supports RS256/RSA, but this SDK has no JOSE/RSA library
/// dependency anywhere and CryptoKit itself has no RSA signature-verification
/// API, so adding one purely for this rarely-used JWS variant was judged
/// disproportionate; a request signed with an unsupported algorithm/key type
/// throws a clear `DCAPIRequestException` rather than silently mis-verifying.
public enum DCAPIRequestParser {

    public static func parse(_ rawRequestJson: String) throws -> DCAPIRequest {
        guard let data = rawRequestJson.data(using: .utf8),
              let outer = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw DCAPIRequestException("DC API request is not valid JSON")
        }

        // [GetDigitalCredentialOption.requestJson] (Android) / this SDK's
        // equivalent is the FULL request handed to
        // navigator.credentials.get({digital: {requests: [{protocol,
        // data}]}}) - {"requests": [{"protocol": ..., "data": {...}}, ...]} -
        // not a single request's `data` object on its own. The platform
        // picker only surfaces an entry after matching it against one of our
        // registered protocols, so the first (and in practice only, since
        // the caller picks one best protocol before invoking the API) entry
        // is the one that was selected; its `data` is what the rest of this
        // parser (signed vs. unsigned) actually operates on.
        guard let requestEntries = outer["requests"] as? [[String: Any]] else {
            throw DCAPIRequestException("DC API request missing 'requests' array")
        }
        guard let requestEntry = requestEntries.first else {
            throw DCAPIRequestException("DC API request's 'requests' array is empty")
        }
        guard let entryData = requestEntry["data"] as? [String: Any] else {
            throw DCAPIRequestException("DC API request's first entry is missing 'data'")
        }

        let requestJwt = entryData["request"] as? String
        // The platform's own reference wallet echoes this protocol identifier
        // back verbatim in the final response envelope. Falls back to the
        // OpenID4VP protocol implied by this request's own shape if the
        // entry omits it (should not happen per the DC API spec, but the
        // response envelope still needs *some* value).
        let protocolIdentifier = (requestEntry["protocol"] as? String)
            ?? (requestJwt != nil ? "openid4vp-v1-signed" : "openid4vp-v1-unsigned")

        if let requestJwt {
            return try parseSigned(requestJwt, protocolIdentifier: protocolIdentifier)
        }
        return try parseUnsigned(entryData, protocolIdentifier: protocolIdentifier)
    }

    private static func parseUnsigned(_ obj: [String: Any], protocolIdentifier: String) throws -> DCAPIRequest {
        guard let nonce = obj["nonce"] as? String else {
            throw DCAPIRequestException("DC API request missing required 'nonce'")
        }
        return DCAPIRequest(
            clientId: obj["client_id"] as? String,
            responseMode: (obj["response_mode"] as? String) ?? "dc_api",
            nonce: nonce,
            dcqlQuery: obj["dcql_query"] as? [String: Any],
            clientMetadata: obj["client_metadata"] as? [String: Any],
            keyMaterial: nil,
            protocolIdentifier: protocolIdentifier,
            state: obj["state"] as? String
        )
    }

    private static func parseSigned(_ jwt: String, protocolIdentifier: String) throws -> DCAPIRequest {
        let parts = jwt.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3,
              let headerData = base64UrlDecode(parts[0]),
              let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any],
              let payloadData = base64UrlDecode(parts[1]),
              let payload = try? JSONSerialization.jsonObject(with: payloadData) as? [String: Any],
              let signature = base64UrlDecode(parts[2]) else {
            throw DCAPIRequestException("DC API signed request is not a valid JWS")
        }

        let x5cChain = header["x5c"] as? [String]
        let headerJwk = header["jwk"] as? [String: Any]
        let signingInput = Data((parts[0] + "." + parts[1]).utf8)

        try verifySignature(
            header: header,
            x5cChain: x5cChain,
            headerJwk: headerJwk,
            signature: signature,
            signingInput: signingInput
        )

        guard let nonce = payload["nonce"] as? String else {
            throw DCAPIRequestException("DC API signed request payload missing required 'nonce'")
        }

        return DCAPIRequest(
            clientId: payload["client_id"] as? String,
            responseMode: (payload["response_mode"] as? String) ?? "dc_api.jwt",
            nonce: nonce,
            dcqlQuery: payload["dcql_query"] as? [String: Any],
            clientMetadata: payload["client_metadata"] as? [String: Any],
            keyMaterial: DCAPIRequestKeyMaterial(x5c: x5cChain, jwk: headerJwk),
            protocolIdentifier: protocolIdentifier,
            state: payload["state"] as? String
        )
    }

    private static func verifySignature(
        header: [String: Any],
        x5cChain: [String]?,
        headerJwk: [String: Any]?,
        signature: Data,
        signingInput: Data
    ) throws {
        #if canImport(CryptoKit) && canImport(Security)
        let alg = header["alg"] as? String
        guard alg == nil || alg == "ES256" else {
            throw DCAPIRequestException("Unsupported DC API request signing algorithm: \(alg ?? "")")
        }

        let publicKeyBytes: Data
        if let x5cChain, let leaf = x5cChain.first {
            publicKeyBytes = try ecPublicKeyBytes(fromCertBase64: leaf)
        } else if let headerJwk {
            publicKeyBytes = try ecPublicKeyBytes(fromJwk: headerJwk)
        } else {
            throw DCAPIRequestException(
                "DC API signed request header has neither x5c nor jwk - cannot verify signature"
            )
        }

        guard let publicKey = try? P256.Signing.PublicKey(x963Representation: publicKeyBytes) else {
            throw DCAPIRequestException("Failed to parse DC API request's signing public key")
        }
        guard let ecdsaSignature = try? P256.Signing.ECDSASignature(rawRepresentation: signature),
              publicKey.isValidSignature(ecdsaSignature, for: signingInput) else {
            throw DCAPIRequestException("DC API signed request JWS signature verification failed")
        }
        #else
        throw DCAPIRequestException(
            "DC API signed request verification requires CryptoKit and Security (unsupported on this platform)"
        )
        #endif
    }

    #if canImport(Security)
    private static func ecPublicKeyBytes(fromCertBase64 base64: String) throws -> Data {
        guard let certData = standardBase64Decode(base64) else {
            throw DCAPIRequestException("Failed to parse DC API request's x5c leaf certificate")
        }
        guard let cert = SecCertificateCreateWithData(nil, certData as CFData) else {
            throw DCAPIRequestException("Failed to parse DC API request's x5c leaf certificate")
        }
        guard let secKey = SecCertificateCopyKey(cert) else {
            throw DCAPIRequestException("Failed to extract public key from DC API request's x5c leaf certificate")
        }
        var error: Unmanaged<CFError>?
        guard let rep = SecKeyCopyExternalRepresentation(secKey, &error) as Data? else {
            throw DCAPIRequestException("Failed to export DC API request's x5c public key")
        }
        return rep
    }
    #endif

    private static func ecPublicKeyBytes(fromJwk jwk: [String: Any]) throws -> Data {
        guard (jwk["kty"] as? String) == "EC",
              let xStr = jwk["x"] as? String,
              let yStr = jwk["y"] as? String,
              let x = base64UrlDecode(xStr),
              let y = base64UrlDecode(yStr) else {
            throw DCAPIRequestException("Unsupported DC API request signing JWK type")
        }
        return Data([0x04]) + x + y
    }

    // MARK: - Base64 helpers (deliberately self-contained rather than
    // depending on `SirosKeystore`'s internal `EncryptedContainer`
    // base64url helpers, which aren't visible across the module boundary).

    private static func base64UrlDecode(_ string: String) -> Data? {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 { base64 += "=" }
        return Data(base64Encoded: base64)
    }

    /// x5c entries (RFC 7515 §4.1.6) are plain base64 (not base64url) DER
    /// certificates - tolerate missing padding since not every JOSE producer
    /// includes it.
    private static func standardBase64Decode(_ string: String) -> Data? {
        var padded = string
        while padded.count % 4 != 0 { padded += "=" }
        return Data(base64Encoded: padded)
    }
}

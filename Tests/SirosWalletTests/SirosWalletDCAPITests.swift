// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosAuth
import SirosCredentials
import SirosKeystore
@testable import SirosWallet

// `handleDCAPIRequest`'s dc_api.jwt response encryption and the signed
// request JWS variant both need CryptoKit (P-256 ECDH/ECDSA), and the
// default `JweKeystore` this wallet falls back to is CryptoKit-only too -
// matching this test target's existing `#if canImport(CryptoKit)` convention
// (see e.g. `SirosWalletNotificationTests`).
#if canImport(CryptoKit)

import CryptoKit

/// Minimal `AuthProvider` stub - `handleDCAPIRequest` never invokes the
/// authenticator, so all methods simply throw.
private final class StubAuthProvider: AuthProvider, @unchecked Sendable {
    struct NotImplemented: Error {}
    func register(options: RegisterOptions) async throws -> RegisterResult { throw NotImplemented() }
    func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw NotImplemented() }
    func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw NotImplemented() }
}

/// A `KeystoreManager` test double - mirrors the Kotlin test suite's mockk
/// usage of `KeystoreManager`: `signVpToken`/`signMdocPresentationForDCAPI`
/// return canned values and record every call's arguments for assertion,
/// every other method either isn't reachable from `handleDCAPIRequest` or
/// (like `isUnlocked`) is deliberately `false` so `recordPresentation`'s
/// keystore-persistence branch is skipped, matching the Kotlin tests'
/// `every { keystore.isUnlocked } returns false` setup exactly.
private final class FakeKeystoreManager: KeystoreManager, @unchecked Sendable {
    struct NotImplemented: Error {}

    var isUnlocked: Bool = false

    var signVpTokenResult: String = "signed-vp-token"
    var signMdocResult: Data = Data("device-response".utf8)

    private(set) var signVpTokenCalls: [(credential: String, disclosedClaims: [String]?, nonce: String, audience: String, kid: String?)] = []
    private(set) var signMdocCalls: [(credentialBytes: Data, disclosedClaims: [String]?, nonce: String, origin: String, encryptionPublicJwkThumbprint: String?, kid: String?)] = []

    func unlock(prfOutput: Data, encryptedContainer: Data, hkdfSalt: Data, hkdfInfo: Data) async throws {}
    func lock() {}
    func generateKey(algorithm: String) async throws -> String { throw NotImplemented() }
    func sign(keyId: String, payload: Data, algorithm: String) async throws -> Data { throw NotImplemented() }
    func generateProof(audience: String, nonce: String, freshKey: Bool) async throws -> String { throw NotImplemented() }

    func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String {
        throw NotImplemented()
    }

    func signVpToken(
        credential: String,
        disclosedClaims: [String]?,
        nonce: String,
        audience: String,
        kid: String?
    ) async throws -> String {
        signVpTokenCalls.append((credential, disclosedClaims, nonce, audience, kid))
        return signVpTokenResult
    }

    func signMdocPresentationForDCAPI(
        credentialBytes: Data,
        disclosedClaims: [String]?,
        nonce: String,
        origin: String,
        encryptionPublicJwkThumbprint: String?,
        kid: String?
    ) async throws -> Data {
        signMdocCalls.append((credentialBytes, disclosedClaims, nonce, origin, encryptionPublicJwkThumbprint, kid))
        return signMdocResult
    }

    func exportEncryptedContainer() async throws -> Data { Data() }
    func listKeys() -> [KeyInfo] { [] }
    func saveCredential(id: Int64, json: String) async throws {}
    func getCredential(id: Int64) async throws -> String? { nil }
    func getAllCredentials() async throws -> [Int64: String] { [:] }
    func deleteCredential(id: Int64) async throws {}
    func clearCredentials() async throws {}
    func savePresentationRecord(id: Int64, json: String) async throws {}
    func getAllPresentationRecords() async throws -> [Int64: String] { [:] }
    func clearPresentationRecords() async throws {}
    func generateKeypairs(count: Int) async throws -> [KeypairInfo] { [] }
    func generateKeyProof(
        keyId: String,
        typ: String,
        issuer: String,
        audience: String,
        extraClaims: [String: String]
    ) async throws -> String {
        throw NotImplemented()
    }
}

/// Thread-safe capture box for the last HTTP request a fake `BackendApiClient`
/// made, so tests can assert on the AuthZEN `/v1/evaluate` request body
/// `handleDCAPIRequest`'s direct (non-engine) trust evaluation builds.
private final class RequestCapture: @unchecked Sendable {
    private let lock = NSLock()
    private var _lastBody: Data?
    var lastBody: Data? {
        get { lock.lock(); defer { lock.unlock() }; return _lastBody }
        set { lock.lock(); defer { lock.unlock() }; _lastBody = newValue }
    }
}

final class SirosWalletDCAPITests: XCTestCase {

    // MARK: - Test fixtures

    private func makeWallet(
        store: InMemoryCredentialStore,
        keystore: FakeKeystoreManager,
        capture: RequestCapture = RequestCapture()
    ) -> SirosWallet {
        let config = WalletConfig(backendUrl: "https://example.invalid", credentialStore: store)
        let wallet = SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: keystore)
        XCTAssertNotNil(wallet, "wallet should initialise with an injected keystore")
        let w = wallet!
        // `handleDCAPIRequest`'s trust evaluation posts to `/v1/evaluate` via
        // `BackendApiClient` - always answer "trusted" unless a test
        // overrides `capture` handling itself, matching the Kotlin suite's
        // blanket `coEvery { apiClient.evaluateTrust(any()) } returns
        // buildJsonObject { put("decision", true) }`.
        w.apiClient = BackendApiClient(baseUrl: "https://example.invalid", httpFn: { _, _, _, body in
            capture.lastBody = body
            let json: [String: Any] = ["decision": true]
            return try JSONSerialization.data(withJSONObject: json)
        })
        return w
    }

    /// Wraps a request's `data` object in the envelope
    /// `DCAPIRequestParser.parse` actually expects from the OS/browser -
    /// `{"requests": [{"protocol": ..., "data": {...}}]}`, not the bare
    /// `data` object on its own.
    private func wrapDCAPIRequest(protocolIdentifier: String, data: [String: Any]) -> String {
        let obj: [String: Any] = ["requests": [["protocol": protocolIdentifier, "data": data]]]
        let jsonData = try! JSONSerialization.data(withJSONObject: obj)
        return String(data: jsonData, encoding: .utf8)!
    }

    private func makeCredential(
        id: Int64,
        format: String,
        raw: String,
        name: String,
        vct: String? = nil,
        doctype: String? = nil
    ) -> StoredCredential {
        StoredCredential(
            id: id,
            format: format,
            raw: raw,
            metadata: CredentialMetadata(name: name, vct: vct, doctype: doctype),
            batchId: id,
            instanceId: 0
        )
    }

    // MARK: - Unsigned request, array-wrapped vp_token, state echo

    /// OpenID4VP 1.0 (#response_parameters): each `vp_token` entry MUST be a
    /// JSON array of Presentations, even for a single match - a real bug
    /// (see the matching Kotlin fix and `MdocDeviceResponseBuilder`'s
    /// handover-hash fix in this same session): Multipaz's own verifier
    /// server (`multipaz-verifier-server`) does `value.jsonArray.map{...}`
    /// and throws (surfacing as an opaque HTTP 500) given a bare string.
    /// Also covers `state` being echoed back unchanged when present -
    /// omitting it left the verifier with no way to correlate the DC API's
    /// separate response channel back to a session.
    func testHandleDCAPIRequestUnsignedRequestReturnsArrayWrappedVpTokenAndEchoesState() async throws {
        let store = InMemoryCredentialStore()
        await store.save(makeCredential(id: 1, format: "dc+sd-jwt", raw: "issuer.payload.sig~disclosure~", name: "Diploma", vct: "urn:example:vct"))
        let keystore = FakeKeystoreManager()
        let wallet = makeWallet(store: store, keystore: keystore)

        let requestJson = wrapDCAPIRequest(protocolIdentifier: "openid4vp-v1-unsigned", data: [
            "response_type": "vp_token",
            "nonce": "dc-nonce-1",
            "response_mode": "dc_api",
            "state": "verifier-session-state",
            "dcql_query": [
                "credentials": [
                    ["id": "query1", "format": "dc+sd-jwt"],
                ],
            ],
        ])

        let result = try await wallet.handleDCAPIRequest(rawRequestJson: requestJson, origin: "https://relying-party.example")

        XCTAssertEqual(keystore.signVpTokenCalls.count, 1)
        let call = try XCTUnwrap(keystore.signVpTokenCalls.first)
        XCTAssertEqual(call.credential, "issuer.payload.sig~disclosure~")
        XCTAssertEqual(call.nonce, "dc-nonce-1")
        XCTAssertEqual(call.audience, "origin:https://relying-party.example")

        XCTAssertEqual(result.credentialIds, [1])

        let parsed = try JSONSerialization.jsonObject(with: Data(result.responseJson.utf8)) as? [String: Any]
        XCTAssertEqual(parsed?["protocol"] as? String, "openid4vp-v1-unsigned")
        let data = parsed?["data"] as? [String: Any]
        let vpToken = data?["vp_token"] as? [String: Any]
        let query1Tokens = vpToken?["query1"] as? [String]
        XCTAssertEqual(query1Tokens, ["signed-vp-token"], "vp_token entry must be an array, even for a single match")
        XCTAssertEqual(data?["state"] as? String, "verifier-session-state")

        let history = wallet.presentationHistory
        XCTAssertEqual(history.count, 1)
        XCTAssertEqual(history.first?.credentialIds, [1])
    }

    // MARK: - mdoc credential signing path

    func testHandleDCAPIRequestMdocCredentialUsesSignMdocPresentationForDCAPI() async throws {
        let store = InMemoryCredentialStore()
        let rawMdoc = Data("fake-cbor".utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        await store.save(makeCredential(id: 1, format: "mso_mdoc", raw: rawMdoc, name: "mDL", doctype: "org.iso.18013.5.1.mDL"))
        let keystore = FakeKeystoreManager()
        let wallet = makeWallet(store: store, keystore: keystore)

        let requestJson = wrapDCAPIRequest(protocolIdentifier: "openid4vp-v1-unsigned", data: [
            "nonce": "dc-nonce-mdl",
            "response_mode": "dc_api",
        ])

        _ = try await wallet.handleDCAPIRequest(rawRequestJson: requestJson, origin: "https://relying-party.example")

        XCTAssertEqual(keystore.signMdocCalls.count, 1)
        let call = try XCTUnwrap(keystore.signMdocCalls.first)
        XCTAssertEqual(call.nonce, "dc-nonce-mdl")
        XCTAssertEqual(call.origin, "https://relying-party.example")
        XCTAssertNil(call.encryptionPublicJwkThumbprint, "plain dc_api mode must not pass an encryption thumbprint")
    }

    // MARK: - No matching credential

    func testHandleDCAPIRequestNoMatchingCredentialThrows() async {
        let store = InMemoryCredentialStore()
        let keystore = FakeKeystoreManager()
        let wallet = makeWallet(store: store, keystore: keystore)

        let requestJson = wrapDCAPIRequest(protocolIdentifier: "openid4vp-v1-unsigned", data: ["nonce": "n"])

        do {
            _ = try await wallet.handleDCAPIRequest(rawRequestJson: requestJson, origin: "https://relying-party.example")
            XCTFail("expected an error for no matching credential")
        } catch SirosError.wallet(let message, _) {
            XCTAssertTrue(message.contains("No credential"), "unexpected message: \(message)")
        } catch {
            XCTFail("expected SirosError.wallet, got \(error)")
        }
    }

    // MARK: - dc_api.jwt response encryption

    /// The JWE header must carry the verifier's own `kid` so it can find the
    /// matching ephemeral private key to decrypt with - a real bug in the
    /// Kotlin port this mirrors: omitting it broke verifier-side key lookup
    /// entirely ("kid not found in JWT header").
    func testHandleDCAPIRequestDcApiJwtResponseModeEncryptsResponse() async throws {
        let store = InMemoryCredentialStore()
        await store.save(makeCredential(id: 1, format: "dc+sd-jwt", raw: "raw", name: "X"))
        let keystore = FakeKeystoreManager()
        let wallet = makeWallet(store: store, keystore: keystore)

        let verifierPrivateKey = P256.KeyAgreement.PrivateKey()
        let verifierPublicX963 = verifierPrivateKey.publicKey.x963Representation
        let verifierJwk: [String: Any] = [
            "kty": "EC",
            "crv": "P-256",
            "x": base64UrlEncode(verifierPublicX963[1..<33]),
            "y": base64UrlEncode(verifierPublicX963[33..<65]),
            "kid": "enc-1",
            "use": "enc",
        ]

        let requestJson = wrapDCAPIRequest(protocolIdentifier: "openid4vp-v1-unsigned", data: [
            "nonce": "dc-nonce-2",
            "state": "verifier-session-state",
            "response_mode": "dc_api.jwt",
            "client_metadata": ["jwks": ["keys": [verifierJwk]]],
        ])

        let result = try await wallet.handleDCAPIRequest(rawRequestJson: requestJson, origin: "https://relying-party.example")

        let parsed = try JSONSerialization.jsonObject(with: Data(result.responseJson.utf8)) as? [String: Any]
        let data = parsed?["data"] as? [String: Any]
        let jwe = try XCTUnwrap(data?["response"] as? String, "response must be a JWE, not a plain vp_token")

        let segments = jwe.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        XCTAssertEqual(segments.count, 5, "compact JWE must have 5 dot-separated segments")
        XCTAssertEqual(segments[1], "", "ECDH-ES direct key agreement has no wrapped CEK segment")

        let header = try XCTUnwrap(decodeBase64UrlJsonObject(segments[0]))
        XCTAssertEqual(header["kid"] as? String, "enc-1")
        XCTAssertEqual(header["alg"] as? String, "ECDH-ES")

        let decrypted = try decryptTestJwe(compact: jwe, verifierPrivateKey: verifierPrivateKey)
        let decryptedObj = try XCTUnwrap(try JSONSerialization.jsonObject(with: decrypted) as? [String: Any])
        let vpToken = decryptedObj["vp_token"] as? [String: Any]
        XCTAssertEqual(vpToken?["_default"] as? [String], ["signed-vp-token"])
        XCTAssertEqual(decryptedObj["state"] as? String, "verifier-session-state")
    }

    // MARK: - Signed (JWS) request variant

    /// Trust evaluation must use the JAR's own `client_id` (from its verified
    /// payload), not the bare origin, since a signed request DOES assert an
    /// explicit `client_id`.
    func testHandleDCAPIRequestSignedRequestVerifiesJwsAndUsesPayloadFields() async throws {
        let store = InMemoryCredentialStore()
        await store.save(makeCredential(id: 1, format: "dc+sd-jwt", raw: "raw", name: "X"))
        let keystore = FakeKeystoreManager()
        let capture = RequestCapture()
        let wallet = makeWallet(store: store, keystore: keystore, capture: capture)

        let verifierSigningKey = P256.Signing.PrivateKey()
        let jwt = try signTestJwt(
            privateKey: verifierSigningKey,
            headerJwkPublicKey: verifierSigningKey.publicKey,
            claims: [
                "client_id": "https://relying-party.example",
                "nonce": "dc-nonce-signed",
                "response_mode": "dc_api",
            ]
        )

        let requestJson = wrapDCAPIRequest(protocolIdentifier: "openid4vp-v1-signed", data: ["request": jwt])

        _ = try await wallet.handleDCAPIRequest(rawRequestJson: requestJson, origin: "https://relying-party.example")

        XCTAssertEqual(keystore.signVpTokenCalls.count, 1)
        let call = try XCTUnwrap(keystore.signVpTokenCalls.first)
        XCTAssertEqual(call.nonce, "dc-nonce-signed")
        XCTAssertEqual(call.audience, "origin:https://relying-party.example")

        let capturedBody = try XCTUnwrap(capture.lastBody)
        let capturedJson = try XCTUnwrap(try JSONSerialization.jsonObject(with: capturedBody) as? [String: Any])
        let subject = capturedJson["subject"] as? [String: Any]
        XCTAssertEqual(subject?["id"] as? String, "https://relying-party.example")
    }

    /// Header advertises the legitimate key, but the JWT is actually signed
    /// by a different (attacker-controlled) key - signature verification
    /// against the advertised key must fail.
    func testHandleDCAPIRequestSignedRequestWithTamperedSignatureThrows() async throws {
        let store = InMemoryCredentialStore()
        let keystore = FakeKeystoreManager()
        let wallet = makeWallet(store: store, keystore: keystore)

        let legitKey = P256.Signing.PrivateKey()
        let attackerKey = P256.Signing.PrivateKey()
        let jwt = try signTestJwt(
            privateKey: attackerKey,
            headerJwkPublicKey: legitKey.publicKey,
            claims: ["nonce": "n"]
        )

        let requestJson = wrapDCAPIRequest(protocolIdentifier: "openid4vp-v1-signed", data: ["request": jwt])

        do {
            _ = try await wallet.handleDCAPIRequest(rawRequestJson: requestJson, origin: "https://relying-party.example")
            XCTFail("expected DCAPIRequestException for tampered signature")
        } catch is DCAPIRequestException {
            // expected
        } catch {
            XCTFail("expected DCAPIRequestException, got \(error)")
        }
    }

    // MARK: - Test-side JOSE helpers
    //
    // This SDK has no JOSE library dependency, so both building a signed
    // test JWT (standing in for a verifier's JAR request) and decrypting a
    // JWE this wallet produced (standing in for the verifier's own
    // decryption) are implemented directly here on CryptoKit, mirroring
    // `DCAPIRequestParser`/`DCAPIResponseEncryption`'s own from-scratch
    // implementations exactly (just run in reverse).

    private func base64UrlEncode(_ data: some ContiguousBytes) -> String {
        let d = data.withUnsafeBytes { Data($0) }
        return d.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func base64UrlDecode(_ string: String) -> Data {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 { base64 += "=" }
        return Data(base64Encoded: base64) ?? Data()
    }

    private func decodeBase64UrlJsonObject(_ base64url: String) -> [String: Any]? {
        try? JSONSerialization.jsonObject(with: base64UrlDecode(base64url)) as? [String: Any]
    }

    /// Build a compact JWS: header `{"alg":"ES256","jwk":<headerJwkPublicKey as JWK>}`, given claims as payload.
    private func signTestJwt(
        privateKey: P256.Signing.PrivateKey,
        headerJwkPublicKey: P256.Signing.PublicKey,
        claims: [String: Any]
    ) throws -> String {
        let x963 = headerJwkPublicKey.x963Representation
        let jwk: [String: Any] = [
            "kty": "EC",
            "crv": "P-256",
            "x": base64UrlEncode(x963[1..<33]),
            "y": base64UrlEncode(x963[33..<65]),
        ]
        let header: [String: Any] = ["alg": "ES256", "jwk": jwk]
        let headerB64 = base64UrlEncode(try JSONSerialization.data(withJSONObject: header))
        let payloadB64 = base64UrlEncode(try JSONSerialization.data(withJSONObject: claims))
        let signingInput = Data("\(headerB64).\(payloadB64)".utf8)
        let signature = try privateKey.signature(for: signingInput)
        let sigB64 = base64UrlEncode(signature.rawRepresentation)
        return "\(headerB64).\(payloadB64).\(sigB64)"
    }

    /// Decrypt a compact JWE produced by `DCAPIResponseEncryption.encryptResponse`
    /// (ECDH-ES + A1*GCM, RFC 7518 §4.6) - standing in for the verifier's own
    /// decryption, which this wallet never itself performs.
    private struct MalformedJwe: Error {}

    private func decryptTestJwe(compact: String, verifierPrivateKey: P256.KeyAgreement.PrivateKey) throws -> Data {
        let segments = compact.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard segments.count == 5 else { throw MalformedJwe() }
        let header = try XCTUnwrap(decodeBase64UrlJsonObject(segments[0]))
        let epk = try XCTUnwrap(header["epk"] as? [String: Any])
        let epkX = base64UrlDecode(try XCTUnwrap(epk["x"] as? String))
        let epkY = base64UrlDecode(try XCTUnwrap(epk["y"] as? String))
        let ephemeralPublicKey = try P256.KeyAgreement.PublicKey(x963Representation: Data([0x04]) + epkX + epkY)

        let enc = (header["enc"] as? String) ?? "A128GCM"
        let keyDataLenBits = enc == "A256GCM" ? 256 : (enc == "A192GCM" ? 192 : 128)

        let sharedSecret = try verifierPrivateKey.sharedSecretFromKeyAgreement(with: ephemeralPublicKey)
        let z = sharedSecret.withUnsafeBytes { Data($0) }
        let cek = SymmetricKey(data: concatKDF(z: z, algorithmId: enc, keyDataLenBits: keyDataLenBits))

        let iv = base64UrlDecode(segments[2])
        let ciphertext = base64UrlDecode(segments[3])
        let tag = base64UrlDecode(segments[4])
        let aad = Data(segments[0].utf8)

        let nonce = try AES.GCM.Nonce(data: iv)
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        return try AES.GCM.open(sealedBox, using: cek, authenticating: aad)
    }

    private func concatKDF(z: Data, algorithmId: String, keyDataLenBits: Int) -> Data {
        var otherInfo = Data()
        func appendLengthPrefixed(_ value: Data) {
            withUnsafeBytes(of: UInt32(value.count).bigEndian) { otherInfo.append(contentsOf: $0) }
            otherInfo.append(value)
        }
        appendLengthPrefixed(Data(algorithmId.utf8))
        appendLengthPrefixed(Data())
        appendLengthPrefixed(Data())
        withUnsafeBytes(of: UInt32(keyDataLenBits).bigEndian) { otherInfo.append(contentsOf: $0) }

        let keyDataLenBytes = keyDataLenBits / 8
        var output = Data()
        var counter: UInt32 = 1
        while output.count < keyDataLenBytes {
            var counterBytes = Data()
            withUnsafeBytes(of: counter.bigEndian) { counterBytes.append(contentsOf: $0) }
            output.append(contentsOf: SHA256.hash(data: counterBytes + z + otherInfo))
            counter += 1
        }
        return output.prefix(keyDataLenBytes)
    }
}

#endif

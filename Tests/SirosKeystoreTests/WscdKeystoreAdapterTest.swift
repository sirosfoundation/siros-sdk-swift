// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore

#if canImport(CryptoKit)
import CryptoKit
@preconcurrency import SwiftCBOR

/// A configurable `Signer` test double, mirroring the Kotlin test suite's
/// MockK-based `createMockSigner()`.
private final class MockSigner: Signer, @unchecked Sendable {
    var generatedKeyIds: [String] = []
    var securityPropertiesResult: Result<SignerSecurityProperties, Error> = .success(
        SignerSecurityProperties(keyStorage: ["hardware"], userAuthentication: ["pin"])
    )
    var exportPublicKeyOverride: Data?

    private var keyCounter = 0
    private let realKey = P256.Signing.PrivateKey()

    func generateKey(algorithm: String) async throws -> String {
        keyCounter += 1
        let keyId = "test-key-\(keyCounter)"
        generatedKeyIds.append(keyId)
        return keyId
    }

    func sign(keyId: String, data: Data) async throws -> Data {
        Data(repeating: 0, count: 64)
    }

    func listKeys() async throws -> [SignerKeyInfo] {
        [SignerKeyInfo(keyId: "test-key-1", algorithm: "ES256")]
    }

    func deleteKey(keyId: String) async throws {}

    func attestationChain(keyId: String) async throws -> AttestationChain? { nil }

    func exportPublicKey(keyId: String) async throws -> Data {
        if let override = exportPublicKeyOverride { return override }
        let jwk = JwtHelpers.publicKeyJwk(realKey)
        return try JSONSerialization.data(withJSONObject: jwk)
    }

    func migrateKey(keyId: String, targetPlugin: String) async throws -> MigrationResult {
        .migrated(newKeyId: keyId)
    }

    func securityProperties(keyId: String) async throws -> SignerSecurityProperties {
        switch securityPropertiesResult {
        case .success(let props): return props
        case .failure(let error): throw error
        }
    }
}

final class WscdKeystoreAdapterTest: XCTestCase {

    private func unlockedAdapter(_ signer: MockSigner = MockSigner()) async throws -> WscdKeystoreAdapter {
        let adapter = WscdKeystoreAdapter(signer: signer)
        try await adapter.unlock(prfOutput: Data(), encryptedContainer: Data(), hkdfSalt: Data(), hkdfInfo: Data())
        return adapter
    }

    func testInitiallyLocked() {
        let adapter = WscdKeystoreAdapter(signer: MockSigner())
        XCTAssertFalse(adapter.isUnlocked)
    }

    func testUnlockSetsState() async throws {
        let adapter = try await unlockedAdapter()
        XCTAssertTrue(adapter.isUnlocked)
    }

    func testLockClearsState() async throws {
        let adapter = try await unlockedAdapter()
        adapter.lock()
        XCTAssertFalse(adapter.isUnlocked)
    }

    // MARK: - generateKeyAttestation

    /// Raw WSCD vocabulary ("hardware"/"pin") must be translated to the
    /// OID4VCI spec's registered iso_18045_* values, not passed through -
    /// confirmed via a real conformance-test issuer that an unrecognized enum
    /// value here gets rejected.
    func testGenerateKeyAttestationBuildsValidJwtWithAttestedKeysAndSecurityProperties() async throws {
        let signer = MockSigner()
        let adapter = try await unlockedAdapter(signer)

        let jwt = try await adapter.generateKeyAttestation(nonce: "test-nonce-123", count: 3)

        let parts = jwt.split(separator: ".")
        XCTAssertEqual(parts.count, 3)

        let header = JwtHelpers.parseJwtHeader(jwt)
        XCTAssertEqual(header?["typ"] as? String, "key-attestation+jwt")
        XCTAssertEqual(header?["alg"] as? String, "ES256")
        XCTAssertNotNil(header?["jwk"])

        let claims = JwtHelpers.parseJwtPayload(jwt)
        XCTAssertEqual(claims?["nonce"] as? String, "test-nonce-123")
        let attestedKeys = claims?["attested_keys"] as? [[String: Any]]
        XCTAssertEqual(attestedKeys?.count, 3)
        XCTAssertEqual(claims?["key_storage"] as? [String], ["iso_18045_moderate"])
        XCTAssertEqual(claims?["user_authentication"] as? [String], ["iso_18045_basic"])

        // 3 keys generated for the batch, matching count - not reusing a
        // single pre-existing key.
        XCTAssertEqual(signer.generatedKeyIds.count, 3)
    }

    /// The exact real-world case that caused a conformance-test issuer to
    /// reject the attestation: the "softkey" WSCD plugin reports raw
    /// key_storage=["software"], which isn't a registered iso_18045_* value
    /// on its own.
    func testGenerateKeyAttestationMapsSoftwareKeyStorageToIso18045Basic() async throws {
        let signer = MockSigner()
        signer.securityPropertiesResult = .success(
            SignerSecurityProperties(keyStorage: ["software"], userAuthentication: [])
        )
        let adapter = try await unlockedAdapter(signer)

        let jwt = try await adapter.generateKeyAttestation(nonce: "n", count: 1)
        let claims = JwtHelpers.parseJwtPayload(jwt)
        XCTAssertEqual(claims?["key_storage"] as? [String], ["iso_18045_basic"])
    }

    func testGenerateKeyAttestationDefaultsKeyStorageWhenSecurityPropertiesUnavailable() async throws {
        let signer = MockSigner()
        signer.securityPropertiesResult = .failure(KeystoreError.invalidParameter("not supported"))
        let adapter = try await unlockedAdapter(signer)

        let jwt = try await adapter.generateKeyAttestation(nonce: "n", count: 1)
        let claims = JwtHelpers.parseJwtPayload(jwt)
        XCTAssertEqual(claims?["key_storage"] as? [String], ["iso_18045_basic"])
        XCTAssertNil(claims?["user_authentication"])
    }

    // MARK: - generateKeyProof

    func testGenerateKeyProofBuildsValidPopJwt() async throws {
        let signer = MockSigner()
        let adapter = try await unlockedAdapter(signer)

        let jwt = try await adapter.generateKeyProof(
            keyId: "test-key-1",
            typ: "oauth-client-attestation-pop+jwt",
            issuer: "siros-sample://callback",
            audience: "https://wallet-backend.example.com",
            extraClaims: ["nonce": "challenge-abc"]
        )

        let header = JwtHelpers.parseJwtHeader(jwt)
        XCTAssertEqual(header?["typ"] as? String, "oauth-client-attestation-pop+jwt")
        XCTAssertEqual(header?["alg"] as? String, "ES256")
        XCTAssertNotNil(header?["jwk"])

        let claims = JwtHelpers.parseJwtPayload(jwt)
        XCTAssertEqual(claims?["aud"] as? String, "https://wallet-backend.example.com")
        XCTAssertEqual(claims?["nonce"] as? String, "challenge-abc")
        XCTAssertEqual(claims?["iss"] as? String, "siros-sample://callback")
        XCTAssertNotNil(claims?["iat"])
        XCTAssertNotNil(claims?["exp"])
        XCTAssertNotNil(claims?["jti"])
    }

    func testGenerateKeyProofOmitsExtraClaimsWhenNoneGiven() async throws {
        let signer = MockSigner()
        let adapter = try await unlockedAdapter(signer)

        let jwt = try await adapter.generateKeyProof(
            keyId: "test-key-1",
            typ: "oauth-client-attestation-pop+jwt",
            issuer: "siros-sample://callback",
            audience: "https://issuer.example.com",
            extraClaims: [:]
        )

        let claims = JwtHelpers.parseJwtPayload(jwt)
        XCTAssertNil(claims?["nonce"])
    }

    func testGenerateKeyProofThrowsForUnknownKeyId() async throws {
        let adapter = try await unlockedAdapter()

        do {
            _ = try await adapter.generateKeyProof(keyId: "does-not-exist", typ: "x", issuer: "iss", audience: "aud", extraClaims: [:])
            XCTFail("expected keyNotFound")
        } catch KeystoreError.keyNotFound {
            // expected
        }
    }

    // MARK: - signMdocPresentationForDCAPI

    private func buildTaggedItem(digestId: UInt64, elementIdentifier: String, elementValue: String) -> CBOR {
        let item: CBOR = .map([
            .utf8String("digestID"): .unsignedInt(digestId),
            .utf8String("random"): .byteString([UInt8](repeating: 0, count: 16)),
            .utf8String("elementIdentifier"): .utf8String(elementIdentifier),
            .utf8String("elementValue"): .utf8String(elementValue),
        ])
        return .tagged(.encodedCBORDataItem, .byteString(item.encode()))
    }

    /// Build a synthetic mdoc credential's raw bytes: a DeviceResponse-shaped
    /// envelope, matching `MdocCbor.parseStoredCredential`'s expected shape
    /// (mirrors `CredentialUtilsTests.buildMdocRaw`).
    private func buildIssuerSignedEnvelope() -> Data {
        let items: CBOR = .array([
            buildTaggedItem(digestId: 0, elementIdentifier: "family_name", elementValue: "Doe"),
        ])
        let nameSpaces: CBOR = .map([.utf8String("org.iso.18013.5.1"): items])
        let issuerAuth: CBOR = .array(Array(repeating: .byteString([]), count: 4))
        let issuerSigned: CBOR = .map([
            .utf8String("nameSpaces"): nameSpaces,
            .utf8String("issuerAuth"): issuerAuth,
        ])
        let document: CBOR = .map([
            .utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL"),
            .utf8String("issuerSigned"): issuerSigned,
        ])
        let envelope: CBOR = .map([
            .utf8String("documents"): .array([document]),
            .utf8String("status"): .unsignedInt(0),
        ])
        return Data(envelope.encode())
    }

    func testSignMdocPresentationForDCAPIProducesDeviceResponse() async throws {
        let adapter = try await unlockedAdapter()

        let responseBytes = try await adapter.signMdocPresentationForDCAPI(
            credentialBytes: buildIssuerSignedEnvelope(),
            disclosedClaims: nil,
            nonce: "test-nonce",
            origin: "https://verifier.example.com",
            encryptionPublicJwkThumbprint: nil,
            kid: nil
        )

        let decoded = try CBOR.decode([UInt8](responseBytes))
        guard case .map(let root)? = decoded else {
            return XCTFail("expected a top-level CBOR map")
        }
        XCTAssertEqual(root[.utf8String("version")], .utf8String("1.0"))
        guard case .array(let documents)? = root[.utf8String("documents")], documents.count == 1,
              case .map(let doc) = documents[0] else {
            return XCTFail("expected a single document in the DeviceResponse")
        }
        guard case .map(let deviceSigned)? = doc[.utf8String("deviceSigned")],
              case .map(let deviceAuth)? = deviceSigned[.utf8String("deviceAuth")],
              deviceAuth[.utf8String("deviceSignature")] != nil else {
            return XCTFail("expected deviceSigned.deviceAuth.deviceSignature to be present")
        }
    }
}

#else
// On non-Apple platforms, CryptoKit is unavailable
// so we just have a placeholder test
final class WscdKeystoreAdapterTest: XCTestCase {
    func testCryptoKitUnavailable() {
        XCTAssertTrue(true)
    }
}
#endif

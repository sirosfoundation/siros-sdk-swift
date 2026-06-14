// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore

#if canImport(CryptoKit)
import CryptoKit

final class JweKeystoreTests: XCTestCase {

    private let fakePrfOutput = Data(0..<32)
    private let hkdfSalt = Data((0..<32).map { UInt8($0 + 0x10) })
    private let hkdfInfo = Data("SIROS Wallet PRF".utf8)

    // MARK: - Unlock/Lock

    func testUnlockWithEmptyContainerCreatesFreshKeystore() async throws {
        let keystore = JweKeystore()
        XCTAssertFalse(keystore.isUnlocked)

        try await keystore.unlock(prfOutput: fakePrfOutput, encryptedContainer: Data(), hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)
        XCTAssertTrue(keystore.isUnlocked)
        XCTAssertEqual(keystore.listKeys().count, 0)
    }

    func testLockClearsKeys() async throws {
        let keystore = JweKeystore()
        try await keystore.unlock(prfOutput: fakePrfOutput, encryptedContainer: Data(), hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)
        let _ = try await keystore.generateKey()
        XCTAssertEqual(keystore.listKeys().count, 1)

        keystore.lock()
        XCTAssertFalse(keystore.isUnlocked)
    }

    // MARK: - Key generation

    func testGenerateKeyAndListKeys() async throws {
        let keystore = JweKeystore()
        try await keystore.unlock(prfOutput: fakePrfOutput, encryptedContainer: Data(), hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)

        let keyId = try await keystore.generateKey()
        XCTAssertFalse(keyId.isEmpty)

        let keys = keystore.listKeys()
        XCTAssertEqual(keys.count, 1)
        XCTAssertEqual(keys[0].keyId, keyId)
    }

    // MARK: - Export and reimport

    func testExportAndReimportContainer() async throws {
        let keystore = JweKeystore()
        try await keystore.unlock(prfOutput: fakePrfOutput, encryptedContainer: Data(), hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)

        let keyId = try await keystore.generateKey()
        let exported = try await keystore.exportEncryptedContainer()
        XCTAssertFalse(exported.isEmpty)

        keystore.lock()
        XCTAssertFalse(keystore.isUnlocked)

        try await keystore.unlock(prfOutput: fakePrfOutput, encryptedContainer: exported, hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)
        XCTAssertTrue(keystore.isUnlocked)
        XCTAssertEqual(keystore.listKeys().count, 1)
        XCTAssertEqual(keystore.listKeys()[0].keyId, keyId)
    }

    // MARK: - Signing

    func testSignProducesOutput() async throws {
        let keystore = JweKeystore()
        try await keystore.unlock(prfOutput: fakePrfOutput, encryptedContainer: Data(), hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)
        let keyId = try await keystore.generateKey()

        let signed = try await keystore.sign(keyId: keyId, payload: Data("test payload".utf8))
        XCTAssertFalse(signed.isEmpty)
    }

    func testGenerateProofProducesJwt() async throws {
        let keystore = JweKeystore()
        try await keystore.unlock(prfOutput: fakePrfOutput, encryptedContainer: Data(), hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)
        let _ = try await keystore.generateKey()

        let proof = try await keystore.generateProof(audience: "https://issuer.example.com", nonce: "test-nonce-123")
        XCTAssertTrue(proof.contains("."))
        XCTAssertEqual(proof.split(separator: ".").count, 3)

        // Verify header contains typ: openid4vci-proof+jwt
        let header = JwtHelpers.parseJwtHeader(proof)
        XCTAssertEqual(header?["typ"] as? String, "openid4vci-proof+jwt")
        XCTAssertNotNil(header?["jwk"])

        // Verify payload contains audience and nonce
        let payload = JwtHelpers.parseJwtPayload(proof)
        XCTAssertEqual(payload?["aud"] as? String, "https://issuer.example.com")
        XCTAssertEqual(payload?["nonce"] as? String, "test-nonce-123")
    }

    func testSignPresentationProducesJwt() async throws {
        let keystore = JweKeystore()
        try await keystore.unlock(prfOutput: fakePrfOutput, encryptedContainer: Data(), hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)
        let _ = try await keystore.generateKey()

        let vp = try await keystore.signPresentation(
            nonce: "nonce-123",
            audience: "https://verifier.example.com",
            credentialIds: ["cred-1"]
        )
        XCTAssertTrue(vp.contains("."))
        XCTAssertEqual(vp.split(separator: ".").count, 3)
    }

    // MARK: - Locked operations throw

    func testLockedKeystoreOperationsThrow() async {
        let keystore = JweKeystore()

        do {
            let _ = try await keystore.generateKey()
            XCTFail("Expected KeystoreError.locked")
        } catch is KeystoreError {
            // expected
        } catch {
            XCTFail("Wrong error type: \(error)")
        }

        do {
            let _ = try await keystore.generateProof(audience: "https://issuer.example.com", nonce: "nonce")
            XCTFail("Expected KeystoreError.locked")
        } catch is KeystoreError {
            // expected
        } catch {
            XCTFail("Wrong error type: \(error)")
        }
    }

    // MARK: - Wrong PRF output fails

    func testDifferentPrfOutputFailsDecrypt() async throws {
        let keystore1 = JweKeystore()
        try await keystore1.unlock(prfOutput: fakePrfOutput, encryptedContainer: Data(), hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)
        let _ = try await keystore1.generateKey()
        let exported = try await keystore1.exportEncryptedContainer()

        let differentPrf = Data((0..<32).map { UInt8($0 + 0x80) })
        let keystore2 = JweKeystore()
        do {
            try await keystore2.unlock(prfOutput: differentPrf, encryptedContainer: exported, hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)
            XCTFail("Should have thrown on wrong key")
        } catch {
            // Expected: decryption fails with wrong key
        }
    }

    // MARK: - signVpToken

    func testSignVpTokenAssemblesSdJwtWithKbJwt() async throws {
        let keystore = JweKeystore()
        try await keystore.unlock(prfOutput: fakePrfOutput, encryptedContainer: Data(), hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)
        let _ = try await keystore.generateKey()

        let issuerJwt = "eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0IjoxfQ.c2ln"
        let d1 = EncryptedContainer.base64UrlEncode(Data("[\"salt1\",\"given_name\",\"Alice\"]".utf8))
        let d2 = EncryptedContainer.base64UrlEncode(Data("[\"salt2\",\"family_name\",\"Smith\"]".utf8))
        let credential = "\(issuerJwt)~\(d1)~\(d2)~"

        let vpToken = try await keystore.signVpToken(
            credential: credential,
            disclosedClaims: nil,
            nonce: "verifier-nonce",
            audience: "https://verifier.example.com"
        )

        let parts = vpToken.split(separator: "~", omittingEmptySubsequences: false).map(String.init)
        // Format: IssuerJWT~d1~d2~KB-JWT
        XCTAssertEqual(parts[0], issuerJwt)
        XCTAssertEqual(parts[1], d1)
        XCTAssertEqual(parts[2], d2)

        let kbJwt = parts[3]
        XCTAssertEqual(kbJwt.split(separator: ".").count, 3)

        // Verify KB-JWT header
        let header = JwtHelpers.parseJwtHeader(kbJwt)
        XCTAssertEqual(header?["typ"] as? String, "kb+jwt")
        XCTAssertNotNil(header?["jwk"])
        // jwk must not contain private key "d"
        if let jwk = header?["jwk"] as? [String: Any] {
            XCTAssertNil(jwk["d"])
        }

        // Verify KB-JWT payload
        let payload = JwtHelpers.parseJwtPayload(kbJwt)
        XCTAssertNotNil(payload?["sd_hash"])
        XCTAssertEqual(payload?["nonce"] as? String, "verifier-nonce")
        XCTAssertEqual(payload?["aud"] as? String, "https://verifier.example.com")
    }

    func testSignVpTokenSelectiveDisclosure() async throws {
        let keystore = JweKeystore()
        try await keystore.unlock(prfOutput: fakePrfOutput, encryptedContainer: Data(), hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)
        let _ = try await keystore.generateKey()

        let issuerJwt = "eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0IjoxfQ.c2ln"
        let d1 = EncryptedContainer.base64UrlEncode(Data("[\"salt1\",\"given_name\",\"Alice\"]".utf8))
        let d2 = EncryptedContainer.base64UrlEncode(Data("[\"salt2\",\"family_name\",\"Smith\"]".utf8))
        let d3 = EncryptedContainer.base64UrlEncode(Data("[\"salt3\",\"birth_date\",\"2000-01-01\"]".utf8))
        let credential = "\(issuerJwt)~\(d1)~\(d2)~\(d3)~"

        let vpToken = try await keystore.signVpToken(
            credential: credential,
            disclosedClaims: ["given_name"],
            nonce: "n1",
            audience: "aud"
        )

        let parts = vpToken.split(separator: "~", omittingEmptySubsequences: false).map(String.init)
        // Should have: issuerJwt, disclosure for given_name, KB-JWT
        XCTAssertEqual(parts.count, 3)
        XCTAssertEqual(parts[0], issuerJwt)
        XCTAssertEqual(parts[1], d1)
        XCTAssertEqual(parts[2].split(separator: ".").count, 3) // KB-JWT
    }

    func testSignVpTokenSdHashComputedCorrectly() async throws {
        let keystore = JweKeystore()
        try await keystore.unlock(prfOutput: fakePrfOutput, encryptedContainer: Data(), hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)
        let _ = try await keystore.generateKey()

        let issuerJwt = "eyJhbGciOiJFUzI1NiJ9.eyJ0ZXN0IjoxfQ.c2ln"
        let credential = "\(issuerJwt)~"

        let vpToken = try await keystore.signVpToken(
            credential: credential,
            disclosedClaims: nil,
            nonce: "n",
            audience: "a"
        )

        let kbJwt = vpToken.split(separator: "~", omittingEmptySubsequences: false).map(String.init).last!
        let payload = JwtHelpers.parseJwtPayload(kbJwt)

        // Compute expected sd_hash
        let sdJwtPresentation = "\(issuerJwt)~"
        let expectedHash = EncryptedContainer.base64UrlEncode(
            Data(SHA256.hash(data: Data(sdJwtPresentation.utf8)))
        )
        XCTAssertEqual(payload?["sd_hash"] as? String, expectedHash)
    }

    func testSignVpTokenLockedKeystoreThrows() async {
        let keystore = JweKeystore()
        do {
            let _ = try await keystore.signVpToken(credential: "cred", disclosedClaims: nil, nonce: "n", audience: "a")
            XCTFail("Expected KeystoreError")
        } catch is KeystoreError {
            // expected
        } catch {
            XCTFail("Wrong error type: \(error)")
        }
    }

    // MARK: - Credential storage

    func testCredentialStorage() async throws {
        let keystore = JweKeystore()
        try await keystore.unlock(prfOutput: fakePrfOutput, encryptedContainer: Data(), hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)

        try await keystore.saveCredential(id: "c1", json: "{\"test\":true}")
        let retrieved = try await keystore.getCredential(id: "c1")
        XCTAssertEqual(retrieved, "{\"test\":true}")

        let all = try await keystore.getAllCredentials()
        XCTAssertEqual(all.count, 1)

        try await keystore.deleteCredential(id: "c1")
        let afterDelete = try await keystore.getCredential(id: "c1")
        XCTAssertNil(afterDelete)
    }

    func testClearCredentials() async throws {
        let keystore = JweKeystore()
        try await keystore.unlock(prfOutput: fakePrfOutput, encryptedContainer: Data(), hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)

        try await keystore.saveCredential(id: "c1", json: "a")
        try await keystore.saveCredential(id: "c2", json: "b")
        let allCreds = try await keystore.getAllCredentials()
        XCTAssertEqual(allCreds.count, 2)

        try await keystore.clearCredentials()
        let clearedCreds = try await keystore.getAllCredentials()
        XCTAssertEqual(clearedCreds.count, 0)
    }

    func testCredentialStorageLockedThrows() async {
        let keystore = JweKeystore()
        do {
            try await keystore.saveCredential(id: "c1", json: "test")
            XCTFail("Expected error")
        } catch is KeystoreError {
            // expected
        } catch {
            XCTFail("Wrong error type")
        }
    }

    // MARK: - Credential persistence through export/import

    func testCredentialsPersistThroughExportImport() async throws {
        let keystore = JweKeystore()
        try await keystore.unlock(prfOutput: fakePrfOutput, encryptedContainer: Data(), hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)

        try await keystore.saveCredential(id: "cred-1", json: "{\"type\":\"test\"}")
        let _ = try await keystore.generateKey()
        let exported = try await keystore.exportEncryptedContainer()

        keystore.lock()
        try await keystore.unlock(prfOutput: fakePrfOutput, encryptedContainer: exported, hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)

        let cred = try await keystore.getCredential(id: "cred-1")
        XCTAssertEqual(cred, "{\"type\":\"test\"}")
        XCTAssertEqual(keystore.listKeys().count, 1)
    }
}

#else
// On non-Apple platforms, CryptoKit is unavailable
// so we just have a placeholder test
final class JweKeystoreTests: XCTestCase {
    func testCryptoKitUnavailable() {
        let keystore = JweKeystore()
        XCTAssertFalse(keystore.isUnlocked)
    }
}
#endif

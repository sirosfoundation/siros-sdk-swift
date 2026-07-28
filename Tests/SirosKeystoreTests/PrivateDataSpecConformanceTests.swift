// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore

#if canImport(CryptoKit)
import CryptoKit

/// Conformance tests driven by privatedata-spec's shared cross-client test
/// vectors (`test-vectors/vectors.jsonl`, bundled here as a test resource -
/// see `loadVectors()`). These vectors are the normative fixtures shared with
/// wallet-frontend and siros-sdk-kotlin (privatedata-spec/test-vectors/README.md).
///
/// KNOWN LIMITATION: the vectors currently checked into privatedata-spec do
/// NOT include an `expected` block (containerJsonBytes/containerHash/jweCompact),
/// even though the README's documented schema has one. That means the
/// README's normative requirements #1-3 (encryption determinism, decrypting
/// the golden container, byte-identical round-trip against a golden
/// container) aren't checkable from this file alone - there's no golden
/// ciphertext to decrypt or compare against. What IS checkable, and what
/// these tests check, is requirements #4-6: metadata preservation, event
/// preservation, and field completeness - by hand-building a container
/// carrying each vector's `plaintextState` (using this SDK's own
/// `EncryptedContainer` primitives) and confirming this SDK decrypts it back
/// losslessly, including across a save-a-new-credential-and-re-export cycle.
///
/// `keypairs[]` is intentionally excluded from round-trip comparisons: the
/// vectors' keypair entries are flat metadata stubs ({id, did, algorithm})
/// with no actual EC private key JWK material, unlike the real nested
/// {kid, keypair: {kid, did, alg, publicKey, privateKey}} shape JweKeystore
/// (and wallet-frontend) actually produce, so they can't be loaded into a
/// signable key or reproduced on export. This is a limitation of the vector
/// fixture, not of the SDK.
final class PrivateDataSpecConformanceTests: XCTestCase {

    private func loadVectors() throws -> [[String: Any]] {
        guard let url = Bundle.module.url(forResource: "vectors", withExtension: "jsonl", subdirectory: "privatedata-spec") else {
            throw XCTSkip("privatedata-spec/vectors.jsonl not found in test bundle resources")
        }
        let text = try String(contentsOf: url, encoding: .utf8)
        return try text.split(separator: "\n").compactMap { line -> [String: Any]? in
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { return nil }
            guard let data = trimmed.data(using: .utf8) else { return nil }
            return try JSONSerialization.jsonObject(with: data) as? [String: Any]
        }
    }

    private func vector(_ id: String) throws -> [String: Any] {
        let all = try loadVectors()
        guard let v = all.first(where: { ($0["id"] as? String) == id }) else {
            XCTFail("vector \(id) not found")
            throw KeystoreError.invalidContainer("vector not found")
        }
        return v
    }

    /// Vector binary fields are documented as base64url (test-vectors/README.md),
    /// but the multi-passkey vector's `credentialIds` are literal human-readable
    /// strings instead - decode as base64url where possible, else fall back to
    /// raw UTF-8 bytes. Either way the bytes only need to be distinct per entry;
    /// JweKeystore selects PRF entries by hkdfSalt, not credentialId, so this
    /// ambiguity doesn't affect what's tested.
    private func decodeVectorBytes(_ value: String) -> Data {
        let decoded = EncryptedContainer.base64UrlDecode(value)
        if !decoded.isEmpty || value.isEmpty {
            return decoded
        }
        return Data(value.utf8)
    }

    /// Encrypt `plaintextState` as a JWE using `mainKey`, matching
    /// JweKeystore's private `encryptJwe` (A256GCMKW / A256GCM compact form).
    private func encryptJwe(_ plaintextState: [String: Any], mainKey: SymmetricKey) throws -> String {
        let plaintext = try JSONSerialization.data(withJSONObject: plaintextState)

        var cekBytes = Data(count: 32)
        cekBytes.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        let cek = SymmetricKey(data: cekBytes)

        let kwNonce = AES.GCM.Nonce()
        let kwSealed = try AES.GCM.seal(cekBytes, using: mainKey, nonce: kwNonce)

        let headerObj: [String: Any] = [
            "alg": "A256GCMKW",
            "enc": "A256GCM",
            "iv": EncryptedContainer.base64UrlEncode(Data(kwNonce)),
            "tag": EncryptedContainer.base64UrlEncode(kwSealed.tag),
        ]
        let headerData = try JSONSerialization.data(withJSONObject: headerObj)
        let headerB64 = EncryptedContainer.base64UrlEncode(headerData)

        let contentNonce = AES.GCM.Nonce()
        let aad = Data(headerB64.utf8)
        let sealed = try AES.GCM.seal(plaintext, using: cek, nonce: contentNonce, authenticating: aad)

        let parts = [
            headerB64,
            EncryptedContainer.base64UrlEncode(kwSealed.ciphertext),
            EncryptedContainer.base64UrlEncode(Data(contentNonce)),
            EncryptedContainer.base64UrlEncode(sealed.ciphertext),
            EncryptedContainer.base64UrlEncode(sealed.tag),
        ]
        return parts.joined(separator: ".")
    }

    /// Mirror of JweKeystore's private `decryptJwe`, used to independently
    /// verify exported containers without going through JweKeystore itself.
    private func decryptJwe(_ jweString: String, mainKey: SymmetricKey) throws -> [String: Any] {
        let parts = jweString.split(separator: ".").map(String.init)
        guard parts.count == 5 else { throw KeystoreError.invalidContainer("JWE must have 5 parts") }

        let headerData = EncryptedContainer.base64UrlDecode(parts[0])
        let encryptedKeyData = EncryptedContainer.base64UrlDecode(parts[1])
        let ivData = EncryptedContainer.base64UrlDecode(parts[2])
        let ciphertextData = EncryptedContainer.base64UrlDecode(parts[3])
        let tagData = EncryptedContainer.base64UrlDecode(parts[4])

        guard let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any],
              let headerIv = header["iv"] as? String,
              let headerTag = header["tag"] as? String else {
            throw KeystoreError.invalidContainer("Invalid JWE header")
        }
        let kwNonce = try AES.GCM.Nonce(data: EncryptedContainer.base64UrlDecode(headerIv))
        let kwTag = EncryptedContainer.base64UrlDecode(headerTag)
        let kwSealedBox = try AES.GCM.SealedBox(nonce: kwNonce, ciphertext: encryptedKeyData, tag: kwTag)
        let cekData = try AES.GCM.open(kwSealedBox, using: mainKey)
        let cek = SymmetricKey(data: cekData)

        let contentNonce = try AES.GCM.Nonce(data: ivData)
        let aadData = Data(parts[0].utf8)
        let contentSealedBox = try AES.GCM.SealedBox(nonce: contentNonce, ciphertext: ciphertextData, tag: tagData)
        let plaintext = try AES.GCM.open(contentSealedBox, using: cek, authenticating: aadData)

        guard let json = try JSONSerialization.jsonObject(with: plaintext) as? [String: Any] else {
            throw KeystoreError.invalidContainer("JWE payload is not valid JSON object")
        }
        return json
    }

    private struct PrfEntryInput {
        let credentialId: Data
        let prfOutput: Data
        let hkdfSalt: Data
    }

    /// Hand-build a container carrying `plaintextState`, with one prfKeys[]
    /// entry per `entries`, all wrapping the SAME mainKey - matching the
    /// wallet-frontend's multi-passkey container shape (one wallet, several
    /// registered authenticators, each independently able to unlock it).
    private func buildContainer(entries: [PrfEntryInput], hkdfInfo: Data, plaintextState: [String: Any]) throws -> Data {
        let (mainKey, mainKeyInfo) = EncryptedContainer.generateMainKey()
        var prfKeys: [PrfKeyInfo] = []
        for entry in entries {
            let prfKey = EncryptedContainer.derivePrfKey(prfOutput: entry.prfOutput, hkdfSalt: entry.hkdfSalt, hkdfInfo: hkdfInfo)
            let encapsulation = try EncryptedContainer.wrapMainKey(prfKey: prfKey, mainKey: mainKey, mainKeyInfo: mainKeyInfo)
            prfKeys.append(PrfKeyInfo(
                credentialId: entry.credentialId,
                transports: nil,
                prfSalt: Data(count: 32),
                hkdfSalt: entry.hkdfSalt,
                hkdfInfo: hkdfInfo,
                algorithm: AesGcmKeyAlgorithm(name: "AES-GCM", length: 256),
                keypair: encapsulation.keypair,
                unwrapKey: encapsulation.unwrapKey
            ))
        }
        let jwe = try encryptJwe(plaintextState, mainKey: mainKey)
        let container = ContainerData(jwe: jwe, mainKey: mainKeyInfo, prfKeys: prfKeys)
        return try EncryptedContainer.serialize(container)
    }

    /// Independently decrypt an exported container without going through
    /// JweKeystore, using known PRF material.
    private func independentlyDecrypt(_ containerBytes: Data, prfOutput: Data, hkdfSalt: Data, hkdfInfo: Data) throws -> [String: Any] {
        let container = try EncryptedContainer.parse(containerBytes)
        guard let mainKeyInfo = container.mainKey,
              let prfKeyInfo = container.prfKeys.first(where: { $0.hkdfSalt == hkdfSalt }) else {
            throw KeystoreError.invalidContainer("missing mainKey/prfKeyInfo")
        }
        let prfKey = EncryptedContainer.derivePrfKey(prfOutput: prfOutput, hkdfSalt: prfKeyInfo.hkdfSalt, hkdfInfo: prfKeyInfo.hkdfInfo)
        let mainKey = try EncryptedContainer.unwrapMainKey(prfKey: prfKey, prfKeyInfo: prfKeyInfo, mainKeyInfo: mainKeyInfo)
        return try decryptJwe(container.jwe, mainKey: mainKey)
    }

    // MARK: - single-credential-v3-001

    func testSingleCredentialVectorDecryptFidelityAndRoundTrip() async throws {
        let v = try vector("single-credential-v3-001")
        let inputs = v["inputs"] as! [String: Any]
        let credentialId = decodeVectorBytes(inputs["credentialId"] as! String)
        let prfOutput = decodeVectorBytes(inputs["prfOutput"] as! String)
        let hkdfSalt = decodeVectorBytes(inputs["hkdfSalt"] as! String)
        let hkdfInfo = Data((inputs["hkdfInfo"] as! String).utf8)
        let plaintextState = inputs["plaintextState"] as! [String: Any]

        let containerBytes = try buildContainer(
            entries: [PrfEntryInput(credentialId: credentialId, prfOutput: prfOutput, hkdfSalt: hkdfSalt)],
            hkdfInfo: hkdfInfo,
            plaintextState: plaintextState
        )

        let keystore = JweKeystore()
        try await keystore.unlock(prfOutput: prfOutput, encryptedContainer: containerBytes, hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)
        XCTAssertTrue(keystore.isUnlocked)

        // metadata: the credential's raw payload survives decrypt via the
        // credential store. NOTE: unlike Kotlin's JweKeystore, Swift's
        // getCredential() currently returns ONLY the S.credentials[].data
        // raw string (not a reconstructed JSON blob with format/kid/issuer/
        // configId as separate keys) - that's a known, separate parity gap,
        // not something this test papers over. The full per-field
        // preservation (format/kid/credentialIssuerIdentifier/
        // credentialConfigurationId) is verified below via the independently
        // decrypted container's S.credentials[] entries, which IS what
        // buildWalletStateV3()/loadFromWalletStateV3() operate on.
        let credentialsArray = (plaintextState["S"] as! [String: Any])["credentials"] as! [[String: Any]]
        let expectedCred = credentialsArray[0]
        let restoredCredData = try await keystore.getCredential(id: "cred-001")
        XCTAssertEqual(expectedCred["data"] as? String, restoredCredData, "expected credential cred-001's raw data to survive decrypt")

        // roundTrip: export -> independently decrypt -> compare (excluding keypairs, see class doc).
        let exported = try await keystore.exportEncryptedContainer()
        let redecrypted = try independentlyDecrypt(exported, prfOutput: prfOutput, hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)

        XCTAssertEqual(plaintextState["lastEventHash"] as? String, redecrypted["lastEventHash"] as? String)
        XCTAssertTrue(jsonEqual(plaintextState["events"], redecrypted["events"]))
        let expectedS = plaintextState["S"] as! [String: Any]
        let actualS = redecrypted["S"] as! [String: Any]
        XCTAssertTrue(jsonEqual(expectedS["credentials"], actualS["credentials"]))
        XCTAssertTrue(jsonEqual(expectedS["presentations"], actualS["presentations"]))
        XCTAssertTrue(jsonEqual(expectedS["settings"], actualS["settings"]))
        XCTAssertTrue(jsonEqual(expectedS["credentialIssuanceSessions"], actualS["credentialIssuanceSessions"]))
    }

    func testSingleCredentialVectorAddingCredentialAfterUnlockPreservesOriginalStateAndAddsNew() async throws {
        // Regression test for a real bug found while writing this suite:
        // buildWalletStateV3() used to return preservedWalletState verbatim
        // whenever it was non-nil (i.e. whenever unlock() loaded an EXISTING
        // container), completely ignoring anything saved via saveCredential()/
        // generateKey() during that session - meaning a second credential
        // added by a returning user would silently vanish on export, and
        // lastEventHash/events were reset to empty in the fallback path.
        let v = try vector("single-credential-v3-001")
        let inputs = v["inputs"] as! [String: Any]
        let credentialId = decodeVectorBytes(inputs["credentialId"] as! String)
        let prfOutput = decodeVectorBytes(inputs["prfOutput"] as! String)
        let hkdfSalt = decodeVectorBytes(inputs["hkdfSalt"] as! String)
        let hkdfInfo = Data((inputs["hkdfInfo"] as! String).utf8)
        let plaintextState = inputs["plaintextState"] as! [String: Any]

        let containerBytes = try buildContainer(
            entries: [PrfEntryInput(credentialId: credentialId, prfOutput: prfOutput, hkdfSalt: hkdfSalt)],
            hkdfInfo: hkdfInfo,
            plaintextState: plaintextState
        )

        let keystore = JweKeystore()
        try await keystore.unlock(prfOutput: prfOutput, encryptedContainer: containerBytes, hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)

        let newCredentialJson = "{\"id\":\"cred-999\",\"format\":\"vc+sd-jwt\",\"raw\":\"header.payload.sig\"}"
        try await keystore.saveCredential(id: "cred-999", json: newCredentialJson)

        let exported = try await keystore.exportEncryptedContainer()
        let redecrypted = try independentlyDecrypt(exported, prfOutput: prfOutput, hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)

        XCTAssertEqual(plaintextState["lastEventHash"] as? String, redecrypted["lastEventHash"] as? String)
        XCTAssertTrue(jsonEqual(plaintextState["events"], redecrypted["events"]))

        let redecryptedCreds = (redecrypted["S"] as! [String: Any])["credentials"] as! [[String: Any]]
        let credIds = redecryptedCreds.compactMap { $0["credentialId"] as? String }
        XCTAssertTrue(credIds.contains("cred-001"), "original credential cred-001 must survive")
        XCTAssertTrue(credIds.contains("cred-999"), "newly added credential cred-999 must be present")

        let newCredEntry = redecryptedCreds.first { $0["credentialId"] as? String == "cred-999" }!
        XCTAssertEqual(newCredEntry["data"] as? String, newCredentialJson)

        let expectedS = plaintextState["S"] as! [String: Any]
        let actualS = redecrypted["S"] as! [String: Any]
        XCTAssertTrue(jsonEqual(expectedS["presentations"], actualS["presentations"]))
        XCTAssertTrue(jsonEqual(expectedS["settings"], actualS["settings"]))
        XCTAssertTrue(jsonEqual(expectedS["credentialIssuanceSessions"], actualS["credentialIssuanceSessions"]))
    }

    // MARK: - multi-passkey-v3-001

    func testMultiPasskeyVectorAnyRegisteredPasskeyUnlocksTheSameSharedState() async throws {
        let v = try vector("multi-passkey-v3-001")
        let inputs = v["inputs"] as! [String: Any]
        let credentialIds = inputs["credentialIds"] as! [String]
        let prfOutputs = inputs["prfOutputs"] as! [String]
        let hkdfSalts = inputs["hkdfSalts"] as! [String]
        let hkdfInfo = Data((inputs["hkdfInfo"] as! String).utf8)
        let plaintextState = inputs["plaintextState"] as! [String: Any]

        XCTAssertEqual(3, credentialIds.count)
        XCTAssertEqual(credentialIds.count, prfOutputs.count)
        XCTAssertEqual(credentialIds.count, hkdfSalts.count)

        let entries = (0..<credentialIds.count).map { i in
            PrfEntryInput(
                credentialId: decodeVectorBytes(credentialIds[i]),
                prfOutput: decodeVectorBytes(prfOutputs[i]),
                hkdfSalt: decodeVectorBytes(hkdfSalts[i])
            )
        }
        let containerBytes = try buildContainer(entries: entries, hkdfInfo: hkdfInfo, plaintextState: plaintextState)

        // prfSelection: unlocking with ANY of the 3 passkeys' own PRF material
        // must resolve to the SAME shared wallet state (all 3 wrap one mainKey).
        for entry in entries {
            let keystore = JweKeystore()
            try await keystore.unlock(prfOutput: entry.prfOutput, encryptedContainer: containerBytes, hkdfSalt: entry.hkdfSalt, hkdfInfo: hkdfInfo)
            XCTAssertTrue(keystore.isUnlocked)

            let creds = try await keystore.getAllCredentials()
            XCTAssertEqual(3, creds.count)
            for id in ["cred-001", "cred-002", "cred-003"] {
                XCTAssertNotNil(creds[id], "credential \(id) must be visible via this passkey")
            }
        }
    }

    func testMultiPasskeyVectorWrongPrfOutputForAGivenHkdfSaltFailsToUnlock() async throws {
        let v = try vector("multi-passkey-v3-001")
        let inputs = v["inputs"] as! [String: Any]
        let credentialIds = inputs["credentialIds"] as! [String]
        let prfOutputs = inputs["prfOutputs"] as! [String]
        let hkdfSalts = inputs["hkdfSalts"] as! [String]
        let hkdfInfo = Data((inputs["hkdfInfo"] as! String).utf8)
        let plaintextState = inputs["plaintextState"] as! [String: Any]

        let entries = (0..<credentialIds.count).map { i in
            PrfEntryInput(
                credentialId: decodeVectorBytes(credentialIds[i]),
                prfOutput: decodeVectorBytes(prfOutputs[i]),
                hkdfSalt: decodeVectorBytes(hkdfSalts[i])
            )
        }
        let containerBytes = try buildContainer(entries: entries, hkdfInfo: hkdfInfo, plaintextState: plaintextState)

        // Use passkey #0's hkdfSalt but passkey #1's prfOutput - must fail,
        // not silently unlock into someone else's key material.
        let keystore = JweKeystore()
        do {
            try await keystore.unlock(prfOutput: entries[1].prfOutput, encryptedContainer: containerBytes, hkdfSalt: entries[0].hkdfSalt, hkdfInfo: hkdfInfo)
            XCTFail("Expected unlock to fail with mismatched prfOutput/hkdfSalt pairing")
        } catch {
            // expected
        }
    }

    // MARK: - Helpers

    /// Recursive structural equality for heterogeneous JSON trees produced by
    /// `JSONSerialization` ([String: Any], [Any], NSNumber, NSString, NSNull).
    private func jsonEqual(_ a: Any?, _ b: Any?) -> Bool {
        switch (a, b) {
        case (nil, nil):
            return true
        case (.some(let a), .some(let b)):
            if let a = a as? [String: Any], let b = b as? [String: Any] {
                guard Set(a.keys) == Set(b.keys) else { return false }
                return a.allSatisfy { key, value in jsonEqual(value, b[key]) }
            }
            if let a = a as? [Any], let b = b as? [Any] {
                guard a.count == b.count else { return false }
                return zip(a, b).allSatisfy { jsonEqual($0, $1) }
            }
            if let a = a as? NSNumber, let b = b as? NSNumber { return a == b }
            if let a = a as? String, let b = b as? String { return a == b }
            if a is NSNull && b is NSNull { return true }
            return false
        default:
            return false
        }
    }
}

#else
final class PrivateDataSpecConformanceTests: XCTestCase {
    func testCryptoKitUnavailable() {
        // No-op placeholder: CryptoKit is unavailable on this platform.
    }
}
#endif

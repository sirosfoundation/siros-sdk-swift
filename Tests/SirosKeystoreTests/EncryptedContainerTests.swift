// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore

final class EncryptedContainerTests: XCTestCase {

    func testSerializeAndParseRoundTrip() throws {
        let publicKeyData = Data(repeating: 0x04, count: 65)
        let container = ContainerData(
            jwe: "test.jwe.value.here.sig",
            mainKey: MainKeyInfo(
                publicKey: EncapsulationPublicKeyInfo(
                    importKey: ImportKeyInfo(
                        format: "raw",
                        keyData: publicKeyData,
                        algorithm: EcKeyAlgorithm(name: "ECDH", namedCurve: "P-256")
                    )
                ),
                unwrapKey: MainUnwrapKeyInfo(
                    format: "raw",
                    unwrapAlgo: "AES-KW",
                    unwrappedKeyAlgo: AesGcmKeyAlgorithm(name: "AES-GCM", length: 256)
                )
            ),
            prfKeys: []
        )

        let serialized = try EncryptedContainer.serialize(container)
        let parsed = try EncryptedContainer.parse(serialized)

        XCTAssertEqual(parsed.jwe, "test.jwe.value.here.sig")
        XCTAssertNotNil(parsed.mainKey)
        XCTAssertEqual(parsed.mainKey?.unwrapKey.unwrapAlgo, "AES-KW")
        XCTAssertTrue(parsed.prfKeys.isEmpty)
    }

    func testParseInvalidJsonThrows() {
        let badData = Data("not json".utf8)
        XCTAssertThrowsError(try EncryptedContainer.parse(badData))
    }

    func testParseMissingJweThrows() {
        let json = "{\"mainKey\": null}"
        let data = Data(json.utf8)
        XCTAssertThrowsError(try EncryptedContainer.parse(data))
    }

    func testBinaryFieldDecodingBase64Url() throws {
        // Test with tagged binary field format
        let json = "{\"jwe\": \"test\", \"prfKeys\": [{\"credentialId\": {\"$b64u\": \"AQID\"}, \"prfSalt\": {\"$b64u\": \"AQID\"}, \"hkdfSalt\": {\"$b64u\": \"AQID\"}, \"hkdfInfo\": {\"$b64u\": \"AQID\"}, \"keypair\": {\"publicKey\": {\"importKey\": {\"format\": \"raw\", \"keyData\": {\"$b64u\": \"AQID\"}, \"algorithm\": {\"name\": \"ECDH\", \"namedCurve\": \"P-256\"}}}, \"privateKey\": {\"unwrapKey\": {\"format\": \"jwk\", \"wrappedKey\": {\"$b64u\": \"AQID\"}, \"unwrapAlgo\": {\"name\": \"AES-GCM\", \"iv\": {\"$b64u\": \"AQID\"}}, \"unwrappedKeyAlgo\": {\"name\": \"ECDH\", \"namedCurve\": \"P-256\"}}}}, \"unwrapKey\": {\"wrappedKey\": {\"$b64u\": \"AQID\"}, \"unwrappingKey\": {\"deriveKey\": {\"algorithm\": {\"name\": \"ECDH\"}, \"derivedKeyAlgorithm\": {\"name\": \"AES-KW\", \"length\": 256}}}}}]}"
        let data = Data(json.utf8)
        let container = try EncryptedContainer.parse(data)

        XCTAssertEqual(container.prfKeys.count, 1)
        XCTAssertEqual(container.prfKeys[0].credentialId, Data([1, 2, 3]))
    }
}

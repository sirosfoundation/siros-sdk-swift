// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import SirosCredentials

final class TokenStatusListTests: XCTestCase {

    // MARK: - bit packing
    //
    // The draft's own packing: entries are packed least-significant-bits
    // first within each byte.

    func testOneBitEntriesAreReadLeastSignificantBitFirst() {
        // 0b1010_0101 -> indices 0..7 = 1,0,1,0,0,1,0,1
        let list = Data([0xA5])
        let read = (0...7).map { TokenStatusList.readStatus(in: list, bits: 1, idx: $0) }
        XCTAssertEqual(read, [1, 0, 1, 0, 0, 1, 0, 1])
    }

    func testTwoBitEntriesPackFourToAByte() {
        // 0b11_10_01_00 -> indices 0..3 = 0,1,2,3
        let list = Data([0xE4])
        XCTAssertEqual((0...3).map { TokenStatusList.readStatus(in: list, bits: 2, idx: $0) }, [0, 1, 2, 3])
    }

    func testFourBitEntriesPackTwoToAByte() {
        // 0b1100_0011 -> index 0 = 3, index 1 = 12
        let list = Data([0xC3])
        XCTAssertEqual(TokenStatusList.readStatus(in: list, bits: 4, idx: 0), 3)
        XCTAssertEqual(TokenStatusList.readStatus(in: list, bits: 4, idx: 1), 12)
    }

    func testEightBitEntriesAreOnePerByte() {
        let list = Data([0x00, 0x01, 0x02, 0xFF])
        XCTAssertEqual((0...3).map { TokenStatusList.readStatus(in: list, bits: 8, idx: $0) }, [0, 1, 2, 255])
    }

    func testAnIndexPastTheEndReadsAsUnknownNotAsValid() {
        // Reporting 0 (VALID) for an out-of-range index would silently treat a
        // revoked credential as good.
        XCTAssertNil(TokenStatusList.readStatus(in: Data([0x00]), bits: 1, idx: 8))
        XCTAssertNil(TokenStatusList.readStatus(in: Data([0x00]), bits: 8, idx: 1))
        XCTAssertNil(TokenStatusList.readStatus(in: Data([0x00]), bits: 1, idx: -1))
    }

    func testAnIllegalEntryWidthIsReportedAsSuchNotAsAMissingIndex() async {
        // "Index 1 is outside the status list" would send whoever is debugging
        // the issuer looking in entirely the wrong place.
        let key = P256.Signing.PrivateKey()
        let token = Self.statusListToken(bits: 3, signedBy: key)
        let client = TokenStatusListClient(
            httpGet: { _, _ in Data(token.utf8) },
            resolveIssuerKey: { _, _ in Self.publicJwk(of: key) }
        )
        let resolution = await client.resolve(
            TokenStatusList.Reference(idx: 1, uri: "https://x.example")
        )
        guard case .unavailable(let reason) = resolution else {
            return XCTFail("expected an unavailable status, got \(resolution)")
        }
        XCTAssertTrue(reason.contains("entry width of 3 bits"), reason)
    }

    /// A properly signed Status List Token declaring `bits` as its entry width.
    ///
    /// Really signed, because the reader verifies the signature before it
    /// looks at the list - an unsigned shell never reaches the width check.
    private static func statusListToken(bits: Int, signedBy key: P256.Signing.PrivateKey) -> String {
        func b64(_ object: [String: Any]) -> String {
            EncryptedContainerBase64.urlEncode(
                // swiftlint:disable:next force_try
                try! JSONSerialization.data(withJSONObject: object, options: .sortedKeys)
            )
        }
        let header = b64(["alg": "ES256", "typ": "statuslist+jwt"])
        let payload = b64([
            "iss": "https://issuer.example",
            "status_list": ["bits": bits, "lst": "eJw="],
        ])
        let signingInput = "\(header).\(payload)"
        // swiftlint:disable:next force_try
        let signature = try! key.signature(for: Data(signingInput.utf8))
        return "\(signingInput).\(EncryptedContainerBase64.urlEncode(signature.rawRepresentation))"
    }

    private static func publicJwk(of key: P256.Signing.PrivateKey) -> [String: String] {
        let x963 = key.publicKey.x963Representation
        return [
            "kty": "EC",
            "crv": "P-256",
            "x": EncryptedContainerBase64.urlEncode(Data(x963[1..<33])),
            "y": EncryptedContainerBase64.urlEncode(Data(x963[33..<65])),
        ]
    }

    func testAnEntryWidthTheDraftDoesNotDefineIsRefused() {
        XCTAssertNil(TokenStatusList.readStatus(in: Data([0x00]), bits: 3, idx: 0))
        XCTAssertNil(TokenStatusList.readStatus(in: Data([0x00]), bits: 0, idx: 0))
    }

    func testAnIndexInALaterByteIsFound() {
        var list = Data(repeating: 0, count: 4)
        list[2] = 0x04 // 0b0000_0100 -> bit 2 of byte 2 -> index 18
        XCTAssertEqual(TokenStatusList.readStatus(in: list, bits: 1, idx: 18), 1)
        XCTAssertEqual(TokenStatusList.readStatus(in: list, bits: 1, idx: 17), 0)
    }

    // MARK: - the credential's reference

    func testAStatusListReferenceIsReadFromACredentialsClaims() {
        let reference = TokenStatusList.extractReference(from: claims(
            #"{"status":{"status_list":{"idx":42,"uri":"https://issuer.example/statuslists/1"}}}"#
        ))
        XCTAssertEqual(reference?.idx, 42)
        XCTAssertEqual(reference?.uri, "https://issuer.example/statuslists/1")
    }

    func testACredentialWithoutAStatusReferenceHasNone() {
        XCTAssertNil(TokenStatusList.extractReference(from: claims(#"{"iss":"https://issuer.example"}"#)))
        XCTAssertNil(TokenStatusList.extractReference(from: claims(#"{"status":{}}"#)))
        // A reference missing either half is not a reference.
        XCTAssertNil(TokenStatusList.extractReference(from: claims(#"{"status":{"status_list":{"idx":1}}}"#)))
        XCTAssertNil(TokenStatusList.extractReference(
            from: claims(#"{"status":{"status_list":{"uri":"https://x.example"}}}"#)
        ))
    }

    // MARK: - decompression

    func testAZlibWrappedListInflates() {
        // A zlib stream produced elsewhere, holding the eight bytes 0..7.
        let compressed = Data(base64Encoded: "eJxjYGRiZmFlYwcAAFwAHQ==")
        XCTAssertNotNil(compressed)
        XCTAssertEqual(TokenStatusList.inflate(compressed!), Data([0, 1, 2, 3, 4, 5, 6, 7]))
    }

    func testAStoredUncompressedDeflateBlockInflates() {
        // A raw DEFLATE stream with a single stored (type 0) block, which is
        // the one shape that can be written by hand: final bit set, type 0,
        // then LEN/NLEN and the literal bytes.
        var raw = Data([0x01, 0x03, 0x00, 0xFC, 0xFF])
        raw.append(contentsOf: [0xAA, 0xBB, 0xCC])
        XCTAssertEqual(TokenStatusList.inflate(raw), Data([0xAA, 0xBB, 0xCC]))
    }

    func testARealCompressedListInflatesByteForByte() {
        // Exercises the paths a hand-written stored block does not: dynamic
        // Huffman tables and LZ77 back-references, including the overlapping
        // copies a long run of one byte compresses to.
        let base64 = "eNpj5hKUkFfTNbF28gwIj0vNKa5q7OifNnfJ6k07Dxw/d/XO41cff7BwC0kqqOuZ2jh7BUbEp+WWVDd1Tpg+b+mazbsOnjh/7e6T159+svIISylq6JvZungHRSak55XWNHdNnDF/2dotuw+dvHD93tM3n3+x8YpIK2kamNu5+gRHJWbkl9W2dE+auWD5uq17Dp+6eOP+s7dfGNj5RGWUtQwt7N18Q6KTMgvK61p7Js9auGL9tr1HTl+6+eD5u6+MHPxisiraRpYO7n6hMclZhRX1bb1TZi9auWH7vqNnLt96+OL9NyZOAXE5VR1jK0cP/7DYlOyiyob2vqlzFq/auGP/sbNXbj96+eE7M6leZx4Nq9GwGg2r0bAaDathF1aOo2DEAQBUmdZk"
        let compressed = Data(base64Encoded: base64)
        XCTAssertNotNil(compressed)

        let expected = Data(
            (0..<300).map { UInt8(($0 * 7 + 3) % 251) }.repeated(6) + [UInt8](repeating: 0x41, count: 500)
        )
        XCTAssertEqual(TokenStatusList.inflate(compressed!), expected)
    }

    func testDataThatIsNotCompressedAtAllIsReportedAsUndecompressable() {
        XCTAssertNil(TokenStatusList.inflate(Data([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])))
    }

    private func claims(_ json: String) -> [String: Any] {
        (try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any]) ?? [:]
    }
}

private extension Array {
    func repeated(_ times: Int) -> [Element] {
        var result: [Element] = []
        for _ in 0..<times { result.append(contentsOf: self) }
        return result
    }
}

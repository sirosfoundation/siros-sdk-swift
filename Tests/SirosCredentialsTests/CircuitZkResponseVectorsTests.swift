// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@preconcurrency import SwiftCBOR
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import SirosCredentials

/// The shared `circuit_zk` response conformance vectors (siros-dc-matcher at 932b07a, verbatim, see
/// Resources/circuit-zk-response-vectors.PROVENANCE.txt) against this SDK's validator, plus the x5chain builder.
final class CircuitZkResponseVectorsTests: XCTestCase {
    private static let manifestHash = "fcd9a92dc80e96e7c35515f67e5ac29d4fdde9d13bb18abd03ca8846fcc3eaf7"

    private func sha256(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }

    /// The vector files (`ok_*`, `err_*`) and their README, in byte order of name. The test bundle's resources are
    /// flattened, so the files are picked by name.
    private func vectorFiles() throws -> [URL] {
        let dir = try XCTUnwrap(Bundle.module.resourceURL)
        return try FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasPrefix("ok_") || $0.lastPathComponent.hasPrefix("err_") || $0.lastPathComponent == "README.md" }
            .sorted { $0.lastPathComponent.utf8.lexicographicallyPrecedes($1.lastPathComponent.utf8) }
    }

    func testTheVectorsAreTheVerbatimUpstreamFiles() throws {
        let manifest = try vectorFiles().map { "\(sha256(try Data(contentsOf: $0)))  \($0.lastPathComponent)\n" }.joined()
        XCTAssertEqual(sha256(Data(manifest.utf8)), Self.manifestHash, "re-copy from siros-dc-matcher and update PROVENANCE")
    }

    private func expectation(_ vector: [String: Any]) throws -> CircuitZkResponseExpectation {
        let query = try XCTUnwrap(vector["query"] as? [String: Any])
        let metadata = (((vector["client_metadata"] as? [String: Any])?["vp_formats_supported"] as? [String: Any])?["circuit_zk"]) as? [String: Any]
        let items = (query["req"] as? [[String: Any]] ?? []).map {
            CircuitZkResponseExpectation.Item(handle: $0["return"] as? String ?? "", functionId: $0["id"] as? String ?? "")
        }
        return CircuitZkResponseExpectation(
            queryId: query["id"] as? String ?? "", multiple: query["multiple"] as? Bool == true,
            circuitIds: metadata?["circuit_id_values"] as? [String], proofSystems: metadata?["circuit_proof_system_values"] as? [String],
            items: items)
    }

    private func token(_ vector: [String: Any]) throws -> String {
        if let text = vector["vp_token_text"] as? String { return text }
        let data = try JSONSerialization.data(withJSONObject: try XCTUnwrap(vector["vp_token"]), options: [.fragmentsAllowed])
        return String(decoding: data, as: UTF8.self)
    }

    func testEveryVector() throws {
        var ok = 0, err = 0
        var codes = Set<String>()
        for file in try vectorFiles() where file.pathExtension == "json" {
            let name = file.lastPathComponent
            let vector = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any], name)
            let expect = try XCTUnwrap(vector["expect"] as? [String: Any], name)
            do {
                try CircuitZkResponseValidator.validate(try expectation(vector), vpToken: try token(vector))
                XCTAssertEqual(expect["valid"] as? Bool, true, "\(name): accepted but expected \(expect)")
                ok += 1
            } catch let error as CircuitZkResponseError {
                XCTAssertEqual(error.code, expect["error"] as? String, name)
                codes.insert(error.code)
                err += 1
            }
        }
        XCTAssertEqual(ok, 8)
        XCTAssertGreaterThanOrEqual(err, 70)
        // Every reason code the vectors name is produced.
        XCTAssertGreaterThanOrEqual(codes.count, 30, "\(codes.sorted())")
    }

    // MARK: x5chain builder

    private func issuerAuth(unprotected: [CBOR: CBOR]) -> CBOR {
        .array([.byteString([0xA1, 0x01, 0x26]), .map(unprotected), .byteString([1, 2]), .byteString([UInt8](repeating: 9, count: 64))])
    }

    func testTheChainIsLeafFirstPaddedStandardBase64() throws {
        let leaf = [UInt8](repeating: 0xFB, count: 10), ca = [UInt8](repeating: 0xFF, count: 11)
        let chain = try XCTUnwrap(CircuitZkX5Chain.encoded(issuerAuth: issuerAuth(unprotected: [.unsignedInt(33): .array([.byteString(leaf), .byteString(ca)])])))
        XCTAssertEqual(chain, [Data(leaf).base64EncodedString(), Data(ca).base64EncodedString()])
        XCTAssertTrue(chain[0].contains("=") || chain[1].contains("="), "padded")
        XCTAssertTrue(chain.joined().contains("+") || chain.joined().contains("/"), "standard alphabet, not base64url")
        // A single certificate may be a bare byte string.
        XCTAssertEqual(CircuitZkX5Chain.encoded(issuerAuth: issuerAuth(unprotected: [.unsignedInt(33): .byteString(leaf)])), [Data(leaf).base64EncodedString()])
    }

    func testAnUnusableChainIsNeverBuilt() {
        func chain(_ value: CBOR?) -> [String]? {
            CircuitZkX5Chain.encoded(issuerAuth: issuerAuth(unprotected: value.map { [.unsignedInt(33): $0] } ?? [:]))
        }
        XCTAssertNil(chain(nil))
        XCTAssertNil(chain(.array([])))
        XCTAssertNil(chain(.byteString([])))
        XCTAssertNil(chain(.array([.byteString([1]), .utf8String("x")])))
        XCTAssertNil(chain(.utf8String("x")))
        XCTAssertNil(chain(.array((0..<9).map { _ in .byteString([1]) })), "more than 8")
        XCTAssertNotNil(chain(.array((0..<8).map { _ in .byteString([1]) })))
        XCTAssertNil(chain(.byteString([UInt8](repeating: 1, count: 4097))), "over 4096 bytes")
        XCTAssertNotNil(chain(.byteString([UInt8](repeating: 1, count: 4096))))
        XCTAssertNil(CircuitZkX5Chain.encoded(issuerAuth: .array([])))
    }

    func testABuiltChainPassesTheValidator() throws {
        let chain = try XCTUnwrap(CircuitZkX5Chain.encoded(issuerAuth: issuerAuth(unprotected: [.unsignedInt(33): .array([.byteString([UInt8](repeating: 0xFB, count: 4096)), .byteString([0xFF])])])))
        let json = chain.map { "\"\($0)\"" }.joined(separator: ",")
        let token = #"{"q":[{"circuit_id":"c","proof_system":"p","proof":"AQID","x5chain":[\#(json)],"results":{"h":{"satisfied":true}}}]}"#
        let expectation = CircuitZkResponseExpectation(
            queryId: "q", multiple: false, circuitIds: ["c"], proofSystems: ["p"], items: [.init(handle: "h", functionId: "age_check")])
        XCTAssertNoThrow(try CircuitZkResponseValidator.validate(expectation, vpToken: token))
    }
}

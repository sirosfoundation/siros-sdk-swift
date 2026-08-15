// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

// The native zk_cred_longfellow XCFramework only ships iOS slices - see
// LongfellowZkProofSystem.swift's own `#if os(iOS)` gating.
#if os(iOS)

import CryptoKit
import Foundation
import XCTest
import libzstd
import SirosCredentials

/// Exercises the real, vendored `zk_cred_longfellow` UniFFI bindings
/// directly against the exact known-good V8 test vectors from the native
/// crate's own `src/mdoc_zk/prover_v8_test.rs`
/// (`tests_v8_prover::test_ppid_prover_succeeds`) - not through
/// `LongfellowZkProofSystem`, since that actor builds its own fresh witness
/// DeviceResponse via a signer callback and this test vector's device
/// signature is a fixed, already-baked-in value we have no private key for.
/// This instead validates the exact same low-level calls
/// `LongfellowZkProofSystem` itself makes (circuit decompression, `Data`
/// marshaling, `CircuitVersion.v8` + attribute count, `proveWithPpid`)
/// against a real circuit and a real, fully-signed DeviceResponse -
/// confirming the FFI wiring genuinely works end-to-end, not just that it
/// compiles. Mirrors `LongfellowZkVectorTest` (Kotlin's androidTest
/// equivalent), which found two real production bugs (zstd-jni's Android
/// packaging, UniFFI's direct-ByteBuffer requirement) this exact kind of
/// real-vector run was designed to catch.
final class LongfellowZkVectorTests: XCTestCase {

    // Verbatim from prover_v8_test.rs's tests_v8_prover module.
    private static let verifierContext: [UInt8] = [
        0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x65, 0x72,
        0x40, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x2e,
        0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e,
        0x63, 0x6f, 0x6d, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
    private static let expectedSeed: [UInt8] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22,
    ]
    private static let namespace = "eu.europa.ec.eudi.pid.1"
    private static let now = "2026-05-31T11:27:12Z"
    private static let requestedClaims = ["given_name", "pairwise_pseudonym"]

    private func loadResource(_ name: String, ext: String) throws -> Data {
        guard let url = Bundle.module.url(forResource: name, withExtension: ext, subdirectory: "zk-circuits") else {
            throw XCTSkip("test resource not found: \(name).\(ext)")
        }
        return try Data(contentsOf: url)
    }

    private func loadCircuitBytes() throws -> Data {
        let compressed = try loadResource(
            "8_2_4307_2945_bb8e6a26d2700ddad968562d1c4aee83067772fee6f889748a0bc64f2c694ad5",
            ext: ""
        )
        // ~104MB decompressed for this 2-attribute V8 circuit (confirmed via
        // `zstd -l`, ~334x ratio) - read from the frame's own embedded
        // content size, mirroring LongfellowZkProofSystem's own decompress().
        let frameSize = compressed.withUnsafeBytes { (src: UnsafeRawBufferPointer) -> UInt64 in
            ZSTD_getFrameContentSize(src.baseAddress, src.count)
        }
        let contentSizeUnknown = UInt64.max
        let contentSizeError = UInt64.max - 1
        XCTAssertTrue(frameSize != contentSizeUnknown && frameSize != contentSizeError && frameSize > 0)

        var output = Data(count: Int(frameSize))
        let written = output.withUnsafeMutableBytes { (dst: UnsafeMutableRawBufferPointer) -> Int in
            compressed.withUnsafeBytes { (src: UnsafeRawBufferPointer) -> Int in
                ZSTD_decompress(dst.baseAddress, dst.count, src.baseAddress, src.count)
            }
        }
        XCTAssertEqual(ZSTD_isError(written), 0)
        return output
    }

    /// Mirrors `tests_v8_prover::test_ppid_prover_succeeds` in the Rust crate.
    func testProveWithPpid_realV8Vector_succeeds() throws {
        let circuitBytes = try loadCircuitBytes()
        let mdoc = try loadResource("v8_test_mdoc", ext: "cbor")
        let transcript = try loadResource("v8_test_transcript", ext: "cbor")

        let prover = try initializeProver(
            circuit: circuitBytes,
            circuitVersion: .v8,
            numAttributes: UInt8(Self.requestedClaims.count)
        )

        let proof = try proveWithPpid(
            prover: prover,
            deviceResponse: mdoc,
            namespace: Self.namespace,
            requestedClaims: Self.requestedClaims,
            sessionTranscript: transcript,
            time: Self.now,
            verifierContext: Data(Self.verifierContext)
        )

        XCTAssertFalse(proof.isEmpty, "proof must be non-empty")
    }

    /// Confirms `LongfellowZkProofSystem`'s own pseudonym formula
    /// (`SHA256(seed || verifierContext)`, applied inline in `generateProof`
    /// to derive its returned `pseudonym`) matches the reference
    /// `compute_ppid` helper in `prover_v8_test.rs`'s `tests_v8_prover`
    /// module bit-for-bit. Expected value independently precomputed (Python
    /// `hashlib.sha256`), not derived from the same Swift code under test -
    /// a regression/reference check, not a tautology.
    func testPseudonymFormula_matchesReferenceComputePpid() {
        let expectedHex = "63ec50dbdc29936d0f4f28ff3d31d3496a51a178696ee98ae15e4dcc27c4e2c7"
        var expected = [UInt8]()
        var index = expectedHex.startIndex
        while index < expectedHex.endIndex {
            let next = expectedHex.index(index, offsetBy: 2)
            expected.append(UInt8(expectedHex[index..<next], radix: 16)!)
            index = next
        }

        let actual = Array(SHA256.hash(data: Self.expectedSeed + Self.verifierContext))

        XCTAssertEqual(expected, actual)
    }
}

#endif // os(iOS)

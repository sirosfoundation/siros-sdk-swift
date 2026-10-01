// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

// Shared by every native ZK proof system that fetches circuits/keys from
// go-zk-circuits (currently `LongfellowZkProofSystem` and `VegaProofSystem`,
// both iOS-only) - extracted here rather than duplicated per system, mirroring
// the Kotlin SDK's own separate `ZkCircuitDecompression.kt` file.
#if os(iOS)

import Foundation
import libzstd
import SirosCredentials

/// Decompresses `compressedBytes` (zstd-compressed, per the catalog's
/// `ZkArtifact.compression` field) using the zstd frame's own embedded
/// content size when available (`ZSTD_getFrameContentSize`), falling back to
/// the catalog's `uncompressed.size` metadata, and finally to a generous
/// fixed multiplier if neither is available.
func decompressZkCircuitArtifact(_ compressedBytes: Data, descriptor: ZkCircuitDescriptor) throws -> Data {
    // ZSTD_getFrameContentSize's two sentinel returns are defined in
    // zstd.h as `(0ULL - 1)`/`(0ULL - 2)` (ZSTD_CONTENTSIZE_UNKNOWN/
    // _ERROR) - computed directly rather than relying on the Swift Clang
    // importer resolving those object-like macros, which isn't guaranteed
    // for expression-valued `#define`s.
    let contentSizeUnknown = UInt64.max
    let contentSizeError = UInt64.max - 1
    let frameSize = compressedBytes.withUnsafeBytes { (src: UnsafeRawBufferPointer) -> UInt64 in
        ZSTD_getFrameContentSize(src.baseAddress, src.count)
    }
    let outputSize: Int
    if frameSize != contentSizeUnknown, frameSize != contentSizeError, frameSize > 0 {
        outputSize = Int(frameSize)
    } else if let uncompressedSize = descriptor.artifact?.uncompressed?.size, uncompressedSize > 0 {
        #if canImport(os)
        zkDecompressionLogger.warning("Circuit '\(descriptor.id)' zstd frame has no embedded content size; using catalog metadata")
        #endif
        outputSize = Int(uncompressedSize)
    } else {
        #if canImport(os)
        zkDecompressionLogger.warning("Circuit '\(descriptor.id)' has no known uncompressed size; guessing buffer size")
        #endif
        // These circuits compress at roughly 300-400x (a 319KB real V8
        // 2-attribute circuit decompresses to ~104MB, confirmed via
        // `zstd -l`) - only reached if BOTH the frame's own embedded
        // content size AND the catalog's uncompressed.size are absent.
        outputSize = compressedBytes.count * 400
    }

    var output = Data(count: outputSize)
    let writtenOrError = output.withUnsafeMutableBytes { (dst: UnsafeMutableRawBufferPointer) -> Int in
        compressedBytes.withUnsafeBytes { (src: UnsafeRawBufferPointer) -> Int in
            ZSTD_decompress(dst.baseAddress, dst.count, src.baseAddress, src.count)
        }
    }
    guard ZSTD_isError(writtenOrError) == 0 else {
        throw MdocError.malformed("zstd decompression failed for circuit '\(descriptor.id)'")
    }
    if writtenOrError != outputSize {
        output = output.prefix(writtenOrError)
    }
    return output
}

#if canImport(os)
import os
let zkDecompressionLogger = Logger(subsystem: "org.siros.sdk", category: "ZkCircuitDecompression")
#endif

#endif // os(iOS)

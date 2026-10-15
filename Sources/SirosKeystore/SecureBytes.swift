// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// A short-lived secret (a PIN or passphrase) held in a buffer THIS TYPE owns and
/// explicitly zeroes, instead of `Data`/`String`.
///
/// `Data` and `String` cannot be reliably wiped: their storage is copy-on-write and
/// ARC-managed, so a `let`, a closure capture, or an internal copy the standard
/// library makes while reading or converting the value can keep the bytes alive in
/// memory this type never sees and cannot reach, for as long as the allocator
/// chooses not to reuse that page. `SecureBytes` fixes the one thing Swift *can*
/// give a guarantee about: ONE buffer, allocated and freed by this type, is
/// positively overwritten with zero the moment ``wipe()`` runs (on `deinit`, or
/// sooner when the caller is done with it) rather than left for ARC to collect
/// whenever it gets around to it.
///
/// ## What this does NOT fix
///
/// This is a best-effort mitigation, not a guarantee that the secret never
/// appears in memory outside this buffer. In particular:
///
/// - Every call that hands the secret to an existing `Data`-typed API (this
///   SDK's own ``ScaSignFlow/classifySecret(_:)``, or the UniFFI-generated FFI
///   call in `UniFFISigner`) necessarily makes an ordinary, unwipeable `Data`
///   copy for that call - `SecureBytes` cannot change the signature of code it
///   does not own. Keep each such copy as short-lived and unnamed as possible
///   (an expression, not a `let`) so ARC drops it as soon as the call returns;
///   this does not make it wiped, only not retained.
///   See ``dataCopy()``'s doc comment.
/// - Crossing the UniFFI/Rust FFI boundary (`FfiConverterData.write`, in the
///   generated `siros_wscd_manager.swift`) appends the PIN's bytes into a
///   growable `[UInt8]` `RustBuffer` one `Array.append` at a time; any
///   reallocation Swift's `Array` performs while that buffer grows makes an
///   intermediate copy this type has no way to reach or wipe. Once the call
///   returns, the Rust side owns its own copy, zeroed (or not) under its own
///   contract - entirely outside what this Swift SDK can audit or control.
/// - `mlock`/`munlock` (best-effort, see `init`/`wipe`) ask the OS not to swap
///   the page to disk; they do not stop another process with sufficient
///   privilege from reading this process's memory, and silently do nothing
///   useful if the call fails (no page-lock budget, no permission) - this type
///   does not surface that failure, since a wipe must still happen either way.
///
/// `SecureBytes` is `@unchecked Sendable`: every mutating access is
/// lock-protected, and the type's only shared state is the buffer itself.
public final class SecureBytes: @unchecked Sendable {
    private let lock = NSLock()
    private var buffer: UnsafeMutableBufferPointer<UInt8>?

    /// Copies `bytes` into a freshly allocated buffer this instance owns.
    public init(_ bytes: [UInt8]) {
        let buf = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: bytes.count)
        _ = buf.initialize(from: bytes)
        if let base = buf.baseAddress, buf.count > 0 {
            // Best-effort: asks the OS not to swap this page. Not available
            // (or not permitted) everywhere - a failure is not reported, since
            // the buffer is still used and still wiped either way.
            _ = mlock(base, buf.count)
        }
        buffer = buf
    }

    /// Copies the UTF-8 encoding of `string` into a freshly allocated buffer.
    /// `string` itself is an ordinary Swift `String` and is NOT wiped by this
    /// initializer - only use this where the secret already exists as a
    /// `String` for a reason outside this type's control (a test fixture, or
    /// a host's `WscdAuthProvider` implementation that hands back `Data`
    /// already, see `UniFFISigner.swift`).
    public convenience init(utf8 string: String) {
        self.init(Array(string.utf8))
    }

    /// The number of bytes held, or `0` once wiped.
    public var count: Int {
        lock.lock(); defer { lock.unlock() }
        return buffer?.count ?? 0
    }

    /// Whether `wipe()` has already run.
    public var isWiped: Bool {
        lock.lock(); defer { lock.unlock() }
        return buffer == nil
    }

    /// Copies the held bytes out as `Data`, for the one call that needs a
    /// `Data`-typed argument - this copy is an ORDINARY `Data`, not tracked or
    /// wiped by this type (see the type's doc comment on residual exposure).
    /// Returns empty `Data` once wiped.
    public func dataCopy() -> Data {
        lock.lock(); defer { lock.unlock() }
        guard let buffer else { return Data() }
        return Data(buffer)
    }

    /// Overwrites the buffer with zero and releases it. Idempotent: safe to
    /// call more than once, including after `deinit` has already run it.
    public func wipe() {
        lock.lock(); defer { lock.unlock() }
        guard let buffer else { return }
        buffer.update(repeating: 0)
        if let base = buffer.baseAddress, buffer.count > 0 {
            _ = munlock(base, buffer.count)
        }
        buffer.deallocate()
        self.buffer = nil
    }

    deinit { wipe() }
}

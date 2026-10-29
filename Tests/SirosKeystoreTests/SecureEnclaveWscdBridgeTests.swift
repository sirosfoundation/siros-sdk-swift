// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore

// The bridge to the UniFFI callback and error types exists on iOS only (the XCFramework has no other slice).
// Secure Enclave key generation needs a real interactive user session (confirmed failing the same way
// `LocalAuthProviderTests` already does over SSH) - these tests drive the Rust<->Swift wiring and the error-mapping
// contract with a fake `SecureEnclaveKeystoreBackend`, not a real Secure Enclave, the same split
// `UniFFIPinBridgeTests` already has for the PIN bridge.
#if os(iOS)
import siros_wscd_managerFFI
import LocalAuthentication

final class SecureEnclaveWscdBridgeTests: XCTestCase {

    private final class FakeBackend: SecureEnclaveKeystoreBackend, @unchecked Sendable {
        private let lock = NSLock()
        private var keys: [String: (x: Data, y: Data)] = [:]
        var failWith: Error?

        var isAvailable: Bool { true }

        func generateKey(keyTag: String) throws -> (x: Data, y: Data) {
            if let failWith { throw failWith }
            lock.lock(); defer { lock.unlock() }
            // Deterministic but distinct fake coordinates - this test never
            // verifies a signature cryptographically, only that the right
            // bytes made it end to end through Rust and back.
            let pair = (x: Data(repeating: UInt8(keys.count), count: 32), y: Data(repeating: UInt8(keys.count + 1), count: 32))
            keys[keyTag] = pair
            return pair
        }

        func sign(keyTag: String, data: Data) throws -> Data {
            if let failWith { throw failWith }
            lock.lock(); defer { lock.unlock() }
            guard keys[keyTag] != nil else {
                throw SecureEnclaveKeystoreError.keyNotFound(keyTag)
            }
            // Not a real signature - echoes `data` padded to 64 bytes, just
            // to prove the right bytes reached the callback.
            var out = Data(count: 64)
            out.replaceSubrange(0..<min(data.count, 64), with: data.prefix(64))
            return out
        }

        func deleteKey(keyTag: String) throws {
            if let failWith { throw failWith }
            lock.lock(); defer { lock.unlock() }
            guard keys.removeValue(forKey: keyTag) != nil else {
                throw SecureEnclaveKeystoreError.keyNotFound(keyTag)
            }
        }
    }

    private func signer(_ backend: SecureEnclaveKeystoreBackend) throws -> UniFFISigner {
        let signer = try UniFFISigner(config: FfiWscdConfig(defaultPlugin: "apple-se"))
        try signer.registerAppleSecureEnclavePlugin(backend: backend)
        return signer
    }

    // MARK: - Happy path: real UniFFI round trip, fake backend

    func testGenerateSignDeleteRoundTripThroughTheRealFfiBoundary() async throws {
        let backend = FakeBackend()
        let signer = try signer(backend)

        let kid = try await signer.generateKey(algorithm: "ES256")
        let signature = try await signer.sign(keyId: kid, data: Data("hello".utf8))
        XCTAssertEqual(signature.prefix(5), Data("hello".utf8))

        // A key that never existed must fail, not silently succeed.
        do {
            _ = try await signer.sign(keyId: "apple-se-does-not-exist", data: Data())
            XCTFail("signing an unknown kid must fail, not silently succeed")
        } catch {
            // Any error is the right outcome here - KeyNotFound specifically,
            // in practice.
        }
    }

    // MARK: - Error mapping: the Copilot-review-grade concern this whole bridge exists for

    /// Mirrors the Rust-side fix in siros-wscd-manager PR #132:
    /// `AuthCancelled`/`AuthRequired` must survive the callback boundary,
    /// not collapse into a generic error - verified here from the OTHER
    /// side of that same boundary (Swift throwing into Rust, rather than
    /// Rust's `secure_enclave_callback_error` receiving from the host).
    func testLaErrorCancellationMapsToAuthCancelled() {
        for code: LAError.Code in [.userCancel, .appCancel, .systemCancel] {
            let mapped = SecureEnclaveCallbackBridge.mapError(LAError(code))
            guard case .AuthCancelled = mapped else {
                return XCTFail("\(code) must map to AuthCancelled, got \(mapped)")
            }
        }
    }

    func testOtherLaErrorsMapToAuthRequired() {
        let mapped = SecureEnclaveCallbackBridge.mapError(LAError(.biometryNotEnrolled))
        guard case .AuthRequired = mapped else {
            return XCTFail("expected AuthRequired, got \(mapped)")
        }
    }

    func testNotAvailableMapsToUnsupportedNotCallback() {
        let mapped = SecureEnclaveCallbackBridge.mapError(SecureEnclaveKeystoreError.notAvailable)
        guard case .Unsupported = mapped else {
            return XCTFail("expected Unsupported, got \(mapped)")
        }
    }

    func testKeyNotFoundMapsToKeyNotFoundNotCallback() {
        let mapped = SecureEnclaveCallbackBridge.mapError(SecureEnclaveKeystoreError.keyNotFound("some-tag"))
        guard case .KeyNotFound(let msg) = mapped else {
            return XCTFail("expected KeyNotFound, got \(mapped)")
        }
        XCTAssertEqual(msg, "some-tag")
    }

    /// The real end-to-end version of `testLaErrorCancellationMapsToAuthCancelled`:
    /// a backend that throws `LAError.userCancel` from `generateKey` must
    /// surface as `FfiWscdError.AuthCancelled` all the way back through the
    /// real Rust manager, not just at the bridge's own `mapError` unit level.
    func testCancelledBiometricPromptSurvivesTheRoundTripAsAuthCancelled() async throws {
        let backend = FakeBackend()
        backend.failWith = LAError(.userCancel)
        let signer = try signer(backend)

        do {
            _ = try await signer.generateKey(algorithm: "ES256")
            XCTFail("the fake backend is configured to always fail")
        } catch let error as FfiWscdError {
            guard case .AuthCancelled = error else {
                return XCTFail("expected AuthCancelled, got \(error)")
            }
        }
    }
}
#endif

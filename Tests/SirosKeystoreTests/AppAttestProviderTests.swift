// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore

#if canImport(DeviceCheck)
import Foundation

/// Fake `AppAttestServiceProviding` - `DCAppAttestService` itself requires
/// a real device + valid entitlement (`isSupported` is `false` on
/// Simulator/CI), so this is the only way to exercise `generateEvidence`'s
/// key-exists/key-doesn't-exist branching logic in tests.
private final class FakeAppAttestService: AppAttestServiceProviding, @unchecked Sendable {
    var isSupported: Bool = true
    var generatedKeyId = "fake-app-attest-key-id"
    var attestationObject = Data("fake-attestation-object".utf8)
    private(set) var generateKeyCallCount = 0
    private(set) var attestKeyCalls: [(keyId: String, clientDataHash: Data)] = []

    func generateKey() async throws -> String {
        generateKeyCallCount += 1
        return generatedKeyId
    }

    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        attestKeyCalls.append((keyId, clientDataHash))
        return attestationObject
    }

    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        Data("fake-assertion".utf8)
    }
}

/// A locked box for `String?` - the `loadPersistedKeyId`/`savePersistedKeyId`
/// closures injected into `AppAttestProvider` are `@Sendable`, so a plain
/// captured `var` triggers a real Swift 6 concurrency error (not just a
/// style nit); this gives the closures a genuinely thread-safe place to
/// read/write.
private final class KeyIdBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: String?

    func get() -> String? {
        lock.lock(); defer { lock.unlock() }
        return value
    }

    func set(_ newValue: String) {
        lock.lock(); defer { lock.unlock() }
        value = newValue
    }
}

final class AppAttestProviderTests: XCTestCase {

    func testGenerateEvidenceGeneratesAndPersistsKeyWhenNoneExists() async throws {
        let service = FakeAppAttestService()
        let persistedKeyId = KeyIdBox()
        let provider = AppAttestProvider(
            service: service,
            loadPersistedKeyId: { persistedKeyId.get() },
            savePersistedKeyId: { persistedKeyId.set($0) }
        )

        let evidence = try await provider.generateEvidence(challenge: "chal-1", keyId: "wscd-instance-key-1")

        XCTAssertEqual(service.generateKeyCallCount, 1)
        XCTAssertEqual(persistedKeyId.get(), service.generatedKeyId)
        XCTAssertEqual(service.attestKeyCalls.count, 1)
        XCTAssertEqual(service.attestKeyCalls[0].keyId, service.generatedKeyId)
        XCTAssertEqual(evidence.type, "apple_app_attest")
        XCTAssertEqual(evidence.token, service.attestationObject.base64EncodedString())
        // The evidence's keyId is the WSCD correlation value, NOT the App
        // Attest key ID - the two are deliberately different identifiers.
        XCTAssertEqual(evidence.keyId, "wscd-instance-key-1")
        XCTAssertEqual(evidence.challenge, "chal-1")
    }

    func testGenerateEvidenceThrowsAlreadyAttestedWhenKeyExists() async throws {
        let service = FakeAppAttestService()
        let provider = AppAttestProvider(
            service: service,
            loadPersistedKeyId: { "already-persisted-key-id" },
            savePersistedKeyId: { _ in XCTFail("must not persist a new key when one already exists") }
        )

        do {
            _ = try await provider.generateEvidence(challenge: "chal-1", keyId: "wscd-instance-key-1")
            XCTFail("expected AppAttestError.alreadyAttested")
        } catch AppAttestProvider.AppAttestError.alreadyAttested {
            // expected
        }

        XCTAssertEqual(service.generateKeyCallCount, 0)
        XCTAssertEqual(service.attestKeyCalls.count, 0)
    }

    func testGenerateEvidencePropagatesAttestationFailure() async throws {
        struct FailingService: AppAttestServiceProviding {
            let isSupported = true
            func generateKey() async throws -> String { "some-key-id" }
            func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
                struct BoomError: Error {}
                throw BoomError()
            }
            func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data { Data() }
        }
        let persistedKeyId = KeyIdBox()
        let provider = AppAttestProvider(
            service: FailingService(),
            loadPersistedKeyId: { persistedKeyId.get() },
            savePersistedKeyId: { persistedKeyId.set($0) }
        )

        do {
            _ = try await provider.generateEvidence(challenge: "chal-1", keyId: "wscd-instance-key-1")
            XCTFail("expected an error")
        } catch AppAttestProvider.AppAttestError.attestationFailed {
            // expected
        }

        // Real Copilot-review finding, fixed: a key must NOT be persisted
        // when attestation fails, or every later call would immediately
        // throw alreadyAttested against a key that was never actually
        // attested - permanently bricking native attestation for this
        // install. Generating a throwaway unattested key is harmless; a
        // permanently stuck install is not.
        XCTAssertNil(persistedKeyId.get(), "must not persist a key that failed attestation")
    }
}

#endif

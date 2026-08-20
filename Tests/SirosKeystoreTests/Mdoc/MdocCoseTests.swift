// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import XCTest
@preconcurrency import SwiftCBOR
@testable import SirosKeystore

#if canImport(CryptoKit)
import CryptoKit
#endif

/// Round-trips `MdocCose.sign1Detached`/`MdocCose.verify1` against a real
/// ECDSA P-256 key pair. Ported from the Kotlin SDK's `MdocCoseTest.kt`.
///
/// Unlike the Kotlin/JDK port, no raw<->DER signature conversion test
/// scaffolding is needed - CryptoKit's `ECDSASignature.rawRepresentation`
/// already matches the COSE/JOSE wire format directly.
final class MdocCoseTests: XCTestCase {

    #if canImport(CryptoKit)
    func testVerify1_acceptsASignatureProducedBySign1Detached() async throws {
        let keyPair = P256.Signing.PrivateKey()
        let payload = Array("ReaderAuthentication test payload".utf8)

        let sign1 = try await MdocCose.sign1Detached(algorithm: "ES256", payload: payload) { toBeSigned in
            let signature = try keyPair.signature(for: Data(toBeSigned))
            return Array(signature.rawRepresentation)
        }

        let publicKeyX963 = Array(keyPair.publicKey.x963Representation)
        XCTAssertTrue(MdocCose.verify1(sign1, payload: payload, publicKeyX963: publicKeyX963))
    }

    func testVerify1_rejectsATamperedPayload() async throws {
        let keyPair = P256.Signing.PrivateKey()
        let payload = Array("ReaderAuthentication test payload".utf8)

        let sign1 = try await MdocCose.sign1Detached(algorithm: "ES256", payload: payload) { toBeSigned in
            let signature = try keyPair.signature(for: Data(toBeSigned))
            return Array(signature.rawRepresentation)
        }

        let tamperedPayload = Array("different payload entirely".utf8)
        let publicKeyX963 = Array(keyPair.publicKey.x963Representation)
        XCTAssertFalse(MdocCose.verify1(sign1, payload: tamperedPayload, publicKeyX963: publicKeyX963))
    }

    func testVerify1_rejectsASignatureFromTheWrongKey() async throws {
        let signingKeyPair = P256.Signing.PrivateKey()
        let otherKeyPair = P256.Signing.PrivateKey()
        let payload = Array("ReaderAuthentication test payload".utf8)

        let sign1 = try await MdocCose.sign1Detached(algorithm: "ES256", payload: payload) { toBeSigned in
            let signature = try signingKeyPair.signature(for: Data(toBeSigned))
            return Array(signature.rawRepresentation)
        }

        let otherPublicKeyX963 = Array(otherKeyPair.publicKey.x963Representation)
        XCTAssertFalse(MdocCose.verify1(sign1, payload: payload, publicKeyX963: otherPublicKeyX963))
    }
    #endif
}

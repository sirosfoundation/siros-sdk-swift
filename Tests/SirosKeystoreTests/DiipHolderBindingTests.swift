// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosCredentials
@testable import SirosKeystore

#if canImport(CryptoKit)
import CryptoKit

/// The DIIP holder-binding half of the keystore: `did:jwk` key naming, the
/// `jwt` proof shape, and looking a key up by whichever identifier a
/// credential happens to name it with.
final class DiipHolderBindingTests: XCTestCase {

    private let prfOutput = Data(0..<32)
    private let hkdfSalt = Data((0..<32).map { UInt8($0 + 0x10) })
    private let hkdfInfo = Data("SIROS Wallet PRF".utf8)

    private func unlocked(_ version: DidKeyVersion = .jwk) async throws -> JweKeystore {
        let keystore = JweKeystore(didKeyVersion: version)
        try await keystore.unlock(
            prfOutput: prfOutput, encryptedContainer: Data(), hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo
        )
        return keystore
    }

    // MARK: - key naming

    func testAWalletIsDidJwkOutOfTheBox() {
        XCTAssertEqual(DidKeyVersion.from(nil), .jwk)
        XCTAssertEqual(DidKeyVersion.from("something-unknown"), .jwk)
        XCTAssertEqual(DidKeyVersion.from("p256-pub"), .p256Pub)
        XCTAssertEqual(DidKeyVersion.from("jwk_jcs-pub"), .jwkJcsPub)
    }

    func testANewKeyIsNamedByItsDidJwkVerificationMethod() async throws {
        let keystore = try await unlocked()
        let kid = try await keystore.generateKey()
        XCTAssertTrue(kid.hasPrefix("did:jwk:"), "kid is a DID URL, not a thumbprint: \(kid)")
        XCTAssertTrue(kid.hasSuffix("#0"))

        // The DID resolves back to the key it names.
        let did = String(kid.dropLast(2))
        let document = Did.resolveDidJwk(did).document
        XCTAssertNotNil(document?.findPublicKey(kid: kid, relationship: .authentication))
    }

    func testTheLegacyDidKeyVersionsKeepNamingKeysByThumbprint() async throws {
        let keystore = try await unlocked(.p256Pub)
        let kid = try await keystore.generateKey()
        XCTAssertFalse(kid.hasPrefix("did:"))
    }

    func testAKeyPairsDidSurvivesAContainerRoundTrip() async throws {
        let keystore = try await unlocked()
        let kid = try await keystore.generateKey()
        let container = try await keystore.exportEncryptedContainer()

        // A wallet reconfigured for a legacy version must not re-identify a
        // key that credentials are already bound to.
        let reloaded = JweKeystore(didKeyVersion: .p256Pub)
        try await reloaded.unlock(
            prfOutput: prfOutput, encryptedContainer: container, hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo
        )
        XCTAssertEqual(reloaded.listKeys().map(\.keyId), [kid])
        XCTAssertEqual(reloaded.did(forKid: kid), String(kid.dropLast(2)))
    }

    // MARK: - the OID4VCI proof

    func testTheJwtProofNamesTheHoldersDidRatherThanEmbeddingTheKey() async throws {
        let keystore = try await unlocked()
        let kid = try await keystore.generateKey()
        let proof = try await keystore.generateProof(
            audience: "https://issuer.example", nonce: "n-0S6_WzA2Mj", freshKey: false
        )
        let header = JwtHelpers.parseJwtHeader(proof)
        let claims = JwtHelpers.parseJwtPayload(proof)

        XCTAssertEqual(header?["typ"] as? String, "openid4vci-proof+jwt")
        XCTAssertEqual(header?["kid"] as? String, kid)
        XCTAssertNil(header?["jwk"], "the key is named, not embedded")
        XCTAssertEqual(claims?["iss"] as? String, String(kid.dropLast(2)))
        XCTAssertEqual(claims?["aud"] as? String, "https://issuer.example")
        XCTAssertEqual(claims?["nonce"] as? String, "n-0S6_WzA2Mj")
    }

    func testTheProofVerifiesUnderTheKeyItsDidResolvesTo() async throws {
        // An issuer verifying the proof resolves the DID and checks the
        // signature - this is the seam a mismatch would only show up at.
        let keystore = try await unlocked()
        _ = try await keystore.generateKey()
        let proof = try await keystore.generateProof(
            audience: "https://issuer.example", nonce: "nonce", freshKey: false
        )
        let header = try XCTUnwrap(JwtHelpers.parseJwtHeader(proof))
        let claims = try XCTUnwrap(JwtHelpers.parseJwtPayload(proof))
        let did = try XCTUnwrap(claims["iss"] as? String)

        let jwk = try XCTUnwrap(
            Did.resolveDidJwk(did).document?
                .findPublicKey(kid: header["kid"] as? String, relationship: .authentication)
        )
        XCTAssertTrue(verify(proof, with: jwk))
    }

    func testWithoutADidTheProofStillCarriesTheKeyInTheHeader() async throws {
        // A non-DIIP issuer has nothing to resolve, so the legacy form is the
        // only one it can verify.
        let keystore = try await unlocked(.p256Pub)
        _ = try await keystore.generateKey()
        let proof = try await keystore.generateProof(
            audience: "https://issuer.example", nonce: "nonce", freshKey: false
        )
        XCTAssertNotNil(JwtHelpers.parseJwtHeader(proof)?["jwk"])
        XCTAssertNil(JwtHelpers.parseJwtPayload(proof)?["iss"])
    }

    // MARK: - presenting what the wallet already holds

    func testACredentialBoundByCnfKidIsPresentedWithAKbJwtNamingThatKey() async throws {
        let keystore = try await unlocked()
        let kid = try await keystore.generateKey()
        let credential = sdJwt(#"{"vct":"urn:example:x","cnf":{"kid":"\#(kid)"}}"#)

        let vp = try await keystore.signVpToken(
            credential: credential, disclosedClaims: nil, nonce: "nonce",
            audience: "https://verifier.example", kid: nil
        )
        let kb = try XCTUnwrap(vp.split(separator: "~").last.map(String.init))
        let header = JwtHelpers.parseJwtHeader(kb)
        XCTAssertEqual(header?["typ"] as? String, "kb+jwt")
        XCTAssertEqual(header?["kid"] as? String, kid)
        XCTAssertNil(header?["jwk"], "a kid-bound credential does not re-embed the key")
    }

    func testACredentialBoundByCnfJwkKeepsTheEmbeddedKeyKbJwt() async throws {
        // This is the regression that bites an existing wallet: the key pair
        // is named by a DID URL, but the credential can only name it by
        // value, so the lookup has to fall back to the thumbprint.
        let keystore = try await unlocked()
        let kid = try await keystore.generateKey()
        let publicJwk = try XCTUnwrap(publicJwk(of: keystore, kid: kid))
        let thumbprint = try XCTUnwrap(JwtHelpers.jwkThumbprint(publicJwk))
        XCTAssertNotEqual(kid, thumbprint, "the stored kid is not the thumbprint")

        let jwkJson = String(
            data: try JSONSerialization.data(withJSONObject: publicJwk, options: .sortedKeys),
            encoding: .utf8
        )!
        let credential = sdJwt(#"{"vct":"urn:example:x","cnf":{"jwk":\#(jwkJson)}}"#)

        let vp = try await keystore.signVpToken(
            credential: credential, disclosedClaims: nil, nonce: "nonce",
            audience: "https://verifier.example", kid: nil
        )
        let kb = try XCTUnwrap(vp.split(separator: "~").last.map(String.init))
        XCTAssertNotNil(
            JwtHelpers.parseJwtHeader(kb)?["jwk"],
            "a jwk-bound credential keeps the embedded key"
        )
        XCTAssertTrue(verify(kb, with: publicJwk))
    }

    func testAKeyPairIsFoundByThumbprintEvenWhenItIsNamedByADidUrl() async throws {
        let keystore = try await unlocked()
        let kid = try await keystore.generateKey()
        let publicJwk = try XCTUnwrap(publicJwk(of: keystore, kid: kid))
        let thumbprint = try XCTUnwrap(JwtHelpers.jwkThumbprint(publicJwk))

        // signPresentation with the thumbprint must reach the same key rather
        // than reporting it unavailable - this is what an mdoc device key or a
        // container written by another client hands us.
        let jwt = try await keystore.signPresentation(
            nonce: "nonce", audience: "https://verifier.example", credentialIds: [], kid: thumbprint
        )
        XCTAssertTrue(verify(jwt, with: publicJwk))
    }

    func testAnUnknownKidIsStillRefused() async throws {
        // The fallback must not become "sign with whatever key is around".
        let keystore = try await unlocked()
        _ = try await keystore.generateKey()
        do {
            _ = try await keystore.signPresentation(
                nonce: "nonce", audience: "https://verifier.example",
                credentialIds: [], kid: "no-such-key"
            )
            XCTFail("signing with the wrong key is never a safe substitute")
        } catch {
            // expected
        }
    }

    // MARK: - cnf reading

    func testCnfKidIsPreferredOverCnfJwkAndAnAbsentCnfIsNil() {
        let jwk: [String: Any] = [
            "kty": "EC", "crv": "P-256",
            "x": "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
            "y": "_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE",
        ]
        XCTAssertEqual(
            HolderIdentity.resolveCnfKid(["kid": "did:jwk:abc#0", "jwk": jwk]),
            "did:jwk:abc#0"
        )
        XCTAssertEqual(HolderIdentity.resolveCnfKid(["jwk": jwk]), JwtHelpers.jwkThumbprint(jwk))
        XCTAssertNil(HolderIdentity.resolveCnfKid(nil))
    }

    // MARK: - helpers

    private func publicJwk(of keystore: JweKeystore, kid: String) -> [String: String]? {
        keystore.listKeys().first { $0.keyId == kid }.flatMap { _ in
            // The public key is recoverable from the DID the key is named by,
            // which is the point of did:jwk.
            Did.resolveDidJwk(String(kid.dropLast(2))).document?
                .findPublicKey(kid: nil, relationship: .any)
        }
    }

    private func verify(_ jwt: String, with jwk: [String: String]) -> Bool {
        let parts = jwt.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3,
              let x = jwk["x"], let y = jwk["y"],
              let key = try? P256.Signing.PublicKey(
                  x963Representation: Data([0x04])
                      + EncryptedContainer.base64UrlDecode(x)
                      + EncryptedContainer.base64UrlDecode(y)
              ),
              let signature = try? P256.Signing.ECDSASignature(
                  rawRepresentation: EncryptedContainer.base64UrlDecode(parts[2])
              )
        else { return false }
        return key.isValidSignature(signature, for: Data("\(parts[0]).\(parts[1])".utf8))
    }

    private func sdJwt(_ payload: String) -> String {
        func b64(_ text: String) -> String {
            EncryptedContainer.base64UrlEncode(Data(text.utf8))
        }
        return "\(b64(#"{"alg":"ES256","typ":"dc+sd-jwt"}"#)).\(b64(payload)).sig~"
    }
}

#endif

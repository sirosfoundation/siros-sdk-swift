// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosCredentials
@testable import SirosKeystore

#if canImport(CryptoKit)
import CryptoKit

/// The holder-binding half of the keystore, where HAIP and DIIP part company:
/// `did:jwk` key naming, the two `jwt` proof shapes, and looking a key up by
/// whichever identifier a credential happens to name it with.
final class HolderBindingTests: XCTestCase {

    private let prfOutput = Data(0..<32)
    private let hkdfSalt = Data((0..<32).map { UInt8($0 + 0x10) })
    private let hkdfInfo = Data("SIROS Wallet PRF".utf8)

    private func unlocked(_ profile: InteropProfile = .diip) async throws -> JweKeystore {
        let keystore = JweKeystore(profile: profile)
        try await keystore.unlock(
            prfOutput: prfOutput, encryptedContainer: Data(), hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo
        )
        return keystore
    }

    // MARK: - key naming

    func testEachProfileNamesKeysTheWayItsHolderBindingNeeds() {
        XCTAssertEqual(DidKeyVersion.forProfile(.diip), .jwk)
        XCTAssertEqual(DidKeyVersion.forProfile(.haip), .p256Pub)
        XCTAssertEqual(DidKeyVersion.from(nil), .jwk)
        XCTAssertEqual(DidKeyVersion.from("p256-pub"), .p256Pub)
        XCTAssertEqual(DidKeyVersion.from("jwk_jcs-pub"), .jwkJcsPub)
    }

    func testAWalletSpeaksHaipUnlessToldOtherwise() {
        // Adding DIIP support must not change the proof shape every existing
        // SIROS ID issuer already accepts.
        XCTAssertEqual(InteropProfile.default, .haip)
        XCTAssertEqual(InteropProfile.haip.holderBinding, .embeddedJwk)
        XCTAssertEqual(InteropProfile.diip.holderBinding, .didJwk)
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

    func testAHaipWalletKeepsNamingKeysByThumbprint() async throws {
        let keystore = try await unlocked(.haip)
        let kid = try await keystore.generateKey()
        XCTAssertFalse(kid.hasPrefix("did:"))
    }

    func testAKeyPairsDidSurvivesAContainerRoundTrip() async throws {
        let keystore = try await unlocked()
        let kid = try await keystore.generateKey()
        let container = try await keystore.exportEncryptedContainer()

        // A wallet reconfigured for the other profile must not re-identify a
        // key that credentials are already bound to.
        let reloaded = JweKeystore(profile: .haip)
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

    func testAHaipProofCarriesTheKeyInTheHeader() async throws {
        // A HAIP issuer does not resolve DIDs, so the embedded form is the
        // only one it can verify.
        let keystore = try await unlocked(.haip)
        _ = try await keystore.generateKey()
        let proof = try await keystore.generateProof(
            audience: "https://issuer.example", nonce: "nonce", freshKey: false
        )
        XCTAssertNotNil(JwtHelpers.parseJwtHeader(proof)?["jwk"])
        XCTAssertNil(JwtHelpers.parseJwtPayload(proof)?["iss"])
    }

    func testOneWalletSendsEachIssuerTheProofShapeItCanVerify() async throws {
        // The whole point of the per-issuance choice: a DIIP-configured wallet
        // must still be able to talk to a HAIP issuer, and the reverse.
        let wallet = try await unlocked(.diip)
        let kid = try await wallet.generateKey()

        let toHaip = try await wallet.generateProof(
            audience: "https://haip.example", nonce: "nonce",
            freshKey: false, holderBinding: .embeddedJwk
        )
        XCTAssertNotNil(JwtHelpers.parseJwtHeader(toHaip)?["jwk"], "a HAIP issuer gets the key it can verify")
        XCTAssertNil(JwtHelpers.parseJwtHeader(toHaip)?["kid"])

        let toDiip = try await wallet.generateProof(
            audience: "https://diip.example", nonce: "nonce",
            freshKey: false, holderBinding: .didJwk
        )
        XCTAssertEqual(JwtHelpers.parseJwtHeader(toDiip)?["kid"] as? String, kid)
        XCTAssertNil(JwtHelpers.parseJwtHeader(toDiip)?["jwk"])
    }

    func testADiipWalletStillEmitsAHaipProofWhenThatIsWhatWasNegotiated() async throws {
        // The mirror of the case above: the binding the caller asks for wins
        // over what the keystore's own profile would have chosen, in both
        // directions. A key named by a DID URL still has to be embeddable,
        // since a HAIP issuer resolves no DIDs at all.
        let keystore = try await unlocked(.diip)
        _ = try await keystore.generateKey()
        let proof = try await keystore.generateProof(
            audience: "https://issuer.example", nonce: "nonce",
            freshKey: false, holderBinding: .embeddedJwk
        )
        XCTAssertNotNil(JwtHelpers.parseJwtHeader(proof)?["jwk"], "a HAIP proof carries the key")
        XCTAssertNil(JwtHelpers.parseJwtHeader(proof)?["kid"], "and names neither a kid")
        XCTAssertNil(JwtHelpers.parseJwtPayload(proof)?["iss"], "nor an iss")
    }

    // MARK: - negotiation must work on a HAIP-shaped keystore

    func testAHaipKeystoreCanStillProduceADiipProof() async throws {
        // The default wallet is HAIP, so its keys are named by thumbprint and
        // carry a did:key. If that decided the proof shape, negotiating DIIP
        // with an issuer could never be satisfied and the whole per-issuer
        // negotiation would be inert for every wallet that ships.
        let keystore = try await unlocked(.haip)
        let kid = try await keystore.generateKey()
        XCTAssertFalse(kid.hasPrefix("did:jwk:"), "a HAIP keystore names keys by thumbprint")

        let proof = try await keystore.generateProof(
            audience: "https://issuer.example", nonce: "n-1",
            freshKey: false, holderBinding: .didJwk
        )
        let did = try XCTUnwrap(
            JwtHelpers.parseJwtPayload(proof)?["iss"] as? String,
            "a DIIP proof names the holder with iss"
        )
        XCTAssertTrue(did.hasPrefix("did:jwk:"))
        XCTAssertNil(JwtHelpers.parseJwtHeader(proof)?["jwk"], "a DIIP proof names the key, it does not embed it")
        XCTAssertEqual(JwtHelpers.parseJwtHeader(proof)?["kid"] as? String, Did.didJwkKeyId(did))

        // And it is this key that the DID names.
        let named = try XCTUnwrap(
            Did.resolveDidJwk(did).document?.findPublicKey(kid: nil, relationship: .any)
        )
        XCTAssertTrue(verify(proof, with: named.compactMapValues { $0 as? String }))
    }

    func testACredentialBoundToADidJwkFindsTheThumbprintNamedKeyThatSignsForIt() async throws {
        // The issuer binds cnf.kid to the did:jwk from the proof above, but
        // the wallet stored that key under its thumbprint. Without matching
        // the two, the credential could never be presented.
        let keystore = try await unlocked(.haip)
        let storedKid = try await keystore.generateKey()
        let stored = try XCTUnwrap(publicJwk(of: keystore, kid: storedKid))
        let did = Did.createDidJwk(stored)

        XCTAssertTrue(HolderIdentity.matches(storedKid: storedKid, publicJwk: stored, kid: Did.didJwkKeyId(did)))
        XCTAssertTrue(HolderIdentity.matches(storedKid: storedKid, publicJwk: stored, kid: did))
        XCTAssertEqual(HolderIdentity.thumbprintOfDidJwk(Did.didJwkKeyId(did)), storedKid)

        // And signing for it reaches the key rather than reporting it gone.
        let jwt = try await keystore.signPresentation(
            nonce: "nonce", audience: "https://verifier.example",
            credentialIds: [], kid: Did.didJwkKeyId(did)
        )
        XCTAssertTrue(verify(jwt, with: stored))
    }

    func testADidJwkNamingSomeOtherKeyIsNotAMatch() async throws {
        let keystore = try await unlocked(.haip)
        let storedKid = try await keystore.generateKey()
        let stored = try XCTUnwrap(publicJwk(of: keystore, kid: storedKid))

        let otherKid = try await keystore.generateKey()
        let otherDid = Did.createDidJwk(try XCTUnwrap(publicJwk(of: keystore, kid: otherKid)))

        XCTAssertFalse(
            HolderIdentity.matches(storedKid: storedKid, publicJwk: stored, kid: Did.didJwkKeyId(otherDid))
        )
        XCTAssertNil(HolderIdentity.thumbprintOfDidJwk("did:web:issuer.example"))
        XCTAssertNil(HolderIdentity.thumbprintOfDidJwk("not-a-did"))
    }

    func testOneWalletPresentsAHaipCredentialAndADiipCredentialCorrectly() async throws {
        // Presentation is where the two profiles have to coexist without any
        // configuration at all: the credential's own `cnf` says how its key is
        // named, so the same wallet answers both without being told which is
        // which.
        let keystore = try await unlocked(.diip)
        let diipKid = try await keystore.generateKey()
        let haipKid = try await keystore.generateKey()
        let haipJwk = try XCTUnwrap(publicJwk(of: keystore, kid: haipKid))

        let jwkJson = String(
            data: try JSONSerialization.data(withJSONObject: haipJwk, options: .sortedKeys),
            encoding: .utf8
        )!
        let diipCredential = sdJwt(#"{"vct":"urn:example:diip","cnf":{"kid":"\#(diipKid)"}}"#)
        let haipCredential = sdJwt(#"{"vct":"urn:example:haip","cnf":{"jwk":\#(jwkJson)}}"#)

        let diipVp = try await keystore.signVpToken(
            credential: diipCredential, disclosedClaims: nil, nonce: "nonce",
            audience: "https://verifier.example", kid: nil
        )
        let diipKb = try XCTUnwrap(diipVp.split(separator: "~").last.map(String.init))
        XCTAssertEqual(JwtHelpers.parseJwtHeader(diipKb)?["kid"] as? String, diipKid)
        XCTAssertNil(JwtHelpers.parseJwtHeader(diipKb)?["jwk"])

        let haipVp = try await keystore.signVpToken(
            credential: haipCredential, disclosedClaims: nil, nonce: "nonce",
            audience: "https://verifier.example", kid: nil
        )
        let haipKb = try XCTUnwrap(haipVp.split(separator: "~").last.map(String.init))
        XCTAssertNotNil(JwtHelpers.parseJwtHeader(haipKb)?["jwk"])
        XCTAssertTrue(
            verify(haipKb, with: haipJwk),
            "the HAIP credential is signed by the key it is bound to, not the DIIP one"
        )
    }

    func testABatchIssuanceBindsEachCredentialToItsOwnKey() async throws {
        // freshKey is what OID4VCI batch issuance means: without it every copy
        // in the batch shares one holder key, and presenting them is linkable.
        let keystore = try await unlocked(.diip)
        var kids: Set<String> = []
        for _ in 0..<3 {
            let proof = try await keystore.generateProof(
                audience: "https://issuer.example", nonce: "nonce", freshKey: true
            )
            kids.insert(try XCTUnwrap(JwtHelpers.parseJwtHeader(proof)?["kid"] as? String))
        }
        XCTAssertEqual(kids.count, 3, "each proof names a different key")
        XCTAssertEqual(keystore.listKeys().count, 3)
    }

    func testWithoutFreshKeyTheWalletReusesTheKeyItHas() async throws {
        let keystore = try await unlocked(.diip)
        let kid = try await keystore.generateKey()
        for _ in 0..<2 {
            let proof = try await keystore.generateProof(
                audience: "https://issuer.example", nonce: "nonce", freshKey: false
            )
            XCTAssertEqual(JwtHelpers.parseJwtHeader(proof)?["kid"] as? String, kid)
        }
        XCTAssertEqual(keystore.listKeys().count, 1)
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
        // Works whichever way the keystore names its keys: a DID URL under
        // DIIP, a JWK thumbprint under HAIP.
        keystore.publicKeyJwk(forKid: kid)
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

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
#if canImport(CryptoKit)
import CryptoKit
#endif

/// How a holder key pair is turned into a DID and a local key id.
///
/// The value is shared with wallet-frontend's `DID_KEY_VERSION` config, and it
/// has to be: both clients read the same encrypted `privatedata` container, so
/// a key written by one is looked up by the other under whatever id it was
/// stored with.
public enum DidKeyVersion: String, Sendable, CaseIterable {
    /// `did:jwk`, with the key id being the DID's only verification method,
    /// `<did>#0`. What DIIP requires of a Holder, and the default.
    case jwk

    /// `did:key` with the P-256 multicodec, key id being the JWK thumbprint.
    /// Predates DIIP; kept so a wallet already holding credentials bound to
    /// one keeps working.
    case p256Pub = "p256-pub"

    /// `did:key` with a JCS-canonicalized JWK, key id being the JWK
    /// thumbprint. wallet-frontend's other legacy option.
    case jwkJcsPub = "jwk_jcs-pub"

    /// Whether keys of this version are named by a DID URL rather than by a
    /// JWK thumbprint. This is the branch that matters at every call site: a
    /// DID URL can be resolved by a relying party, a thumbprint cannot.
    public var namesKeysByDidUrl: Bool { self == .jwk }

    /// Parse the value as written in configuration. Unknown or absent values
    /// fall back to ``jwk``, so a wallet is DIIP-compliant out of the box
    /// rather than silently dropping to a legacy identifier.
    public static func from(_ value: String?) -> DidKeyVersion {
        guard let value = value?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
              let match = DidKeyVersion(rawValue: value)
        else { return .jwk }
        return match
    }
}

/// A key pair's DID and the local id it is addressed by.
public struct KeypairIdentity: Sendable, Equatable {
    public let did: String
    public let kid: String

    public init(did: String, kid: String) {
        self.did = did
        self.kid = kid
    }
}

#if canImport(CryptoKit)

enum HolderIdentity {

    /// Derive a key pair's identity from its public JWK.
    ///
    /// For ``DidKeyVersion/jwk`` the key id is a DID URL - DIIP binds the
    /// Holder with a `cnf.kid` naming a verification method of their DID
    /// document, and `#0` is the only one a `did:jwk` document has. The legacy
    /// versions keep the JWK thumbprint they have always used.
    static func derive(publicJwk: [String: String], version: DidKeyVersion) -> KeypairIdentity {
        switch version {
        case .jwk:
            let did = Did.createDidJwk(publicJwk)
            return KeypairIdentity(did: did, kid: Did.didJwkKeyId(did))
        case .p256Pub, .jwkJcsPub:
            // did:key for the legacy versions; the thumbprint is the id.
            let thumbprint = JwtHelpers.jwkThumbprint(publicJwk) ?? UUID().uuidString.lowercased()
            return KeypairIdentity(did: didKey(publicJwk: publicJwk), kid: thumbprint)
        }
    }

    /// `did:key` with the P-256 multicodec (0x1200), base58btc-encoded - the
    /// pre-DIIP identifier this SDK and wallet-frontend used.
    static func didKey(publicJwk: [String: String]) -> String {
        guard let x = publicJwk["x"], let y = publicJwk["y"] else { return "" }
        let xData = [UInt8](EncryptedContainer.base64UrlDecode(x))
        let yData = [UInt8](EncryptedContainer.base64UrlDecode(y))
        guard xData.count == 32, yData.count == 32 else { return "" }
        // Compressed point: 0x02/0x03 by the parity of y, then x.
        let prefix: UInt8 = (yData[31] & 1) == 1 ? 0x03 : 0x02
        let multicodec: [UInt8] = [0x80, 0x24] + [prefix] + xData
        return "did:key:z" + base58btc(multicodec)
    }

    private static let base58Alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

    static func base58btc(_ input: [UInt8]) -> String {
        var digits: [UInt8] = [0]
        for byte in input {
            var carry = Int(byte)
            for index in 0..<digits.count {
                carry += Int(digits[index]) << 8
                digits[index] = UInt8(carry % 58)
                carry /= 58
            }
            while carry > 0 {
                digits.append(UInt8(carry % 58))
                carry /= 58
            }
        }
        // Leading zero bytes are encoded as leading '1's, not dropped.
        var result = String(repeating: "1", count: input.prefix { $0 == 0 }.count)
        for digit in digits.reversed() where !(result.isEmpty && digit == 0) {
            result.append(base58Alphabet[Int(digit)])
        }
        return result.isEmpty ? "1" : result
    }

    /// Whether a stored key pair is the one a credential means by `kid`.
    ///
    /// A key pair's id depends on ``DidKeyVersion``: a DID URL for `did:jwk`,
    /// a JWK thumbprint for the `did:key` versions. Some credentials can only
    /// ever name the holder key by value, and so can only produce a
    /// thumbprint - an mdoc's `deviceKeyInfo.deviceKey`, and an SD-JWT
    /// `cnf.jwk`. Without the fallback, a wallet configured for `did:jwk`
    /// could not present the mdoc credentials it already holds, which is
    /// exactly the regression this guards.
    static func matches(storedKid: String, publicJwk: [String: String], kid: String) -> Bool {
        if storedKid == kid { return true }
        return JwtHelpers.jwkThumbprint(publicJwk) == kid
    }

    /// The `kid` a credential's `cnf` claim binds it to - `cnf.kid` as written
    /// (what DIIP requires), else the thumbprint of `cnf.jwk`.
    static func resolveCnfKid(_ cnf: [String: Any]?) -> String? {
        Did.resolveCnfKid(cnf) { JwtHelpers.jwkThumbprint($0) }
    }

    /// The `cnf` claim of an SD-JWT credential, or nil if it has none.
    static func cnf(of credential: String) -> [String: Any]? {
        let jwt = credential.split(separator: "~", omittingEmptySubsequences: false).first.map(String.init) ?? credential
        return JwtHelpers.parseJwtPayload(jwt)?["cnf"] as? [String: Any]
    }
}

#endif

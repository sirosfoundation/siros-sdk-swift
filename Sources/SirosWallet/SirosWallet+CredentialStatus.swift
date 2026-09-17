// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosCredentials

/// DIIP's Validity and Revocation Algorithm, run over the credentials this
/// wallet holds: the `validFrom` / `validUntil` window, then the issuer's
/// Token Status List.
///
/// A host app renders the outcome and computes none of it - establishing
/// revocation means fetching and verifying a Status List Token, which is not
/// something a UI layer should be doing.
extension SirosWallet {

    /// The DIIP release this wallet follows when it speaks
    /// ``InteropProfile/diip`` - see ``DiipProfile``.
    public var diipProfile: DiipProfile { config.diipProfile }

    /// The interoperability profile this wallet speaks with `issuer` when
    /// nothing else decides - see ``InteropProfile``.
    ///
    /// A per-Issuer override wins over the wallet-wide default. The match is
    /// by prefix so that a `credential_issuer` with a path under a configured
    /// base counts, and the longest configured prefix wins so a specific entry
    /// is not shadowed by a broader one. This is an escape hatch for an Issuer
    /// whose metadata is wrong, not the normal path: see
    /// ``holderBinding(for:)``.
    public func interopProfile(for issuer: String?) -> InteropProfile {
        issuerOverride(for: issuer) ?? config.interopProfile
    }

    /// The configured override for `issuer`, if a specific one was set.
    ///
    /// A bare `hasPrefix` would also match `https://issuer.example.evil`
    /// against an override for `https://issuer.example` - a different domain
    /// entirely, handed another issuer's configuration. The boundary has to be
    /// a path separator.
    func issuerOverride(for issuer: String?) -> InteropProfile? {
        guard let issuer else { return nil }
        return config.issuerInteropProfiles
            .filter { entry in
                let base = entry.key.hasSuffix("/") ? String(entry.key.dropLast()) : entry.key
                return issuer == base || issuer == entry.key || issuer.hasPrefix(base + "/")
            }
            .max { $0.key.count < $1.key.count }?
            .value
    }

    /// How the Holder's key should be named in an OID4VCI proof to `issuer` -
    /// the one thing HAIP and DIIP genuinely disagree about, and something
    /// OID4VCI makes a per-issuance choice.
    ///
    /// **Negotiated, not configured.** The Issuer's own
    /// `cryptographic_binding_methods_supported` for the configuration being
    /// issued says which identifier it can verify, so a wallet holding
    /// credentials from a HAIP ecosystem and a DIIP ecosystem shapes each
    /// proof to its Issuer without anyone choosing a profile. A user cannot
    /// reasonably be asked which of two interoperability profiles an issuer
    /// they just scanned belongs to, and does not have to be.
    ///
    /// The configured profile is only the fallback, for an Issuer that
    /// advertises nothing usable - and the per-Issuer override the escape
    /// hatch above that, for one that advertises the wrong thing.
    ///
    /// Handed to `KeystoreManager.generateProof` so the keystore never has to
    /// know about issuers.
    public func holderBinding(for issuer: String?) -> HolderBinding {
        // An explicit per-Issuer override comes first. It exists precisely for
        // an Issuer whose metadata advertises the wrong thing, so letting the
        // metadata win would leave it with nothing to override.
        if let override = issuerOverride(for: issuer) {
            return override.holderBinding
        }

        let advertised = activeOffer
            .flatMap { offer -> [String]? in
                guard issuer == nil || offer.credentialIssuerIdentifier == issuer else { return nil }
                return offer.cryptographicBindingMethodsSupported
            }
        if let negotiated = HolderBinding.negotiate(advertised) {
            return negotiated
        }
        return config.interopProfile.holderBinding
    }

    /// Evaluate one credential's status.
    ///
    /// The result is cached; ``refreshCredentialStatuses()`` re-runs it. A
    /// status list that cannot be reached leaves the credential
    /// ``CredentialStatus/valid`` rather than hiding it, which is what keeps
    /// the wallet usable offline.
    public func credentialStatus(of credential: StoredCredential) async -> CredentialStatus {
        guard let claims = CredentialUtils.validityClaims(credential) else { return .valid }
        let status = await credentialStatusEvaluator.evaluate(claims: claims)
        credentialStatusCache.set(credential.id, status)
        return status
    }

    /// The last known status of a credential, without network access or
    /// re-evaluation - for synchronous call sites such as a SwiftUI body.
    /// ``CredentialStatus/valid`` until ``refreshCredentialStatuses()`` has
    /// run.
    public func cachedCredentialStatus(of credentialId: Int64) -> CredentialStatus {
        credentialStatusCache.get(credentialId)
    }

    /// Re-evaluate every held credential, and return the statuses by
    /// credential id.
    @discardableResult
    public func refreshCredentialStatuses() async -> [Int64: CredentialStatus] {
        var statuses: [Int64: CredentialStatus] = [:]
        for credential in await credentialStore.getAll() {
            statuses[credential.id] = await credentialStatus(of: credential)
        }
        credentialStatusCache.retain(Set(statuses.keys))
        return statuses
    }

    /// Resolve a DID to its document, for the methods ``diipProfile``
    /// requires - an Issuer's signing key, or a Verifier's identity.
    public func resolveDid(_ did: String) async -> DidResolution {
        await didResolver.resolve(did)
    }

    /// The signing key an issuer publishes, for verifying a Status List Token
    /// it signed.
    ///
    /// Resolved through ``DidResolver``, so `did:web` and anything else that
    /// needs resolving goes to go-trust rather than being fetched here. A
    /// status list whose key cannot be resolved goes unverified, which the
    /// reader reports as an unavailable status, never as a valid one.
    static func resolveIssuerSigningKey(
        issuer: String,
        kid: String?,
        resolver: DidResolver
    ) async -> [String: String]? {
        await resolver.resolve(issuer).document?
            .findPublicKey(kid: kid, relationship: .assertionMethod)
    }

    /// Fetch a URL that belongs to a third party - an issuer's Status List
    /// Token, named by a URI inside the credential itself.
    ///
    /// Only documents whose location the credential already states, never DID
    /// resolution: which document is authoritative for an identifier is
    /// go-trust's decision (see ``DidResolver``). The Status List Token's own
    /// signing key is still resolved through that path, so fetching the list
    /// is not a trust decision.
    ///
    /// These carry NO wallet credentials: attaching this wallet's bearer token
    /// or tenant id to a request at an arbitrary domain would leak them.
    static func fetchPublicUrl(_ urlString: String, headers: [String: String]) async -> Data? {
        guard let url = URL(string: urlString) else { return nil }
        var request = URLRequest(url: url)
        for (name, value) in headers {
            request.setValue(value, forHTTPHeaderField: name)
        }
        guard let (data, response) = try? await URLSession.shared.data(for: request),
              let http = response as? HTTPURLResponse,
              (200..<300).contains(http.statusCode)
        else { return nil }
        return data
    }
}

/// A small mutable cache of evaluated statuses.
///
/// `SirosWallet` is a `final class`, not an actor, so this holds its own lock
/// rather than relying on the wallet's isolation.
final class CredentialStatusCache: @unchecked Sendable {
    private let lock = NSLock()
    private var statuses: [Int64: CredentialStatus] = [:]

    func get(_ id: Int64) -> CredentialStatus {
        lock.lock()
        defer { lock.unlock() }
        return statuses[id] ?? .valid
    }

    func set(_ id: Int64, _ status: CredentialStatus) {
        lock.lock()
        defer { lock.unlock() }
        statuses[id] = status
    }

    /// Drop everything not in `ids` - a credential that has been deleted
    /// should not keep a stale status alive.
    func retain(_ ids: Set<Int64>) {
        lock.lock()
        defer { lock.unlock() }
        statuses = statuses.filter { ids.contains($0.key) }
    }

    /// All held statuses, e.g. after a logout.
    func clear() {
        lock.lock()
        defer { lock.unlock() }
        statuses.removeAll()
    }
}

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

    /// The DIIP release this wallet's wire behaviour follows - see
    /// ``DiipProfile``.
    public var diipProfile: DiipProfile { config.diipProfile }

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
    /// Only DID-identified issuers are answered here - DIIP identifies Issuers
    /// by `did:jwk` or `did:web`, and a status list signed by anything else
    /// goes unverified, which the reader reports as an unavailable status,
    /// never as a valid one.
    static func resolveIssuerSigningKey(
        issuer: String,
        kid: String?,
        resolver: DidResolver
    ) async -> [String: String]? {
        await resolver.resolve(issuer).document?
            .findPublicKey(kid: kid, relationship: .assertionMethod)
    }

    /// Fetch a URL that belongs to a third party - an issuer's status list, a
    /// `did:web` document.
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

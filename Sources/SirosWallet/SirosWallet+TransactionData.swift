// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosCredentials
import SirosKeystore
import SirosTransport

/// Gives the EC TS12 pipeline its type metadata through the wallet's own
/// fetchers: the registry and well-known strategies, with `vct#integrity`
/// directing resolution (`VctmFetcher.fetchDocument`).
struct WalletTransactionMetadataSource: TransactionMetadataSource {
    let fetcher: VctmFetcher
    let registryUrl: String
    /// Fetches documents the metadata references. Deliberately NOT the wallet's
    /// authenticated type-metadata getter: the URLs are attacker-influenced
    /// until their integrity is checked and must never receive credentials.
    let resourceGet: @Sendable (URL) async -> Data?

    func typeMetadataDocument(vct: String, expectedIntegrity: String?) async -> String? {
        // The issuer URL is not known here; the registry and the vct's own
        // well-known location do not need it.
        await fetcher.fetchDocument(
            issuerUrl: "", scope: "", vct: vct, registryUrl: registryUrl, expectedIntegrity: expectedIntegrity
        )?.raw
    }

    func fetchResource(uri: String) async -> Data? {
        // Only absolute https references: metadata is attacker-influenced
        // input until its integrity is checked, so no other scheme is fetched.
        guard let url = URL(string: uri), url.scheme?.lowercased() == "https" else { return nil }
        return await resourceGet(url)
    }
}

extension SirosWallet {
    /// The default `resourceGet`: a plain, unauthenticated GET with a time and size limit.
    static let unauthenticatedResourceGet: @Sendable (URL) async -> Data? = { url in
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = 10
        guard let (data, response) = try? await URLSession.shared.data(for: request),
              (response as? HTTPURLResponse)?.statusCode == 200, data.count <= 256 * 1024 else { return nil }
        return data
    }

    /// The transaction log (EC TS12 section 5.3), newest first: one record
    /// per SCA presentation attempt, consented, declined or refused.
    public func transactionLog() async -> [TransactionLogEntry] {
        await transactionLogStoreInstance().entries()
    }

    /// Replaces where transaction-log records are kept. By default they
    /// persist in the wallet's synchronised container when the keystore
    /// offers one, and in memory otherwise.
    public func setTransactionLogStore(_ store: any TransactionLogStore) {
        lock.lock(); transactionLogStoreStorage = store; transactionLogStoreIsDefault = false; lock.unlock()
    }

    /// Drops the default log store at an account boundary (logout, lock), so a
    /// later account never sees or writes into this one's records. A store the
    /// host supplied is the host's to manage and is left alone.
    func resetDefaultTransactionLogStore() {
        lock.lock(); defer { lock.unlock() }
        if transactionLogStoreIsDefault { transactionLogStoreStorage = nil }
    }

    func transactionLogStoreInstance() -> any TransactionLogStore {
        lock.lock(); defer { lock.unlock() }
        if let existing = transactionLogStoreStorage { return existing }
        transactionLogStoreIsDefault = true
        let created: any TransactionLogStore
        if let extensions = keystore as? ExtensionStore {
            created = ExtensionTransactionLogStore(store: extensions, persisted: { [weak self] in
                await self?.persistAndSyncKeystore()
            })
        } else {
            created = InMemoryTransactionLogStore()
        }
        transactionLogStoreStorage = created
        return created
    }

    func makeTransactionDataService() -> TransactionDataService {
        TransactionDataService(
            source: WalletTransactionMetadataSource(
                fetcher: vctmFetcher, registryUrl: resolvedRegistryUrl, resourceGet: transactionResourceGet
            ),
            consentHandler: transactionConsentHandler,
            factorsProvider: authenticationFactorsProvider,
            log: transactionLogStoreInstance(),
            consentTimeout: transactionDataConsentTimeout
        )
    }

    /// Records, at the start of a legacy flow, whether TS12 handling is in
    /// effect for it, and returns that value so the declaration to the
    /// engine is derived from the same capture. The engine assigns the flow
    /// id later, so the oldest unclaimed record is assigned to the first
    /// flow that asks (`transactionDataActive(forFlow:)`).
    @discardableResult
    func snapshotTransactionDataEnablement() -> Bool {
        let effective = transactionDataEffectivelyEnabled
        lock.lock(); legacyFlowSnapshotQueue.append(effective); lock.unlock()
        return effective
    }

    /// The same for a WMP session (capabilities are offered per session).
    @discardableResult
    func snapshotWmpSessionEnablement() -> Bool {
        let effective = transactionDataEffectivelyEnabled
        lock.lock(); wmpSessionSnapshot = effective; lock.unlock()
        return effective
    }

    /// Whether `flowId` (legacy) or the WMP session started with TS12
    /// handling in effect AND a handler is still registered. A legacy flow
    /// that started without a record falls back to the live value.
    func transactionDataActive(forFlow flowId: String, viaWmp: Bool) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard transactionConsentHandlerStorage != nil else { return false }
        if viaWmp { return wmpSessionSnapshot }
        if let known = legacyFlowSnapshots[flowId] { return known }
        let value = legacyFlowSnapshotQueue.isEmpty
            ? transactionDataEnabledValue
            : legacyFlowSnapshotQueue.removeFirst()
        legacyFlowSnapshots[flowId] = value
        return value
    }

    /// The `...#integrity` claims of an SD-JWT VC (name to SRI string), read
    /// from its issuer-signed payload; empty when none or unreadable.
    static func integrityClaims(ofSdJwt raw: String) -> [String: String] {
        guard let jwt = raw.split(separator: "~", omittingEmptySubsequences: false).first,
              case let parts = jwt.split(separator: ".", omittingEmptySubsequences: false), parts.count == 3,
              let payloadBytes = TransactionDataHashing.base64UrlDecode(String(parts[1])),
              let payload = (try? StrictJSON.parse(payloadBytes))?.objectValue else { return [:] }
        return payload.compactMapValues { $0.stringValue }.filter { $0.key.hasSuffix("#integrity") }
    }

    /// Runs the TS12 sequence for a presentation and returns the bindings by
    /// DCQL query id. `selected` maps each answering query id to the stored
    /// credential chosen for it. Throws `SirosError.transactionData`.
    func processTransactionData(
        entries: [TransactionDataEntryInput],
        responseMode: String?,
        selected: [String: StoredCredential],
        verifier: String,
        requestSigned: Bool?
    ) async throws -> [String: TransactionDataBinding] {
        var credentials: [TransactionDataCredential] = []
        var names: [String: String] = [:]
        var factorContexts: [String: AuthenticationFactorContext] = [:]
        for (queryId, cred) in selected.sorted(by: { $0.key < $1.key }) {
            credentials.append(TransactionDataCredential(
                queryId: queryId, format: cred.format, vct: cred.metadata?.vct,
                integrityClaims: Self.integrityClaims(ofSdJwt: cred.raw)
            ))
            if let name = cred.metadata?.name { names[queryId] = name }
            let kid = cred.kid ?? keystore.listKeys().first?.keyId
            let properties: SignerSecurityProperties? = if let kid { await keystore.securityProperties(keyId: kid) } else { nil }
            let pluginId = kid.flatMap { id in keystore.listKeys().first(where: { $0.keyId == id })?.pluginId }
            factorContexts[queryId] = AuthenticationFactorContext(keyStorage: properties?.keyStorage ?? [], pluginId: pluginId, keyId: kid)
        }
        let service = makeTransactionDataService()
        return try await service.process(
            TransactionDataRequest(entries: entries, responseMode: responseMode, credentials: credentials),
            context: TransactionDataContext(
                verifier: verifier, requestSigned: requestSigned, locale: transactionDataLocale,
                credentialNames: names, factorContexts: factorContexts
            )
        )
    }

    /// The TS12 bindings for a presentation relayed by the orchestrator
    /// (legacy engine or WMP), by DCQL query id. Empty when the request
    /// carries no `transaction_data`. A request that does carry it is refused
    /// unless TS12 handling was in effect when the flow started.
    func orchestratedTransactionBindings(
        transactionData: [TransactionData]?,
        responseMode: String?,
        refs: [CredentialRef]?,
        allCreds: [StoredCredential],
        audience: String,
        flowId: String,
        viaWmp: Bool
    ) async throws -> [String: TransactionDataBinding] {
        // An absent or empty member means the request carries no transaction.
        guard let transactionData, !transactionData.isEmpty else { return [:] }
        do {
            guard transactionDataActive(forFlow: flowId, viaWmp: viaWmp) else {
                throw TransactionDataError(.disabled, detail: "transaction_data received but TS12 handling is not in effect")
            }
            // Without credentials_to_include nothing resolves and the pipeline refuses.
            var selected: [String: StoredCredential] = [:]
            for ref in refs ?? [] {
                guard let queryId = ref.credentialQueryId, !queryId.isEmpty,
                      let id = Int64(ref.credentialId), let cred = allCreds.first(where: { $0.id == id }),
                      selected[queryId] == nil else {
                    throw TransactionDataError(.invalidEntry, detail: "credentials_to_include cannot be matched to DCQL queries")
                }
                selected[queryId] = cred
            }
            return try await processTransactionData(
                entries: transactionData.map(TransactionDataEntryInput.init),
                responseMode: responseMode,
                selected: selected,
                verifier: audience,
                requestSigned: nil
            )
        } catch let error as TransactionDataError {
            throw SirosError.transactionData(error)
        }
    }

    /// WMP `sign_presentation` for a request carrying `transaction_data`:
    /// every credential must be one the transaction is bound to (combined
    /// presentations are not supported over WMP, which lacks the response URI
    /// a non-SCA mdoc part would need).
    func wmpTransactionPresentation(flowId: String, params: SignSubFlowParams) async throws -> SignSubFlowResult {
        let allCreds = await credentialStore.getAll()
        let bindings = try await orchestratedTransactionBindings(
            transactionData: params.transactionData, responseMode: params.responseMode,
            refs: params.credentialsToInclude, allCreds: allCreds, audience: params.audience,
            flowId: flowId, viaWmp: true
        )
        // Resolve every reference first: nothing is signed unless all of them
        // are bound to the transaction.
        var toSign: [(cred: StoredCredential, ref: CredentialRef, binding: TransactionDataBinding)] = []
        for ref in params.credentialsToInclude ?? [] {
            guard let queryId = ref.credentialQueryId, let binding = bindings[queryId],
                  let id = Int64(ref.credentialId), let cred = allCreds.first(where: { $0.id == id }) else {
                throw SirosError.transactionData(TransactionDataError(
                    .invalidEntry, detail: "every credential in a WMP transaction presentation must be bound to the transaction"
                ))
            }
            toSign.append((cred, ref, binding))
        }
        var parts: [String] = []
        for item in toSign {
            parts.append(try await keystore.signVpToken(
                credential: item.cred.raw, disclosedClaims: item.ref.disclosedClaims, nonce: params.nonce,
                audience: params.audience, transactionData: item.binding, kid: item.cred.kid
            ))
        }
        return SignSubFlowResult(vpToken: parts.joined(separator: "\n"))
    }
}

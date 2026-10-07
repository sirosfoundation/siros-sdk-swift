// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Per-request facts the service needs besides the request itself.
public struct TransactionDataContext: Sendable {
    public var verifier: String
    /// `nil` when the SDK does not know (engine and WMP deliver requests
    /// pre-verified); `false` makes the app warn and require confirmation.
    public var requestSigned: Bool?
    public var locale: String
    /// Display name per DCQL query id.
    public var credentialNames: [String: String]
    /// Key facts per DCQL query id, for the authentication factors.
    public var factorContexts: [String: AuthenticationFactorContext]

    public init(verifier: String, requestSigned: Bool? = nil, locale: String,
                credentialNames: [String: String] = [:], factorContexts: [String: AuthenticationFactorContext] = [:]) {
        self.verifier = verifier
        self.requestSigned = requestSigned
        self.locale = locale
        self.credentialNames = credentialNames
        self.factorContexts = factorContexts
    }
}

/// Runs the whole EC TS12 sequence for one request (contract section 4):
/// validate, build the consent model, ask the user, establish the
/// authentication factors, build the per-credential bindings and log the
/// outcome. Nothing is signed by this type; a thrown error means NOTHING may
/// be signed.
public final class TransactionDataService: @unchecked Sendable {
    private let source: any TransactionMetadataSource
    private let consentHandler: (any TransactionConsentHandler)?
    private let factorsProvider: any AuthenticationFactorsProvider
    private let log: any TransactionLogStore
    private let consentTimeout: TimeInterval
    private let fetchTimeout: TimeInterval

    public init(
        source: any TransactionMetadataSource,
        consentHandler: (any TransactionConsentHandler)?,
        factorsProvider: any AuthenticationFactorsProvider = InterimAuthenticationFactorsProvider(),
        log: any TransactionLogStore,
        consentTimeout: TimeInterval = 120,
        fetchTimeout: TimeInterval = 10
    ) {
        self.source = source
        self.consentHandler = consentHandler
        self.factorsProvider = factorsProvider
        self.log = log
        self.consentTimeout = consentTimeout
        self.fetchTimeout = fetchTimeout
    }

    /// The bindings by DCQL query id, for the credentials the transaction is bound to.
    public func process(_ request: TransactionDataRequest, context: TransactionDataContext) async throws -> [String: TransactionDataBinding] {
        let raws = request.entries.map(\.raw)
        let credentialLabel = request.credentials.first.flatMap { context.credentialNames[$0.queryId] ?? $0.vct } ?? ""
        do {
            let pipeline = TransactionDataPipeline(source: source, fetchTimeout: fetchTimeout)
            let validated = try await pipeline.validate(request)

            // 8. Display and consent. No handler: the transaction cannot be shown.
            guard let handler = consentHandler else { throw TransactionDataError(.noConsentHandler) }
            let boundQueryId = validated.entries.first?.credentialIds.first ?? ""
            let name = context.credentialNames[boundQueryId]
                ?? request.credentials.first(where: { $0.queryId == boundQueryId })?.vct ?? ""
            let model = try await TransactionConsentModelBuilder(
                source: source, fetchTimeout: fetchTimeout, maxResourceBytes: 256 * 1024
            ).build(
                validated: validated, request: request, verifier: context.verifier, credentialName: name,
                requestSigned: context.requestSigned, locale: context.locale
            )
            guard await askUser(handler, model) else { throw TransactionDataError(.declined) }

            // 9. Bindings with the factors applied for this operation.
            var bindings: [String: TransactionDataBinding] = [:]
            for credential in request.credentials {
                let factors: [AuthenticationFactor]
                do {
                    factors = try await factorsProvider.factors(for: context.factorContexts[credential.queryId] ?? AuthenticationFactorContext())
                } catch {
                    // A host-supplied provider may throw; that is a refusal like any other.
                    throw TransactionDataError(.insufficientAuthenticationFactors, detail: "the factors provider failed")
                }
                if let binding = try validated.binding(forQueryId: credential.queryId, factors: factors) {
                    // Refuse now, before anything is signed.
                    _ = try binding.kbJwtClaims()
                    bindings[credential.queryId] = binding
                }
            }

            // 10. Log.
            await log.append(TransactionLogEntry.records(
                rawEntries: raws, verifier: context.verifier, credential: credentialLabel, outcome: .consented
            ))
            return bindings
        } catch let error as TransactionDataError {
            await log.append(TransactionLogEntry.records(
                rawEntries: raws, verifier: context.verifier, credential: credentialLabel,
                outcome: error.reason == .declined ? .declined : .refused,
                reason: error.reason == .declined ? nil : error.reason.rawValue
            ))
            throw error
        }
    }

    /// `true` only for an explicit yes. A throw or a missing answer within the
    /// time limit is a decline.
    private func askUser(_ handler: any TransactionConsentHandler, _ model: TransactionConsentRequest) async -> Bool {
        await withDeadline(consentTimeout, fallback: false) { (try? await handler.confirm(model)) ?? false }
    }
}

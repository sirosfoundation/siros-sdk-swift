// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosTransport

// MARK: - Request model (the contract's normalized `TransactionDataRequest`)

/// What an orchestrator claims one `transaction_data` entry decodes to. Used
/// ONLY to detect a disagreement with the SDK's own decoding of `raw`; never
/// as input to display, validation or hashing.
public struct TransactionDataHint: Sendable, Equatable {
    public var type: String?
    public var credentialIds: [String]?
    public var payload: JSONValue?

    public init(type: String? = nil, credentialIds: [String]? = nil, payload: JSONValue? = nil) {
        self.type = type
        self.credentialIds = credentialIds
        self.payload = payload
    }
}

/// One entry of the request's `transaction_data` array, in verifier order.
public struct TransactionDataEntryInput: Sendable, Equatable {
    /// The base64url string exactly as the verifier sent it.
    public var raw: String
    public var hint: TransactionDataHint?

    public init(raw: String, hint: TransactionDataHint? = nil) {
        self.raw = raw
        self.hint = hint
    }

    /// From an engine/WMP entry. An entry without `raw` cannot be hashed and
    /// is refused by the pipeline (empty `raw` fails decoding).
    public init(_ wire: TransactionData) {
        self.raw = wire.raw ?? ""
        self.hint = TransactionDataHint(
            type: wire.type,
            credentialIds: wire.credentialIds,
            payload: wire.payload.map(JSONValue.init)
        )
    }
}

/// A credential that can answer one DCQL query id.
public struct TransactionDataCredential: Sendable, Equatable {
    public var queryId: String
    /// Credential format identifier, e.g. `dc+sd-jwt`.
    public var format: String
    /// The SD-JWT VC `vct`.
    public var vct: String?
    /// The credential's `...#integrity` claims (name to SRI string), when it
    /// carries any: `vct#integrity` and the
    /// `transaction_data_types['<type>'].schema_uri#integrity` /
    /// `.ui_labels_uri#integrity` members (TS12 section 4.1.2).
    public var integrityClaims: [String: String]

    public init(queryId: String, format: String, vct: String?, integrityClaims: [String: String] = [:]) {
        self.queryId = queryId
        self.format = format
        self.vct = vct
        self.integrityClaims = integrityClaims
    }

    var isSdJwtVc: Bool { format == "dc+sd-jwt" || format == "vc+sd-jwt" }
}

/// The normalized request every transport yields before the core runs.
public struct TransactionDataRequest: Sendable, Equatable {
    public var entries: [TransactionDataEntryInput]
    public var responseMode: String?
    public var credentials: [TransactionDataCredential]

    public init(entries: [TransactionDataEntryInput], responseMode: String?, credentials: [TransactionDataCredential]) {
        self.entries = entries
        self.responseMode = responseMode
        self.credentials = credentials
    }
}

// MARK: - Metadata source

/// Where the pipeline obtains SCA type metadata and the documents it
/// references. Everything is optional-returning: unreachable means refusal.
public protocol TransactionMetadataSource: Sendable {
    /// The raw SD-JWT VC Type Metadata document for `vct`. When
    /// `expectedIntegrity` is non-nil the source should prefer a document
    /// hashing to it (see `VctmFetcher.fetchDocument`); the pipeline
    /// re-checks the result either way.
    func typeMetadataDocument(vct: String, expectedIntegrity: String?) async -> String?
    /// Fetches a document referenced by the metadata (`schema_uri`,
    /// `claims_uri`, `ui_labels_uri`).
    func fetchResource(uri: String) async -> Data?
}

// MARK: - Result model

/// One entry that passed every check of the core pipeline.
public struct ValidatedTransactionEntry: Sendable, Equatable {
    /// The verifier's string, the only hash input.
    public let raw: String
    public let type: String
    /// DCQL query ids this entry is bound to.
    public let credentialIds: [String]
    public let payload: JSONValue
    /// The verifier's offered algorithms the SDK supports, in the verifier's
    /// order (`["sha-256"]` when it offered none).
    public let acceptableHashAlgorithms: [String]
    /// Per bound query id: the `transaction_data_types[type]` metadata object
    /// (claims, labels) the display step needs; absent when the type is
    /// built in and the attestation does not list it.
    public let typeMetadata: [String: JSONValue]
}

public struct ValidatedTransactionData: Sendable, Equatable {
    public let entries: [ValidatedTransactionEntry]
    public let responseMode: String

    /// The binding for the credential answering `queryId`: the entries whose
    /// `credential_ids` include it, in verifier order. `nil` when no entry
    /// names it (a non-SCA credential in a combined presentation gets none).
    ///
    /// Decision recorded in the contract (plan item B8, pending an interop
    /// test): a credential's KB-JWT carries the hashes of the entries bound to
    /// it, not of all entries.
    public func binding(forQueryId queryId: String, factors: [AuthenticationFactor]) throws -> TransactionDataBinding? {
        let mine = entries.filter { $0.credentialIds.contains(queryId) }
        guard let first = mine.first else { return nil }
        // One algorithm per KB-JWT: the first the verifier offered for the
        // first entry that every bound entry also accepts.
        guard let algorithm = first.acceptableHashAlgorithms.first(where: { alg in
            mine.allSatisfy { $0.acceptableHashAlgorithms.contains(alg) }
        }) else {
            throw TransactionDataError(.unsupportedHashAlgorithm, detail: "no hash algorithm acceptable to every bound entry")
        }
        return TransactionDataBinding(
            rawEntries: mine.map(\.raw),
            hashAlgorithm: algorithm,
            responseMode: responseMode,
            factors: factors
        )
    }
}

// MARK: - Pipeline

/// The EC TS12 core pipeline (contract section 4, steps 1 to 7). Fails
/// closed: the first problem with any entry throws and nothing is signed.
/// Display and consent (step 8) and logging (step 10) belong to the consent
/// layer; this produces what it needs.
public struct TransactionDataPipeline: Sendable {
    public static let scaCategory = "urn:eu:europa:ec:eudi:sua:sca"

    private let source: any TransactionMetadataSource
    private let fetchTimeout: TimeInterval
    private let maxMetadataBytes: Int
    private let maxResourceBytes: Int
    private let maxRawEntryBytes = 64 * 1024

    public init(
        source: any TransactionMetadataSource,
        fetchTimeout: TimeInterval = 10,
        maxMetadataBytes: Int = 1024 * 1024,
        maxResourceBytes: Int = 256 * 1024
    ) {
        self.source = source
        self.fetchTimeout = fetchTimeout
        self.maxMetadataBytes = maxMetadataBytes
        self.maxResourceBytes = maxResourceBytes
    }

    public func validate(_ request: TransactionDataRequest) async throws -> ValidatedTransactionData {
        guard !request.entries.isEmpty else {
            throw TransactionDataError(.invalidEntry, detail: "transaction_data is empty")
        }
        guard let responseMode = request.responseMode, !responseMode.isEmpty else {
            throw TransactionDataError(.invalidEntry, detail: "request has no response_mode, which the KB-JWT must echo")
        }
        var metadataByVct: [String: JSONValue] = [:]
        var validated: [ValidatedTransactionEntry] = []
        for input in request.entries {
            validated.append(try await validateEntry(input, request: request, metadataByVct: &metadataByVct))
        }
        return ValidatedTransactionData(entries: validated, responseMode: responseMode)
    }

    // MARK: Per entry

    private func validateEntry(
        _ input: TransactionDataEntryInput,
        request: TransactionDataRequest,
        metadataByVct: inout [String: JSONValue]
    ) async throws -> ValidatedTransactionEntry {
        // 1. Decode `raw` ourselves; this, never the orchestrator's hint, is the truth.
        let decoded = try decode(input.raw)
        try checkHint(input.hint, against: decoded)

        // 2. Structure.
        guard let type = decoded["type"]?.stringValue, !type.isEmpty else {
            throw TransactionDataError(.invalidEntry, detail: "type is missing or empty")
        }
        guard let idValues = decoded["credential_ids"]?.arrayValue, !idValues.isEmpty,
              idValues.allSatisfy({ ($0.stringValue ?? "").isEmpty == false }) else {
            throw TransactionDataError(.invalidEntry, detail: "credential_ids is missing, empty or not strings")
        }
        let credentialIds = idValues.compactMap(\.stringValue)
        var bound: [TransactionDataCredential] = []
        for id in credentialIds {
            guard let credential = request.credentials.first(where: { $0.queryId == id }) else {
                throw TransactionDataError(.invalidEntry, detail: "credential_ids names a query that no requested credential answers")
            }
            bound.append(credential)
        }
        guard let payload = decoded["payload"], payload.objectValue != nil else {
            throw TransactionDataError(.invalidEntry, detail: "payload is missing or not an object")
        }
        let offeredAlgs = try offeredAlgorithms(decoded["transaction_data_hashes_alg"])

        // 3. Format: SD-JWT VC only (TS12 v1.0.1 covers nothing else).
        for credential in bound where !credential.isSdJwtVc {
            throw TransactionDataError(.unsupportedFormat, detail: "format \(credential.format)")
        }

        var typeMetadata: [String: JSONValue] = [:]
        for credential in bound {
            // 4. SCA attestation.
            let metadata = try await scaMetadata(for: credential, cache: &metadataByVct)
            // 5. Type support.
            let typeEntry = try typeEntry(type, in: metadata)
            // 6. Schema.
            try await checkSchema(payload: payload, type: type, typeEntry: typeEntry, credential: credential)
            if let typeEntry { typeMetadata[credential.queryId] = typeEntry }
        }

        // 7. Hash algorithm.
        let acceptable = (offeredAlgs ?? ["sha-256"]).filter { TransactionDataHashing.supportedAlgorithms.contains($0) }
        guard !acceptable.isEmpty else {
            throw TransactionDataError(.unsupportedHashAlgorithm, detail: "none of the offered algorithms is supported")
        }

        return ValidatedTransactionEntry(
            raw: input.raw,
            type: type,
            credentialIds: credentialIds,
            payload: payload,
            acceptableHashAlgorithms: acceptable,
            typeMetadata: typeMetadata
        )
    }

    private func decode(_ raw: String) throws -> [String: JSONValue] {
        guard !raw.isEmpty, raw.utf8.count <= maxRawEntryBytes else {
            throw TransactionDataError(.invalidEntry, detail: "raw entry is empty or too large")
        }
        guard let bytes = TransactionDataHashing.base64UrlDecode(raw) else {
            throw TransactionDataError(.invalidEntry, detail: "raw entry is not base64url")
        }
        let value: JSONValue
        do { value = try StrictJSON.parse(bytes) } catch {
            throw TransactionDataError(.invalidEntry, detail: "raw entry is not a JSON document: \(error)")
        }
        guard let object = value.objectValue else {
            throw TransactionDataError(.invalidEntry, detail: "raw entry is not a JSON object")
        }
        return object
    }

    private func checkHint(_ hint: TransactionDataHint?, against decoded: [String: JSONValue]) throws {
        guard let hint else { return }
        let disagree = { throw TransactionDataError(.inconsistentWithOrchestrator, detail: $0) }
        if let t = hint.type, t != decoded["type"]?.stringValue { try disagree("type") }
        if let ids = hint.credentialIds {
            let actual = decoded["credential_ids"]?.arrayValue?.compactMap(\.stringValue)
            if ids != actual { try disagree("credential_ids") }
        }
        if let p = hint.payload {
            guard let actual = decoded["payload"], p.jsonEquals(actual) else { try disagree("payload"); return }
        }
    }

    /// `transaction_data_hashes_alg` as the verifier sent it: an array
    /// (OID4VP 1.0 Appendix B), or a bare string some verifiers send.
    private func offeredAlgorithms(_ value: JSONValue?) throws -> [String]? {
        guard let value else { return nil }
        if let s = value.stringValue { return [s] }
        if let a = value.arrayValue, !a.isEmpty, a.allSatisfy({ $0.stringValue != nil }) { return a.compactMap(\.stringValue) }
        throw TransactionDataError(.invalidEntry, detail: "transaction_data_hashes_alg is not a string or non-empty string array")
    }

    // MARK: Metadata

    private func scaMetadata(for credential: TransactionDataCredential, cache: inout [String: JSONValue]) async throws -> [String: JSONValue] {
        guard let vct = credential.vct, !vct.isEmpty else {
            throw TransactionDataError(.metadataUnavailable, detail: "credential has no vct")
        }
        if let cached = cache[vct]?.objectValue { return try requireSca(cached) }
        let pin = credential.integrityClaims["vct#integrity"]
        guard let text = await bounded({ await source.typeMetadataDocument(vct: vct, expectedIntegrity: pin) }),
              text.utf8.count <= maxMetadataBytes else {
            throw TransactionDataError(.metadataUnavailable, detail: "type metadata for the credential could not be obtained")
        }
        if let pin, !Integrity.matches(Data(text.utf8), pin) {
            throw TransactionDataError(.metadataUnavailable, detail: "type metadata does not match vct#integrity")
        }
        guard let parsed = try? StrictJSON.parse(text), let object = parsed.objectValue else {
            throw TransactionDataError(.metadataUnavailable, detail: "type metadata is not a JSON object")
        }
        guard object["vct"]?.stringValue == vct else {
            throw TransactionDataError(.metadataUnavailable, detail: "type metadata is for a different vct")
        }
        cache[vct] = parsed
        return try requireSca(object)
    }

    private func requireSca(_ metadata: [String: JSONValue]) throws -> [String: JSONValue] {
        guard metadata["category"]?.stringValue == Self.scaCategory else {
            throw TransactionDataError(.notScaAttestation, detail: "type metadata category is not the SCA category")
        }
        return metadata
    }

    /// The `transaction_data_types[type]` object, `nil` for a built-in type
    /// the attestation does not list, or a refusal.
    private func typeEntry(_ type: String, in metadata: [String: JSONValue]) throws -> JSONValue? {
        var listed: JSONValue?
        if let types = metadata["transaction_data_types"] {
            guard let map = types.objectValue else {
                throw TransactionDataError(.metadataUnavailable, detail: "transaction_data_types is not an object")
            }
            listed = map[type]
        }
        if let listed {
            guard listed.objectValue != nil else {
                throw TransactionDataError(.metadataUnavailable, detail: "transaction_data_types entry is not an object")
            }
            return listed
        }
        guard TransactionDataBuiltIns.types.contains(type) else {
            throw TransactionDataError(.unsupportedType, detail: "type is not offered by the attestation's metadata")
        }
        return nil
    }

    // MARK: Schema

    private func checkSchema(
        payload: JSONValue, type: String, typeEntry: JSONValue?, credential: TransactionDataCredential
    ) async throws {
        let schema = try await resolveSchema(type: type, typeEntry: typeEntry, credential: credential)
        let validator = JSONSchemaValidator(resolveRef: { TransactionDataBuiltIns.schema(forReference: $0) })
        switch validator.validate(payload, against: schema) {
        case .valid: return
        case .invalid(let path, let reason):
            throw TransactionDataError(.schemaViolation, detail: "payload\(path): \(reason)")
        case .unsupported(let why):
            throw TransactionDataError(.schemaViolation, detail: "schema cannot be evaluated: \(why)")
        }
    }

    private func resolveSchema(
        type: String, typeEntry: JSONValue?, credential: TransactionDataCredential
    ) async throws -> JSONValue {
        guard let entry = typeEntry?.objectValue else {
            guard let builtIn = TransactionDataBuiltIns.schema(forType: type) else {
                throw TransactionDataError(.metadataUnavailable, detail: "no schema for the type")
            }
            return builtIn
        }
        switch (entry["schema"], entry["schema_uri"]) {
        case (.some, .some):
            throw TransactionDataError(.metadataUnavailable, detail: "metadata gives both schema and schema_uri")
        case (.none, .none):
            guard let builtIn = TransactionDataBuiltIns.schema(forType: type) else {
                throw TransactionDataError(.metadataUnavailable, detail: "metadata names no schema")
            }
            return builtIn
        case (.some(let embedded), .none):
            if let urn = embedded.stringValue {
                if let builtIn = TransactionDataBuiltIns.schema(forType: urn) { return builtIn }
                // A JSON Schema document carried as a string.
                if let parsed = try? StrictJSON.parse(urn), parsed.objectValue != nil { return parsed }
                throw TransactionDataError(.metadataUnavailable, detail: "schema is neither a known built-in nor a JSON Schema")
            }
            return embedded
        case (.none, .some(let uriValue)):
            guard let uri = uriValue.stringValue, !uri.isEmpty else {
                throw TransactionDataError(.metadataUnavailable, detail: "schema_uri is not a string")
            }
            if let builtIn = TransactionDataBuiltIns.schema(forType: uri) { return builtIn }
            let pin = credential.integrityClaims["transaction_data_types['\(type)'].schema_uri#integrity"]
            guard let data = await bounded({ await source.fetchResource(uri: uri) }), data.count <= maxResourceBytes else {
                throw TransactionDataError(.metadataUnavailable, detail: "schema_uri could not be fetched")
            }
            if let pin, !Integrity.matches(data, pin) {
                throw TransactionDataError(.metadataUnavailable, detail: "schema_uri content does not match its #integrity")
            }
            guard let parsed = try? StrictJSON.parse(data) else {
                throw TransactionDataError(.metadataUnavailable, detail: "schema_uri content is not JSON")
            }
            return parsed
        }
    }

    // MARK: Time bound

    /// Runs `operation`, giving up (nil) after `fetchTimeout`.
    private func bounded<T: Sendable>(_ operation: @escaping @Sendable () async -> T?) async -> T? {
        let timeout = fetchTimeout
        return await withTaskGroup(of: T?.self) { group in
            group.addTask { await operation() }
            group.addTask {
                try? await Task.sleep(nanoseconds: UInt64(max(timeout, 0) * 1_000_000_000))
                return nil
            }
            let first = await group.next() ?? nil
            group.cancelAll()
            return first
        }
    }
}

extension JSONValue {
    /// Converts the transport's loosely typed value.
    public init(_ any: AnyCodable) {
        switch any {
        case .string(let s): self = .string(s)
        case .int(let i): self = .int(Int64(i))
        case .double(let d): self = .double(d)
        case .bool(let b): self = .bool(b)
        case .object_(let o): self = .object(o.mapValues(JSONValue.init))
        case .array(let a): self = .array(a.map(JSONValue.init))
        case .null_: self = .null
        }
    }
}

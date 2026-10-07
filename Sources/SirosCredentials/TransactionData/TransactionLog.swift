// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// What a log record says about the transaction itself (TS12 5.3).
public struct TransactionLogSubject: Sendable, Equatable {
    public let transactionId: String?
    public let typeName: String?
    public let entities: [String: String]

    public init(transactionId: String?, typeName: String?, entities: [String: String] = [:]) {
        self.transactionId = transactionId
        self.typeName = typeName
        self.entities = entities
    }
}

/// One transaction-log record for an SCA presentation attempt (TS12 v1.0.1
/// section 5.3), written whether it succeeded, was declined or was refused.
///
/// Holds only the fields section 5.3 names; never the full payload.
public struct TransactionLogEntry: Codable, Sendable, Equatable, Identifiable {
    public enum Outcome: String, Codable, Sendable {
        case consented, declined, refused
    }

    public let id: String
    /// Milliseconds since the Unix epoch.
    public let timestamp: Int64
    /// `payload.transaction_id`, when the entry could be decoded.
    public let transactionId: String?
    /// The transaction type name (`transaction_data_types.name` in section 5.3
    /// terms): "Payment Confirmation" and so on, else the type URI.
    public let typeName: String?
    /// Relevant entity names as present: `payee`, `pisp`, `service`, `aisp`.
    public let entities: [String: String]
    public let verifier: String
    public let credential: String
    public let outcome: Outcome
    /// The `TransactionDataError.Reason` raw value when `outcome == .refused`.
    public let reason: String?

    public init(
        id: String = UUID().uuidString.lowercased(),
        timestamp: Int64 = Int64(Date().timeIntervalSince1970 * 1000),
        subject: TransactionLogSubject,
        verifier: String, credential: String, outcome: Outcome, reason: String? = nil
    ) {
        self.id = id
        self.timestamp = timestamp
        self.transactionId = subject.transactionId
        self.typeName = subject.typeName
        self.entities = subject.entities
        self.verifier = verifier
        self.credential = credential
        self.outcome = outcome
        self.reason = reason
    }

    /// Builds the records for a request's raw entries, one per entry.
    /// Decodes leniently: a refusal may be BECAUSE an entry is malformed, and
    /// it must still be logged, with whatever fields could be read.
    public static func records(
        rawEntries: [String], verifier: String, credential: String, outcome: Outcome, reason: String? = nil
    ) -> [TransactionLogEntry] {
        let raws = rawEntries.isEmpty ? [""] : rawEntries
        return raws.map { raw in
            let fields = TransactionLogFields(raw: raw)
            return TransactionLogEntry(
                subject: TransactionLogSubject(transactionId: fields.transactionId, typeName: fields.typeName, entities: fields.entities),
                verifier: verifier, credential: credential, outcome: outcome, reason: reason
            )
        }
    }
}

/// The section 5.3 fields read from a raw entry.
struct TransactionLogFields {
    var transactionId: String?
    var typeName: String?
    var entities: [String: String] = [:]

    init(raw: String) {
        guard let bytes = TransactionDataHashing.base64UrlDecode(raw),
              let object = (try? StrictJSON.parse(bytes))?.objectValue else { return }
        let type = object["type"]?.stringValue
        typeName = type.map { TransactionDataBuiltIns.displayName(forType: $0) }
        let payload = object["payload"]
        transactionId = payload?["transaction_id"]?.stringValue
        func name(_ path: [String]) -> String? {
            var node = payload
            for key in path { node = node?[key] }
            return node?.stringValue
        }
        switch type {
        case TransactionDataBuiltIns.paymentType:
            entities["payee"] = name(["payee", "name"])
            entities["pisp"] = name(["pisp", "legal_name"])
        case TransactionDataBuiltIns.loginRiskType:
            entities["service"] = name(["service"])
        case TransactionDataBuiltIns.accountAccessType:
            entities["aisp"] = name(["aisp", "legal_name"])
        case TransactionDataBuiltIns.emandateType:
            entities["payee"] = name(["payment_payload", "payee", "name"])
            entities["pisp"] = name(["payment_payload", "pisp", "legal_name"])
        default: break
        }
        entities = entities.compactMapValues { $0 }
    }
}

/// Where transaction-log records are kept.
public protocol TransactionLogStore: Sendable {
    func append(_ entries: [TransactionLogEntry]) async
    /// Newest first.
    func entries() async -> [TransactionLogEntry]
}

/// A bounded in-memory log. Lost on restart: the wallet uses a persistent
/// store when its keystore offers one and falls back to this otherwise.
public final class InMemoryTransactionLogStore: TransactionLogStore, @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [TransactionLogEntry] = []
    private let capacity: Int

    public init(capacity: Int = 500) { self.capacity = max(1, capacity) }

    public func append(_ entries: [TransactionLogEntry]) async {
        lock.lock(); defer { lock.unlock() }
        stored.insert(contentsOf: entries.reversed(), at: 0)
        if stored.count > capacity { stored.removeLast(stored.count - capacity) }
    }

    public func entries() async -> [TransactionLogEntry] {
        lock.lock(); defer { lock.unlock() }
        return stored
    }
}

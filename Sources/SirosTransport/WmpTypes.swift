// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

// MARK: - WMP Metadata

/// WMP metadata envelope present in every request/response.
public struct WmpMeta: Codable, Sendable, Equatable {
    public static let wmpVersion = "0.1"

    public var version: String
    public var sessionId: String?
    public var sender: String?
    public var timestamp: String?
    public var traceId: String?
    public var encrypted: Bool?

    public init(
        version: String = WmpMeta.wmpVersion,
        sessionId: String? = nil,
        sender: String? = nil,
        timestamp: String? = nil,
        traceId: String? = nil,
        encrypted: Bool? = nil
    ) {
        self.version = version
        self.sessionId = sessionId
        self.sender = sender
        self.timestamp = timestamp
        self.traceId = traceId
        self.encrypted = encrypted
    }

    enum CodingKeys: String, CodingKey {
        case version, sender, timestamp, encrypted
        case sessionId = "session_id"
        case traceId = "trace_id"
    }
}

// MARK: - JSON-RPC 2.0

/// JSON-RPC 2.0 request.
public struct JsonRpcRequest: Codable, Sendable, Equatable {
    public var jsonrpc: String
    public var id: String?
    public var method: String
    public var params: [String: AnyCodable]?

    public init(
        jsonrpc: String = "2.0",
        id: String? = nil,
        method: String,
        params: [String: AnyCodable]? = nil
    ) {
        self.jsonrpc = jsonrpc
        self.id = id
        self.method = method
        self.params = params
    }
}

/// JSON-RPC 2.0 response.
public struct JsonRpcResponse: Codable, Sendable, Equatable {
    public var jsonrpc: String
    public var id: String?
    public var result: [String: AnyCodable]?
    public var error: JsonRpcError?

    public init(
        jsonrpc: String = "2.0",
        id: String? = nil,
        result: [String: AnyCodable]? = nil,
        error: JsonRpcError? = nil
    ) {
        self.jsonrpc = jsonrpc
        self.id = id
        self.result = result
        self.error = error
    }
}

/// JSON-RPC error object.
public struct JsonRpcError: Codable, Sendable, Equatable {
    public var code: Int
    public var message: String
    public var data: AnyCodable?

    public init(code: Int, message: String, data: AnyCodable? = nil) {
        self.code = code
        self.message = message
        self.data = data
    }
}

// MARK: - Session lifecycle types

/// WMP session creation parameters.
public struct SessionCreateParams: Codable, Sendable {
    public var wmp: WmpMeta
    public var participants: [String]?
    public var capabilitiesOffered: [String: AnyCodable]?
    public var security: [String: AnyCodable]?
    public var ttl: Int?
    public var auth: SessionAuth?

    public init(
        wmp: WmpMeta,
        participants: [String]? = nil,
        capabilitiesOffered: [String: AnyCodable]? = nil,
        security: [String: AnyCodable]? = nil,
        ttl: Int? = nil,
        auth: SessionAuth? = nil
    ) {
        self.wmp = wmp
        self.participants = participants
        self.capabilitiesOffered = capabilitiesOffered
        self.security = security
        self.ttl = ttl
        self.auth = auth
    }

    enum CodingKeys: String, CodingKey {
        case wmp, participants, security, ttl, auth
        case capabilitiesOffered = "capabilities_offered"
    }
}

/// Session authentication.
public struct SessionAuth: Codable, Sendable {
    public var type: String
    public var token: String

    public init(type: String, token: String) {
        self.type = type
        self.token = token
    }
}

/// WMP session creation result.
public struct SessionCreateResult: Codable, Sendable {
    public var wmp: WmpMeta
    public var capabilities: [String: AnyCodable]?
    public var security: [String: AnyCodable]?
    public var challenge: String?
    public var resumptionToken: String?

    enum CodingKeys: String, CodingKey {
        case wmp, capabilities, security, challenge
        case resumptionToken = "resumption_token"
    }
}

/// WMP session resume parameters.
public struct SessionResumeParams: Codable, Sendable {
    public var wmp: WmpMeta
    public var sessionId: String
    public var resumptionToken: String
    public var lastReceivedId: String?

    public init(
        wmp: WmpMeta,
        sessionId: String,
        resumptionToken: String,
        lastReceivedId: String? = nil
    ) {
        self.wmp = wmp
        self.sessionId = sessionId
        self.resumptionToken = resumptionToken
        self.lastReceivedId = lastReceivedId
    }

    enum CodingKeys: String, CodingKey {
        case wmp
        case sessionId = "session_id"
        case resumptionToken = "resumption_token"
        case lastReceivedId = "last_received_id"
    }
}

/// WMP session resume result.
public struct SessionResumeResult: Codable, Sendable {
    public var wmp: WmpMeta
    public var resumed: Bool
    public var resumptionToken: String?
    public var missedMessages: Int?

    enum CodingKeys: String, CodingKey {
        case wmp, resumed
        case resumptionToken = "resumption_token"
        case missedMessages = "missed_messages"
    }
}

/// WMP session close parameters.
public struct SessionCloseParams: Codable, Sendable {
    public var wmp: WmpMeta
    public var reason: String?

    public init(wmp: WmpMeta, reason: String? = nil) {
        self.wmp = wmp
        self.reason = reason
    }
}

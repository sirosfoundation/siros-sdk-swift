// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// JSON-RPC 2.0 codec for WMP messages.
/// Handles serialization/deserialization and message ID generation.
public final class WmpCodec: Sendable {
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    public init() {
        self.encoder = JSONEncoder()
        self.decoder = JSONDecoder()
    }

    /// Encode a JSON-RPC request. If `id` is nil, generates a UUID.
    /// Pass `id: nil` explicitly (with `omitId: true`) for notifications.
    public func encodeRequest(
        method: String,
        params: [String: AnyCodable]? = nil,
        id: String? = UUID().uuidString,
        omitId: Bool = false
    ) throws -> Data {
        let request = JsonRpcRequest(
            id: omitId ? nil : id,
            method: method,
            params: params
        )
        return try encoder.encode(request)
    }

    /// Encode a JSON-RPC notification (request with no id).
    public func encodeNotification(method: String, params: [String: AnyCodable]? = nil) throws -> Data {
        return try encodeRequest(method: method, params: params, id: nil, omitId: true)
    }

    /// Decode a JSON-RPC response.
    public func decodeResponse(_ data: Data) throws -> JsonRpcResponse {
        return try decoder.decode(JsonRpcResponse.self, from: data)
    }

    /// Decode a JSON-RPC request.
    public func decodeRequest(_ data: Data) throws -> JsonRpcRequest {
        return try decoder.decode(JsonRpcRequest.self, from: data)
    }

    /// Discriminate an incoming message into Request, Notification, or Response.
    public func decodeMessage(_ data: Data) throws -> WmpMessage {
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw WmpCodecError.invalidJSON
        }

        if json["method"] != nil {
            let request = try decoder.decode(JsonRpcRequest.self, from: data)
            if request.id != nil {
                return .request(request)
            } else {
                return .notification(request)
            }
        } else {
            let response = try decoder.decode(JsonRpcResponse.self, from: data)
            return .response(response)
        }
    }

    /// Encode a typed params value into a dictionary for inclusion in a request.
    public func encodeParams<T: Encodable>(_ value: T) throws -> [String: AnyCodable] {
        let data = try encoder.encode(value)
        return try decoder.decode([String: AnyCodable].self, from: data)
    }
}

/// Discriminated union of incoming WMP messages.
public enum WmpMessage: Sendable {
    case request(JsonRpcRequest)
    case notification(JsonRpcRequest)
    case response(JsonRpcResponse)
}

/// Errors from the WMP codec.
public enum WmpCodecError: Error {
    case invalidJSON
}

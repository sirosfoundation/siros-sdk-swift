// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Utilities for handling tagged binary encoding used by the wallet backend.
///
/// Binary data (byte arrays) is encoded in JSON as `{"$b64u": "base64url-string"}`.
/// This is the wire format convention between the frontend/SDK and the Go backend.
public enum TaggedBinary {

    private static let tagKey = "$b64u"

    /// Recursively decode a JSON element, converting any `{"$b64u": "..."}` objects
    /// into plain string values. All other values pass through unchanged.
    public static func decode(_ element: Any) -> Any {
        if let dict = element as? [String: Any] {
            // Check if this is a tagged binary object
            if dict.count == 1, let value = dict[tagKey] as? String {
                return value
            }
            // Regular object — recurse
            return dict.mapValues { decode($0) }
        }
        if let arr = element as? [Any] {
            return arr.map { decode($0) }
        }
        return element
    }

    /// Decode a JSON dictionary, unwrapping tagged binary values.
    public static func decode(_ dict: [String: Any]) -> [String: Any] {
        decode(dict as Any) as? [String: Any] ?? dict
    }

    /// Extract a base64url string from a value that may be either:
    ///  - a plain string: `"dGVzdA"`
    ///  - a tagged binary object: `{"$b64u": "dGVzdA"}`
    public static func extractBase64Url(_ element: Any) -> String? {
        if let str = element as? String {
            return str
        }
        if let dict = element as? [String: Any], let value = dict[tagKey] as? String {
            return value
        }
        return nil
    }
}

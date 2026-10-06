// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Configuration for ``FaceTecIDVProvider``.
public struct FaceTecIDVConfig: Sendable, CustomStringConvertible {
    /// Full URL of facetec-api's process-request endpoint, e.g.
    /// `https://idv.example.com/v1/process-request`.
    public let processRequestUrl: URL
    /// `Authorization` header value for facetec-api (e.g. `"Bearer <token>"`).
    public let authToken: String
    /// FaceTec device key identifier for this app, issued by FaceTec.
    public let deviceKeyIdentifier: String
    /// Refuse to start on a device that cannot read NFC. facetec-api issues
    /// nothing without an authenticated read of the document's chip
    /// (sirosfoundation/facetec-api#65), so a scan on such a device can only
    /// end in a refusal.
    public let requireNfc: Bool
    /// Timeout for each process-request call, in seconds. The calls carry
    /// biometric data and can take a while on FaceTec Server.
    public let requestTimeout: TimeInterval

    public init(
        processRequestUrl: URL,
        authToken: String,
        deviceKeyIdentifier: String,
        requireNfc: Bool = true,
        requestTimeout: TimeInterval = 60
    ) {
        self.processRequestUrl = processRequestUrl
        self.authToken = authToken
        self.deviceKeyIdentifier = deviceKeyIdentifier
        self.requireNfc = requireNfc
        self.requestTimeout = requestTimeout
    }

    /// Leaves ``authToken`` out, so logging a config does not leak the token.
    public var description: String {
        "FaceTecIDVConfig(processRequestUrl: \(processRequestUrl.absoluteString), authToken: <redacted>, "
            + "deviceKeyIdentifier: \(deviceKeyIdentifier), requireNfc: \(requireNfc), "
            + "requestTimeout: \(requestTimeout))"
    }
}

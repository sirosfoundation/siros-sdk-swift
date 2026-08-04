// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Classification of deep-link URIs handled by the wallet.
public enum DeepLinkType: Sendable, Equatable {
    /// WebAuthn/OAuth callback redirect.
    case authCallback(code: String, state: String)
    /// OID4VCI credential offer.
    case credentialOffer(uri: String)
    /// OID4VP presentation request.
    case presentationRequest(uri: String)
    /// Unrecognised link.
    case unknown(uri: String)
}

/// Classifies incoming deep-link URIs.
public enum DeepLinkClassifier {
    /// Classify a deep-link URL string.
    public static func classify(_ urlString: String) -> DeepLinkType {
        guard let components = URLComponents(string: urlString) else {
            return .unknown(uri: urlString)
        }

        let queryItems = components.queryItems ?? []
        func queryValue(_ name: String) -> String? {
            queryItems.first(where: { $0.name == name })?.value
        }

        // Credential offer deep links
        if urlString.hasPrefix("openid-credential-offer://") {
            return .credentialOffer(uri: urlString)
        }
        if queryValue("credential_offer_uri") != nil || queryValue("credential_offer") != nil {
            return .credentialOffer(uri: urlString)
        }

        // Presentation request deep links
        if urlString.hasPrefix("openid4vp://") || urlString.hasPrefix("haip://") {
            return .presentationRequest(uri: urlString)
        }

        // Auth callback — has code + state. Checked before the broader
        // client_id/request_uri heuristic below: an OAuth/OIDC redirect URL
        // commonly carries its own client_id query param, which would
        // otherwise be misclassified as a presentation request and break
        // login.
        if let code = queryValue("code"), let state = queryValue("state") {
            return .authCallback(code: code, state: state)
        }

        if queryValue("request_uri") != nil || queryValue("client_id") != nil {
            return .presentationRequest(uri: urlString)
        }

        return .unknown(uri: urlString)
    }
}

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
    /// Every custom URL scheme the SDK's flows can be started from. A host
    /// app registers these under `CFBundleURLTypes` (plus its own
    /// authorization-callback scheme) and routes `onOpenURL` to
    /// `classify(_:)`. Same set the Kotlin SDK's sample manifest declares.
    public static let credentialOfferSchemes: [String] = ["openid-credential-offer", "haip-vci"]
    public static let presentationRequestSchemes: [String] = ["openid4vp", "mdoc-openid4vp", "haip", "haip-vp"]
    public static var handledSchemes: [String] { credentialOfferSchemes + presentationRequestSchemes }

    /// Classify a deep-link URL string.
    public static func classify(_ urlString: String) -> DeepLinkType {
        guard let components = URLComponents(string: urlString) else {
            return .unknown(uri: urlString)
        }

        let queryItems = components.queryItems ?? []
        func queryValue(_ name: String) -> String? {
            queryItems.first(where: { $0.name == name })?.value
        }

        let scheme = components.scheme?.lowercased()

        // Credential offer deep links
        if let scheme, credentialOfferSchemes.contains(scheme) {
            return .credentialOffer(uri: urlString)
        }
        if queryValue("credential_offer_uri") != nil || queryValue("credential_offer") != nil {
            return .credentialOffer(uri: urlString)
        }

        // Presentation request deep links
        if let scheme, presentationRequestSchemes.contains(scheme) {
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

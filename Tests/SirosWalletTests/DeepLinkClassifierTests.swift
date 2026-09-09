// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosWallet

final class DeepLinkClassifierTests: XCTestCase {

    func testCredentialOfferScheme() {
        let result = DeepLinkClassifier.classify("openid-credential-offer://?credential_offer=%7B%7D")
        if case .credentialOffer(let uri) = result {
            XCTAssertTrue(uri.hasPrefix("openid-credential-offer://"))
        } else {
            XCTFail("Expected .credentialOffer, got \(result)")
        }
    }

    func testCredentialOfferViaQueryParam() {
        let result = DeepLinkClassifier.classify("https://wallet.example.com/offer?credential_offer_uri=https://issuer.example.com/offer/123")
        if case .credentialOffer = result {
            // expected
        } else {
            XCTFail("Expected .credentialOffer, got \(result)")
        }
    }

    func testPresentationRequestOpenid4vp() {
        let result = DeepLinkClassifier.classify("openid4vp://?request_uri=https://verifier.example.com/request/abc")
        if case .presentationRequest(let uri) = result {
            XCTAssertTrue(uri.hasPrefix("openid4vp://"))
        } else {
            XCTFail("Expected .presentationRequest, got \(result)")
        }
    }

    func testPresentationRequestHaip() {
        let result = DeepLinkClassifier.classify("haip://?request_uri=https://verifier.example.com/req")
        if case .presentationRequest = result {
            // expected
        } else {
            XCTFail("Expected .presentationRequest, got \(result)")
        }
    }

    /// The schemes the Kotlin SDK's sample manifest also declares. Without
    /// an explicit rule these fell through to the query heuristics, so a
    /// bare `mdoc-openid4vp://` or `haip-vp://` link with no recognisable
    /// query was `.unknown`, and `haip-vci://` depended on the offer being
    /// passed by value or URI rather than on the scheme saying what it is.
    func testEveryHandledSchemeClassifiesBySchemeAlone() {
        for scheme in DeepLinkClassifier.presentationRequestSchemes {
            guard case .presentationRequest = DeepLinkClassifier.classify("\(scheme)://") else {
                return XCTFail("\(scheme):// must classify as a presentation request")
            }
        }
        for scheme in DeepLinkClassifier.credentialOfferSchemes {
            guard case .credentialOffer = DeepLinkClassifier.classify("\(scheme)://") else {
                return XCTFail("\(scheme):// must classify as a credential offer")
            }
        }
        XCTAssertEqual(
            Set(DeepLinkClassifier.handledSchemes),
            ["openid-credential-offer", "haip-vci", "openid4vp", "mdoc-openid4vp", "haip", "haip-vp"]
        )
        // Scheme matching is case-insensitive, as URL schemes are.
        guard case .presentationRequest = DeepLinkClassifier.classify("OPENID4VP://?request_uri=x") else {
            return XCTFail("scheme comparison must be case-insensitive")
        }
    }

    func testPresentationRequestViaRequestUri() {
        let result = DeepLinkClassifier.classify("https://wallet.example.com/present?request_uri=https://verifier.example.com/req")
        if case .presentationRequest = result {
            // expected
        } else {
            XCTFail("Expected .presentationRequest, got \(result)")
        }
    }

    /// A bare `client_id` (no `request_uri`) is how an unsigned-request-object
    /// cross-device link can arrive - the verifier passes the request params
    /// directly rather than by reference.
    func testPresentationRequestViaClientIdOnly() {
        let result = DeepLinkClassifier.classify("https://wallet.example.com/present?client_id=https://verifier.example.com&response_uri=https://verifier.example.com/cb")
        if case .presentationRequest = result {
            // expected
        } else {
            XCTFail("Expected .presentationRequest, got \(result)")
        }
    }

    func testAuthCallback() {
        let result = DeepLinkClassifier.classify("https://wallet.example.com/callback?code=abc&state=xyz")
        if case .authCallback(let code, let state) = result {
            XCTAssertEqual(code, "abc")
            XCTAssertEqual(state, "xyz")
        } else {
            XCTFail("Expected .authCallback, got \(result)")
        }
    }

    /// Regression test for a real Copilot-review finding: an OAuth/OIDC
    /// redirect commonly carries its own `client_id` query param alongside
    /// `code`/`state` - the auth-callback check must win, or every login
    /// using such a provider gets misclassified as a presentation request.
    func testAuthCallbackWinsOverClientIdHeuristic() {
        let result = DeepLinkClassifier.classify(
            "https://wallet.example.com/callback?client_id=my-wallet&code=abc&state=xyz"
        )
        if case .authCallback(let code, let state) = result {
            XCTAssertEqual(code, "abc")
            XCTAssertEqual(state, "xyz")
        } else {
            XCTFail("Expected .authCallback, got \(result)")
        }
    }

    func testUnknownLink() {
        let result = DeepLinkClassifier.classify("https://example.com/")
        if case .unknown = result {
            // expected
        } else {
            XCTFail("Expected .unknown, got \(result)")
        }
    }

    func testEmptyString() {
        let result = DeepLinkClassifier.classify("")
        if case .unknown = result {
            // expected
        } else {
            XCTFail("Expected .unknown, got \(result)")
        }
    }
}

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

    func testPresentationRequestViaRequestUri() {
        let result = DeepLinkClassifier.classify("https://wallet.example.com/present?request_uri=https://verifier.example.com/req")
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

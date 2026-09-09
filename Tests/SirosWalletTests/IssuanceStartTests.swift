// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosWallet

final class IssuanceStartTests: XCTestCase {

    private let offerJson = #"{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"]}"#

    func testInlineOfferIsUnpackedWhateverTheScheme() {
        let encoded = offerJson.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        for scheme in ["openid-credential-offer", "haip-vci", "OPENID-CREDENTIAL-OFFER", "https"] {
            XCTAssertEqual(
                IssuanceStart.resolve(offerUri: "\(scheme)://?credential_offer=\(encoded)"),
                .offer(offerJson),
                scheme
            )
        }
    }

    func testOfferByReferenceIsFetchedWhateverTheScheme() {
        for scheme in ["openid-credential-offer", "haip-vci", "https"] {
            XCTAssertEqual(
                IssuanceStart.resolve(offerUri: "\(scheme)://issuer.example/wallet?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2F1"),
                .credentialOfferUri("https://issuer.example/offers/1"),
                scheme
            )
        }
    }

    func testAPlainHttpsUriIsTheOfferUriItself() {
        XCTAssertEqual(IssuanceStart.resolve(offerUri: "https://issuer.example/offers/1"), .credentialOfferUri("https://issuer.example/offers/1"))
    }

    func testAnythingElseIsLeftForTheEngine() {
        XCTAssertEqual(IssuanceStart.resolve(offerUri: offerJson), .offer(offerJson))
        XCTAssertEqual(IssuanceStart.resolve(offerUri: "openid-credential-offer://"), .offer("openid-credential-offer://"))
    }

    func testCredentialOfferWinsOverCredentialOfferUri() {
        XCTAssertEqual(
            IssuanceStart.resolve(offerUri: "haip-vci://?credential_offer_uri=https%3A%2F%2Fx&credential_offer=%7B%7D"),
            .offer("{}")
        )
    }
}

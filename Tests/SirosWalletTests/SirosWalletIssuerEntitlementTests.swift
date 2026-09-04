// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosAuth
import SirosCredentials
@testable import SirosWallet

// `SirosWallet.init` requires a real `JweKeystore`, only available where
// CryptoKit is (Apple platforms / CI macOS runner) - matching this test
// target's existing `#if canImport(CryptoKit)` convention. The wire-format
// half of this feature is covered on every platform by
// `SirosCredentialsTests/IssuerEntitlementDecodingTests`.
#if canImport(CryptoKit)

private final class StubAuthProvider: AuthProvider, @unchecked Sendable {
    struct NotImplemented: Error {}
    func register(options: RegisterOptions) async throws -> RegisterResult { throw NotImplemented() }
    func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw NotImplemented() }
    func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw NotImplemented() }
}

/// ARF v3.0.0 section 6.6.2.3: the backend decides whether a PID or
/// attestation provider is registered to issue what it offers, and the wallet
/// has to act on that decision rather than merely display it.
///
/// These pin the three states apart, because collapsing any two of them is the
/// failure mode that matters: refused, allowed-with-findings (warn mode), and
/// not checked at all. Mirrors the Kotlin SDK's `IssuerEntitlementTest`.
final class SirosWalletIssuerEntitlementTests: XCTestCase {

    private let issuer = "https://issuer.example.com"

    private func makeWallet() -> SirosWallet {
        let config = WalletConfig(backendUrl: "https://example.invalid")
        let wallet = SirosWallet(config: config, authProvider: StubAuthProvider())
        XCTAssertNotNil(wallet, "wallet should initialise with default keystore on CryptoKit platforms")
        return wallet!
    }

    func testRefusesIssuanceWhenTheProviderIsNotEntitled() {
        let wallet = makeWallet()
        let entitlement = IssuerEntitlement(
            allowed: false,
            mode: "fail",
            evaluated: true,
            findings: [
                IssuerEntitlementFinding(
                    code: "attestation_type_not_registered",
                    message: "provider is not registered to issue dc+sd-jwt",
                    credentialType: "eu.europa.ec.eudi.pid.1"
                )
            ]
        )

        XCTAssertThrowsError(
            try wallet.enforceIssuerEntitlement(issuerUrl: issuer, entitlement: entitlement)
        ) { error in
            // The reason has to survive into the message: a bare "not allowed"
            // leaves a user with no way to tell a misconfigured issuer from a
            // genuinely unregistered one.
            XCTAssertTrue(
                "\(error)".contains("attestation_type_not_registered"),
                "error should name the finding, was: \(error)"
            )
        }
    }

    func testAllowsIssuanceInWarnModeEvenWithFindings() throws {
        // Warn is the default until the ARF's 24-month registration obligation
        // bites. Findings are reported; issuance still proceeds.
        let wallet = makeWallet()
        let entitlement = IssuerEntitlement(
            allowed: true,
            mode: "warn",
            evaluated: true,
            findings: [
                IssuerEntitlementFinding(
                    code: "no_registration_certificate",
                    message: "issuer metadata carries no registration certificate in issuer_info"
                )
            ]
        )
        XCTAssertNoThrow(try wallet.enforceIssuerEntitlement(issuerUrl: issuer, entitlement: entitlement))
    }

    func testAllowsIssuanceWhenTheCheckDidNotRun() {
        // A nil entitlement means "not checked" - the backend was absent or
        // unreachable. That must not block issuance, and equally must never be
        // recorded anywhere as a pass.
        let wallet = makeWallet()
        XCTAssertNoThrow(try wallet.enforceIssuerEntitlement(issuerUrl: issuer, entitlement: nil))
    }

    func testEntitlementForAConfigurationIsNilWhenResolutionFails() async {
        // No authenticated session and an unreachable issuer: resolution cannot
        // run at all. The helper has to absorb that, or a backend outage
        // becomes an outage for every issuer.
        let wallet = makeWallet()
        let result = await wallet.issuerEntitlementFor(
            issuerUrl: "https://issuer.invalid",
            configurationId: "eu.europa.ec.eudi.pid.1"
        )
        XCTAssertNil(result)
    }

    func testResolvedMetadataDefaultsToNotChecked() {
        // The direct-fetch fallback constructs this with metadata only. If the
        // default were anything but nil, an unauthenticated fetch would read
        // downstream as an evaluated pass.
        let resolved = SirosWallet.ResolvedIssuerMetadata(
            metadata: IssuerMetadata(credentialIssuer: issuer)
        )
        XCTAssertNil(resolved.entitlement)
        XCTAssertNil(resolved.trusted)
        XCTAssertEqual(resolved.metadata.credentialIssuer, issuer)
    }
}

#endif

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosWallet

/// The same openssl-generated fixtures the Kotlin SDK's
/// `MdocIssuerIdentityTest` uses (sdk/wallet/src/test/resources/
/// mdoc-issuer-identity/*.pem there), inlined as base64 DER here. Pure
/// Swift, so this runs on Linux CI as well.
final class MdocIssuerIdentityTests: XCTestCase {

    // SAN = DNS:localhost, DNS:vc-issuer, URI:https://issuer.example/tenant
    private let uriAndDns = "MIIB9TCCAZugAwIBAgIUc80Zc4cLM+WPQjLSyPL7OMI3+cgwCgYIKoZIzj0EAwIwLzEXMBUGA1UECgwORml4dHVyZSBJc3N1ZXIxFDASBgNVBAMMC3VyaV9hbmRfZG5zMB4XDTI2MDkwODEyMzczOFoXDTM2MDkwNTEyMzczOFowLzEXMBUGA1UECgwORml4dHVyZSBJc3N1ZXIxFDASBgNVBAMMC3VyaV9hbmRfZG5zMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWoK0HJW6uuWJAiv9G9wXEGuFP3tLEK/grFOUulXBNc3KcLQO4+zxGs72RqU2k/+XtuLlcEMInF2nurcqyC7Gc6OBlDCBkTAdBgNVHQ4EFgQU4/mpLeZz2FTKNEZygy4n2kC2tiAwHwYDVR0jBBgwFoAU4/mpLeZz2FTKNEZygy4n2kC2tiAwDwYDVR0TAQH/BAUwAwEB/zA+BgNVHREENzA1gglsb2NhbGhvc3SCCXZjLWlzc3VlcoYdaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS90ZW5hbnQwCgYIKoZIzj0EAwIDSAAwRQIgKFHtD1d6Y8d33hIX1t2kxofuHdQjRTfB2I3UR5Gq4nACIQCV4HM2cilF7m4QRHfpgzKJROX6VJh5IVMuSnEU76JrkQ=="
    // SAN = URI:http://issuer.example, DNS:localhost
    private let httpUri = "MIIB2zCCAYGgAwIBAgIUMbcQ1oeG7XtuFBrQZ3S+5ASUviswCgYIKoZIzj0EAwIwLDEXMBUGA1UECgwORml4dHVyZSBJc3N1ZXIxETAPBgNVBAMMCGh0dHBfdXJpMB4XDTI2MDkwODEyMzczOFoXDTM2MDkwNTEyMzczOFowLDEXMBUGA1UECgwORml4dHVyZSBJc3N1ZXIxETAPBgNVBAMMCGh0dHBfdXJpMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWoK0HJW6uuWJAiv9G9wXEGuFP3tLEK/grFOUulXBNc3KcLQO4+zxGs72RqU2k/+XtuLlcEMInF2nurcqyC7Gc6OBgDB+MB0GA1UdDgQWBBTj+akt5nPYVMo0RnKDLifaQLa2IDAfBgNVHSMEGDAWgBTj+akt5nPYVMo0RnKDLifaQLa2IDAPBgNVHRMBAf8EBTADAQH/MCsGA1UdEQQkMCKGFWh0dHA6Ly9pc3N1ZXIuZXhhbXBsZYIJbG9jYWxob3N0MAoGCCqGSM49BAMCA0gAMEUCIAPNLM+bKLDo1la4parzew78N+3RvciortWxu72RpQ5IAiEAzZ/bqxStk2yv4bZ4H7n3GxUfnDhZTpC8Vp3SUY1ziAg="
    // SAN = DNS:*.example.org, DNS:issuer.example.org
    private let dnsOnly = "MIIB3DCCAYKgAwIBAgIUdrAPSFpxJ10hoChpRZXk6iBs5BowCgYIKoZIzj0EAwIwLDEXMBUGA1UECgwORml4dHVyZSBJc3N1ZXIxETAPBgNVBAMMCGRuc19vbmx5MB4XDTI2MDkwODEyMzczOFoXDTM2MDkwNTEyMzczOFowLDEXMBUGA1UECgwORml4dHVyZSBJc3N1ZXIxETAPBgNVBAMMCGRuc19vbmx5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWoK0HJW6uuWJAiv9G9wXEGuFP3tLEK/grFOUulXBNc3KcLQO4+zxGs72RqU2k/+XtuLlcEMInF2nurcqyC7Gc6OBgTB/MB0GA1UdDgQWBBTj+akt5nPYVMo0RnKDLifaQLa2IDAfBgNVHSMEGDAWgBTj+akt5nPYVMo0RnKDLifaQLa2IDAPBgNVHRMBAf8EBTADAQH/MCwGA1UdEQQlMCOCDSouZXhhbXBsZS5vcmeCEmlzc3Vlci5leGFtcGxlLm9yZzAKBggqhkjOPQQDAgNIADBFAiAvfFpdmYfFsGdnuDOnRgQT7x9NQsrJcwkoE5ApyhtibAIhALC4XE4jkCRm2rQlQo4H/GSPOlJLJjE+W3lLPvlzRhR8"
    // SAN = DNS:*.example.org
    private let wildcardOnly = "MIIB0DCCAXegAwIBAgIUHwM3rm2fRJL+U1yikt21YIDSGpQwCgYIKoZIzj0EAwIwMTEXMBUGA1UECgwORml4dHVyZSBJc3N1ZXIxFjAUBgNVBAMMDXdpbGRjYXJkX29ubHkwHhcNMjYwOTA4MTIzNzM4WhcNMzYwOTA1MTIzNzM4WjAxMRcwFQYDVQQKDA5GaXh0dXJlIElzc3VlcjEWMBQGA1UEAwwNd2lsZGNhcmRfb25seTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFqCtByVurrliQIr/RvcFxBrhT97SxCv4KxTlLpVwTXNynC0DuPs8RrO9kalNpP/l7bi5XBDCJxdp7q3KsguxnOjbTBrMB0GA1UdDgQWBBTj+akt5nPYVMo0RnKDLifaQLa2IDAfBgNVHSMEGDAWgBTj+akt5nPYVMo0RnKDLifaQLa2IDAPBgNVHRMBAf8EBTADAQH/MBgGA1UdEQQRMA+CDSouZXhhbXBsZS5vcmcwCgYIKoZIzj0EAwIDRwAwRAIgeDDtlO+mh0QM5M9MI+rgXTifcqf2pgjeS/HMfA3O0GgCICvMm2tEXoGYwx/RoKs5DP5daEJPqlLd5HXqv4+cfjRp"
    // No subjectAltName extension (but other extensions present).
    private let noSan = "MIIBqTCCAU+gAwIBAgIUEX8yqwQMLvus3D68o4L0H4HnuRQwCgYIKoZIzj0EAwIwKjEXMBUGA1UECgwORml4dHVyZSBJc3N1ZXIxDzANBgNVBAMMBm5vX3NhbjAeFw0yNjA5MDgxMjM3MzhaFw0zNjA5MDUxMjM3MzhaMCoxFzAVBgNVBAoMDkZpeHR1cmUgSXNzdWVyMQ8wDQYDVQQDDAZub19zYW4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARagrQclbq65YkCK/0b3BcQa4U/e0sQr+CsU5S6VcE1zcpwtA7j7PEazvZGpTaT/5e24uVwQwicXae6tyrILsZzo1MwUTAdBgNVHQ4EFgQU4/mpLeZz2FTKNEZygy4n2kC2tiAwHwYDVR0jBBgwFoAU4/mpLeZz2FTKNEZygy4n2kC2tiAwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiAnvhPbQctSiszn17jFX8dIf7JuHlvv8HwXwFjGgaqSlAIhAMfRMEOKqRcOc+AmahYfx8fTuV86fPwynEJ2NC8pLnRh"

    private func der(_ b64: String) -> [UInt8] { [UInt8](Data(base64Encoded: b64)!) }

    func testAnHttpsUriSanWinsOverDnsSansWhateverTheirOrder() {
        // The sirosid-dev signing-certificate shape since sirosid-dev#39.
        // A first-DNS-SAN rule gives "https://localhost" here, which is
        // exactly what made every deployed mDL look untrusted.
        XCTAssertEqual(MdocIssuerIdentity.fromDer(der(uriAndDns)), "https://issuer.example/tenant")
    }

    func testAnHttpUriSanIsLiftedToHttps() {
        XCTAssertEqual(MdocIssuerIdentity.fromDer(der(httpUri)), "https://issuer.example")
    }

    func testWithoutAUriSanTheFirstNonWildcardDnsSanNamesTheIssuer() {
        XCTAssertEqual(MdocIssuerIdentity.fromDer(der(dnsOnly)), "https://issuer.example.org")
    }

    func testAWildcardDnsSanAloneNamesNothing() {
        XCTAssertNil(MdocIssuerIdentity.fromDer(der(wildcardOnly)))
    }

    func testNoSanExtensionNamesNothing() {
        XCTAssertNil(MdocIssuerIdentity.fromDer(der(noSan)))
        XCTAssertEqual(MdocIssuerIdentity.subjectAlternativeNames(der(noSan)), .init(), "parses, just has no such extension")
    }

    func testTheRawNamesAreReadInCertificateOrder() {
        XCTAssertEqual(
            MdocIssuerIdentity.subjectAlternativeNames(der(uriAndDns)),
            .init(uris: ["https://issuer.example/tenant"], dnsNames: ["localhost", "vc-issuer"])
        )
    }

    func testGarbageAndTruncatedDerNameNothingAndDoNotTrap() {
        XCTAssertNil(MdocIssuerIdentity.fromDer([]))
        XCTAssertNil(MdocIssuerIdentity.fromDer([0x30, 0x03, 0x02, 0x01, 0x01]))
        XCTAssertNil(MdocIssuerIdentity.fromDer([0x30, 0x82, 0xFF, 0xFF, 0x30]), "declared length past the end")
        let whole = der(uriAndDns)
        XCTAssertNil(MdocIssuerIdentity.fromDer(Array(whole[0..<(whole.count / 2)])))
    }
}

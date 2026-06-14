import XCTest
@testable import SirosKeystoreTests

fileprivate extension Base64UrlTests {
    @available(*, deprecated, message: "Not actually deprecated. Marked as deprecated to allow inclusion of deprecated tests (which test deprecated functionality) without warnings")
    static nonisolated(unsafe) let __allTests__Base64UrlTests = [
        ("testBase64UrlDecodeEmpty", testBase64UrlDecodeEmpty),
        ("testBase64UrlDecodeWithPadding", testBase64UrlDecodeWithPadding),
        ("testBase64UrlNoPadding", testBase64UrlNoPadding),
        ("testBase64UrlNoSlash", testBase64UrlNoSlash),
        ("testBase64UrlRoundTrip", testBase64UrlRoundTrip)
    ]
}

fileprivate extension ContainerTypesTests {
    @available(*, deprecated, message: "Not actually deprecated. Marked as deprecated to allow inclusion of deprecated tests (which test deprecated functionality) without warnings")
    static nonisolated(unsafe) let __allTests__ContainerTypesTests = [
        ("testContainerDataInit", testContainerDataInit),
        ("testKeyInfoEquality", testKeyInfoEquality),
        ("testKeystoreErrorCases", testKeystoreErrorCases)
    ]
}

fileprivate extension EncryptedContainerTests {
    @available(*, deprecated, message: "Not actually deprecated. Marked as deprecated to allow inclusion of deprecated tests (which test deprecated functionality) without warnings")
    static nonisolated(unsafe) let __allTests__EncryptedContainerTests = [
        ("testBinaryFieldDecodingBase64Url", testBinaryFieldDecodingBase64Url),
        ("testParseInvalidJsonThrows", testParseInvalidJsonThrows),
        ("testParseMissingJweThrows", testParseMissingJweThrows),
        ("testSerializeAndParseRoundTrip", testSerializeAndParseRoundTrip)
    ]
}

fileprivate extension JweKeystoreTests {
    @available(*, deprecated, message: "Not actually deprecated. Marked as deprecated to allow inclusion of deprecated tests (which test deprecated functionality) without warnings")
    static nonisolated(unsafe) let __allTests__JweKeystoreTests = [
        ("testCryptoKitUnavailable", testCryptoKitUnavailable)
    ]
}
@available(*, deprecated, message: "Not actually deprecated. Marked as deprecated to allow inclusion of deprecated tests (which test deprecated functionality) without warnings")
func __SirosKeystoreTests__allTests() -> [XCTestCaseEntry] {
    return [
        testCase(Base64UrlTests.__allTests__Base64UrlTests),
        testCase(ContainerTypesTests.__allTests__ContainerTypesTests),
        testCase(EncryptedContainerTests.__allTests__EncryptedContainerTests),
        testCase(JweKeystoreTests.__allTests__JweKeystoreTests)
    ]
}
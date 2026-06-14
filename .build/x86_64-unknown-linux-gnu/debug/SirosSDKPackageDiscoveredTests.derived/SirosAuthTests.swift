import XCTest
@testable import SirosAuthTests

fileprivate extension AuthTypesTests {
    @available(*, deprecated, message: "Not actually deprecated. Marked as deprecated to allow inclusion of deprecated tests (which test deprecated functionality) without warnings")
    static nonisolated(unsafe) let __allTests__AuthTypesTests = [
        ("testAuthSessionCodable", testAuthSessionCodable),
        ("testAuthSessionDecodesFromJson", testAuthSessionDecodesFromJson),
        ("testAuthSessionEquality", testAuthSessionEquality),
        ("testAuthenticateOptionsDefaults", testAuthenticateOptionsDefaults),
        ("testBase64UrlRoundTrip", testBase64UrlRoundTrip),
        ("testRegisterOptionsDefaults", testRegisterOptionsDefaults)
    ]
}

fileprivate extension BackendApiClientTests {
    @available(*, deprecated, message: "Not actually deprecated. Marked as deprecated to allow inclusion of deprecated tests (which test deprecated functionality) without warnings")
    static nonisolated(unsafe) let __allTests__BackendApiClientTests = [
        ("testBlankSuccessBodyReturnsEmptyJsonObject", asyncTest(testBlankSuccessBodyReturnsEmptyJsonObject)),
        ("testDeleteCredentialUsesDeleteMethod", asyncTest(testDeleteCredentialUsesDeleteMethod)),
        ("testEvaluateTrustPostsToExpectedEndpoint", asyncTest(testEvaluateTrustPostsToExpectedEndpoint)),
        ("testGetAccountInfoSendsExpectedHeaders", asyncTest(testGetAccountInfoSendsExpectedHeaders)),
        ("testGetIssuersAcceptsArrayPayload", asyncTest(testGetIssuersAcceptsArrayPayload)),
        ("testRefreshSessionPostsRefreshToken", asyncTest(testRefreshSessionPostsRefreshToken)),
        ("testTenantConfigUsesTenantSpecificPath", asyncTest(testTenantConfigUsesTenantSpecificPath)),
        ("testUnauthenticatedRequestOmitsAuthorizationHeader", asyncTest(testUnauthenticatedRequestOmitsAuthorizationHeader)),
        ("testUpdatePrivateDataPostsJsonBody", asyncTest(testUpdatePrivateDataPostsJsonBody))
    ]
}

fileprivate extension TaggedBinaryTests {
    @available(*, deprecated, message: "Not actually deprecated. Marked as deprecated to allow inclusion of deprecated tests (which test deprecated functionality) without warnings")
    static nonisolated(unsafe) let __allTests__TaggedBinaryTests = [
        ("testDecodePassesThroughNonTaggedObjects", testDecodePassesThroughNonTaggedObjects),
        ("testDecodeUnwrapsTaggedBinaryRecursively", testDecodeUnwrapsTaggedBinaryRecursively),
        ("testExtractBase64UrlFromPlainString", testExtractBase64UrlFromPlainString),
        ("testExtractBase64UrlFromTaggedObject", testExtractBase64UrlFromTaggedObject),
        ("testExtractBase64UrlReturnsNilForInvalid", testExtractBase64UrlReturnsNilForInvalid)
    ]
}

fileprivate extension WebAuthnAuthClientTests {
    @available(*, deprecated, message: "Not actually deprecated. Marked as deprecated to allow inclusion of deprecated tests (which test deprecated functionality) without warnings")
    static nonisolated(unsafe) let __allTests__WebAuthnAuthClientTests = [
        ("testLoginCallsBeginAndFinishAndReturnsSession", asyncTest(testLoginCallsBeginAndFinishAndReturnsSession)),
        ("testLoginThrowsWhenRpIdMissing", asyncTest(testLoginThrowsWhenRpIdMissing)),
        ("testLoginWithUserHandle", asyncTest(testLoginWithUserHandle)),
        ("testRegisterCallsBeginAndFinishAndReturnsSession", asyncTest(testRegisterCallsBeginAndFinishAndReturnsSession)),
        ("testRegisterThrowsWhenPublicKeyMissing", asyncTest(testRegisterThrowsWhenPublicKeyMissing)),
        ("testRegisterUsesPublicKeyFallback", asyncTest(testRegisterUsesPublicKeyFallback)),
        ("testTaggedBinaryDecodingInChallenge", asyncTest(testTaggedBinaryDecodingInChallenge))
    ]
}
@available(*, deprecated, message: "Not actually deprecated. Marked as deprecated to allow inclusion of deprecated tests (which test deprecated functionality) without warnings")
func __SirosAuthTests__allTests() -> [XCTestCaseEntry] {
    return [
        testCase(AuthTypesTests.__allTests__AuthTypesTests),
        testCase(BackendApiClientTests.__allTests__BackendApiClientTests),
        testCase(TaggedBinaryTests.__allTests__TaggedBinaryTests),
        testCase(WebAuthnAuthClientTests.__allTests__WebAuthnAuthClientTests)
    ]
}
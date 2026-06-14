import XCTest
@testable import SirosCredentialsTests

fileprivate extension CredentialMatcherTests {
    @available(*, deprecated, message: "Not actually deprecated. Marked as deprecated to allow inclusion of deprecated tests (which test deprecated functionality) without warnings")
    static nonisolated(unsafe) let __allTests__CredentialMatcherTests = [
        ("testFindSatisfiableOptions", testFindSatisfiableOptions),
        ("testMatchDcqlReturnsFullOutputWithCredentialSets", testMatchDcqlReturnsFullOutputWithCredentialSets),
        ("testMatchExcludesCredentialsWithoutRequiredMetadata", testMatchExcludesCredentialsWithoutRequiredMetadata),
        ("testMatchFiltersByDoctypeForMdoc", testMatchFiltersByDoctypeForMdoc),
        ("testMatchFiltersByFormatAndVct", testMatchFiltersByFormatAndVct),
        ("testMatchReturnsAllWhenQueryHasNoCredentialsArray", testMatchReturnsAllWhenQueryHasNoCredentialsArray),
        ("testMatchSkipsQueriesWithoutId", testMatchSkipsQueriesWithoutId),
        ("testMatchedCredentialIdsAreDistinct", testMatchedCredentialIdsAreDistinct),
        ("testParseCredentialSetsParsesRequiredAndOptional", testParseCredentialSetsParsesRequiredAndOptional),
        ("testParseCredentialSetsReturnsNilWhenAbsent", testParseCredentialSetsReturnsNilWhenAbsent)
    ]
}

fileprivate extension CredentialUtilsTests {
    @available(*, deprecated, message: "Not actually deprecated. Marked as deprecated to allow inclusion of deprecated tests (which test deprecated functionality) without warnings")
    static nonisolated(unsafe) let __allTests__CredentialUtilsTests = [
        ("testBuildMetadataCombinesOfferAndVctm", testBuildMetadataCombinesOfferAndVctm),
        ("testBuildMetadataFallsBackToOfferWhenNoVctm", testBuildMetadataFallsBackToOfferWhenNoVctm),
        ("testExtractClaimsFormatsKeysWhenNoVctm", testExtractClaimsFormatsKeysWhenNoVctm),
        ("testExtractClaimsReturnsEmptyForUnparseableCredential", testExtractClaimsReturnsEmptyForUnparseableCredential),
        ("testExtractClaimsReturnsUserFacingClaims", testExtractClaimsReturnsUserFacingClaims),
        ("testExtractClaimsUsesVctmLabels", testExtractClaimsUsesVctmLabels),
        ("testFormatClaimKey", testFormatClaimKey),
        ("testParseJwtPayloadExtractsPayload", testParseJwtPayloadExtractsPayload),
        ("testParseJwtPayloadHandlesSdJwtWithDisclosures", testParseJwtPayloadHandlesSdJwtWithDisclosures),
        ("testParseJwtPayloadReturnsNilForInvalidInput", testParseJwtPayloadReturnsNilForInvalidInput),
        ("testParseJwtPayloadReturnsNilForMalformedBase64", testParseJwtPayloadReturnsNilForMalformedBase64)
    ]
}

fileprivate extension InMemoryCredentialStoreTests {
    @available(*, deprecated, message: "Not actually deprecated. Marked as deprecated to allow inclusion of deprecated tests (which test deprecated functionality) without warnings")
    static nonisolated(unsafe) let __allTests__InMemoryCredentialStoreTests = [
        ("testClearRemovesAllCredentials", asyncTest(testClearRemovesAllCredentials)),
        ("testDeleteRemovesCredential", asyncTest(testDeleteRemovesCredential)),
        ("testGetAllReturnsAllSavedCredentials", asyncTest(testGetAllReturnsAllSavedCredentials)),
        ("testSaveAndGetById", asyncTest(testSaveAndGetById)),
        ("testUpdateReplacesExistingCredential", asyncTest(testUpdateReplacesExistingCredential))
    ]
}

fileprivate extension VctmFetcherTests {
    @available(*, deprecated, message: "Not actually deprecated. Marked as deprecated to allow inclusion of deprecated tests (which test deprecated functionality) without warnings")
    static nonisolated(unsafe) let __allTests__VctmFetcherTests = [
        ("testFetchFallsBackToWellKnownUrl", asyncTest(testFetchFallsBackToWellKnownUrl)),
        ("testFetchFromTypeMetadataEndpoint", asyncTest(testFetchFromTypeMetadataEndpoint)),
        ("testFetchReturnsNilForInvalidVctUrl", asyncTest(testFetchReturnsNilForInvalidVctUrl)),
        ("testFetchReturnsNilWhenBothFail", asyncTest(testFetchReturnsNilWhenBothFail)),
        ("testFetchReturnsNilWhenNoVctProvided", asyncTest(testFetchReturnsNilWhenNoVctProvided)),
        ("testFetchTrimsTrailingSlashFromIssuerUrl", asyncTest(testFetchTrimsTrailingSlashFromIssuerUrl)),
        ("testParseVctmParsesValidJson", testParseVctmParsesValidJson),
        ("testParseVctmReturnsNilForInvalidJson", testParseVctmReturnsNilForInvalidJson)
    ]
}
@available(*, deprecated, message: "Not actually deprecated. Marked as deprecated to allow inclusion of deprecated tests (which test deprecated functionality) without warnings")
func __SirosCredentialsTests__allTests() -> [XCTestCaseEntry] {
    return [
        testCase(CredentialMatcherTests.__allTests__CredentialMatcherTests),
        testCase(CredentialUtilsTests.__allTests__CredentialUtilsTests),
        testCase(InMemoryCredentialStoreTests.__allTests__InMemoryCredentialStoreTests),
        testCase(VctmFetcherTests.__allTests__VctmFetcherTests)
    ]
}
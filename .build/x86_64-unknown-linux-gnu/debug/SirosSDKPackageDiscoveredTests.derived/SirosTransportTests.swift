import XCTest
@testable import SirosTransportTests

fileprivate extension AnyCodableTests {
    @available(*, deprecated, message: "Not actually deprecated. Marked as deprecated to allow inclusion of deprecated tests (which test deprecated functionality) without warnings")
    static nonisolated(unsafe) let __allTests__AnyCodableTests = [
        ("testArrayRoundTrip", testArrayRoundTrip),
        ("testBoolRoundTrip", testBoolRoundTrip),
        ("testIntRoundTrip", testIntRoundTrip),
        ("testNestedJsonDecoding", testNestedJsonDecoding),
        ("testNullRoundTrip", testNullRoundTrip),
        ("testObjectRoundTrip", testObjectRoundTrip),
        ("testStringRoundTrip", testStringRoundTrip)
    ]
}

fileprivate extension EngineTypesTests {
    @available(*, deprecated, message: "Not actually deprecated. Marked as deprecated to allow inclusion of deprecated tests (which test deprecated functionality) without warnings")
    static nonisolated(unsafe) let __allTests__EngineTypesTests = [
        ("testErrorMessageDecoding", testErrorMessageDecoding),
        ("testFlowActionEncoding", testFlowActionEncoding),
        ("testFlowCompleteDecoding", testFlowCompleteDecoding),
        ("testFlowErrorDecoding", testFlowErrorDecoding),
        ("testFlowProgressDecoding", testFlowProgressDecoding),
        ("testFlowStartIssuanceEncoding", testFlowStartIssuanceEncoding),
        ("testFlowStartPresentationEncoding", testFlowStartPresentationEncoding),
        ("testHandshakeCompleteDecoding", testHandshakeCompleteDecoding),
        ("testHandshakeMessageEncoding", testHandshakeMessageEncoding),
        ("testMatchRequestDecoding", testMatchRequestDecoding),
        ("testMatchResponseEncoding", testMatchResponseEncoding),
        ("testPushMessageDecoding", testPushMessageDecoding),
        ("testSignRequestDecoding", testSignRequestDecoding),
        ("testSignResponseEncoding", testSignResponseEncoding)
    ]
}

fileprivate extension WmpCodecTests {
    @available(*, deprecated, message: "Not actually deprecated. Marked as deprecated to allow inclusion of deprecated tests (which test deprecated functionality) without warnings")
    static nonisolated(unsafe) let __allTests__WmpCodecTests = [
        ("testDecodeMessageIdentifiesNotification", testDecodeMessageIdentifiesNotification),
        ("testDecodeMessageIdentifiesRequestWithId", testDecodeMessageIdentifiesRequestWithId),
        ("testDecodeMessageIdentifiesResponse", testDecodeMessageIdentifiesResponse),
        ("testDecodeResponseHandlesError", testDecodeResponseHandlesError),
        ("testEncodeNotificationOmitsId", testEncodeNotificationOmitsId),
        ("testEncodeParamsSerializesSessionCreateParams", testEncodeParamsSerializesSessionCreateParams),
        ("testEncodeRequestProducesValidJsonRpc2", testEncodeRequestProducesValidJsonRpc2)
    ]
}

fileprivate extension WmpSessionTests {
    @available(*, deprecated, message: "Not actually deprecated. Marked as deprecated to allow inclusion of deprecated tests (which test deprecated functionality) without warnings")
    static nonisolated(unsafe) let __allTests__WmpSessionTests = [
        ("testCreateSendsSessionCreateAndTransitionsActive", asyncTest(testCreateSendsSessionCreateAndTransitionsActive)),
        ("testNotificationsFlowEmitsServerNotification", asyncTest(testNotificationsFlowEmitsServerNotification)),
        ("testSendRequestTimesOutWithoutResponse", asyncTest(testSendRequestTimesOutWithoutResponse))
    ]
}
@available(*, deprecated, message: "Not actually deprecated. Marked as deprecated to allow inclusion of deprecated tests (which test deprecated functionality) without warnings")
func __SirosTransportTests__allTests() -> [XCTestCaseEntry] {
    return [
        testCase(AnyCodableTests.__allTests__AnyCodableTests),
        testCase(EngineTypesTests.__allTests__EngineTypesTests),
        testCase(WmpCodecTests.__allTests__WmpCodecTests),
        testCase(WmpSessionTests.__allTests__WmpSessionTests)
    ]
}
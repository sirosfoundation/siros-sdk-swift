// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosAuth
import SirosCredentials
import SirosKeystore
import SirosTransport
@testable import SirosWallet

#if canImport(CryptoKit)
import CryptoKit

private final class NoAuth: AuthProvider, @unchecked Sendable {
    struct E: Error {}
    func register(options: RegisterOptions) async throws -> RegisterResult { throw E() }
    func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw E() }
    func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw E() }
}

/// A `Signer` that signs nothing real: the tests inspect the KB-JWT claims.
private final class ZeroSigner: Signer, @unchecked Sendable {
    private let key = P256.Signing.PrivateKey()
    func generateKey(algorithm: String) async throws -> String { "k1" }
    func sign(keyId: String, data: Data) async throws -> Data { Data(repeating: 1, count: 64) }
    func listKeys() async throws -> [SignerKeyInfo] { [SignerKeyInfo(keyId: "k1", algorithm: "ES256")] }
    func deleteKey(keyId: String) async throws {}
    func attestationChain(keyId: String) async throws -> AttestationChain? { nil }
    func exportPublicKey(keyId: String) async throws -> Data {
        let point = key.publicKey.x963Representation
        func enc(_ d: Data) -> String {
            d.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        }
        return try JSONSerialization.data(withJSONObject: [
            "kty": "EC", "crv": "P-256", "x": enc(point.subdata(in: 1..<33)), "y": enc(point.subdata(in: 33..<65)),
        ])
    }
    func migrateKey(keyId: String, targetPlugin: String) async throws -> MigrationResult { .migrated(newKeyId: keyId) }
    func securityProperties(keyId: String) async throws -> SignerSecurityProperties {
        SignerSecurityProperties(keyStorage: ["remote_hsm"], userAuthentication: ["pin"], amr: ["hwk", "pop", "pin"])
    }
}

/// Wallet keystore whose SD-JWT signing is the real `WscdKeystoreAdapter`
/// (so the KB-JWT under test is the production one) while the wallet itself
/// sees a locked keystore and skips container persistence.
private final class SigningKeystore: KeystoreManager, @unchecked Sendable {
    let adapter: WscdKeystoreAdapter
    private(set) var plainCalls = 0
    private(set) var scaCalls = 0
    struct NotImplemented: Error {}

    init() async throws {
        adapter = WscdKeystoreAdapter(signer: ZeroSigner())
        try await adapter.unlock(prfOutput: Data(), encryptedContainer: Data(), hkdfSalt: Data(), hkdfInfo: Data())
    }

    var isUnlocked: Bool { false }
    func unlock(prfOutput: Data, encryptedContainer: Data, hkdfSalt: Data, hkdfInfo: Data) async throws {}
    func lock() {}
    func generateKey(algorithm: String) async throws -> String { throw NotImplemented() }
    func sign(keyId: String, payload: Data, algorithm: String) async throws -> Data { throw NotImplemented() }
    func generateProof(audience: String, nonce: String, freshKey: Bool) async throws -> String { throw NotImplemented() }
    func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String { throw NotImplemented() }

    func signVpToken(credential: String, disclosedClaims: [String]?, nonce: String, audience: String, kid: String?) async throws -> String {
        plainCalls += 1
        return try await adapter.signVpToken(credential: credential, disclosedClaims: disclosedClaims, nonce: nonce, audience: audience, kid: kid)
    }

    func signVpToken(credential: String, disclosedClaims: [String]?, nonce: String, audience: String,
                     transactionData: TransactionDataBinding?, kid: String?) async throws -> String {
        scaCalls += 1
        return try await adapter.signVpToken(credential: credential, disclosedClaims: disclosedClaims, nonce: nonce,
                                             audience: audience, transactionData: transactionData, kid: kid)
    }

    func signMdocPresentationForDCAPI(credentialBytes: Data, disclosedClaims: [String]?, nonce: String, origin: String,
                                      encryptionPublicJwkThumbprint: String?, kid: String?) async throws -> Data { throw NotImplemented() }
    func exportEncryptedContainer() async throws -> Data { Data() }
    func listKeys() -> [KeyInfo] { [KeyInfo(keyId: "k1", algorithm: "ES256", pluginId: "r2ps")] }
    func saveCredential(id: Int64, json: String) async throws {}
    func getCredential(id: Int64) async throws -> String? { nil }
    func getAllCredentials() async throws -> [Int64: String] { [:] }
    func deleteCredential(id: Int64) async throws {}
    func clearCredentials() async throws {}
    func savePresentationRecord(id: Int64, json: String) async throws {}
    func getAllPresentationRecords() async throws -> [Int64: String] { [:] }
    func clearPresentationRecords() async throws {}
    func generateKeypairs(count: Int) async throws -> [KeypairInfo] { [] }
    func generateKeyProof(keyId: String, typ: String, issuer: String, audience: String, extraClaims: [String: String]) async throws -> String { throw NotImplemented() }
}

private final class Sender: SignResponseSender, @unchecked Sendable {
    private(set) var sent: [SignResponseMessage] = []
    func sendSignResponse(_ message: SignResponseMessage) { sent.append(message) }
}

private final class Consent: TransactionConsentHandler, @unchecked Sendable {
    var answer = true
    private(set) var requests: [TransactionConsentRequest] = []
    func confirm(_ request: TransactionConsentRequest) async throws -> Bool { requests.append(request); return answer }
}

private struct Factors: AuthenticationFactorsProvider {
    var factors = [AuthenticationFactor(.knowledge, "pin_6_or_more_digits"), AuthenticationFactor(.possession, "key_in_remote_wscd")]
    func factors(for context: AuthenticationFactorContext) async throws -> [AuthenticationFactor] { factors }
}

/// A request in, a KB-JWT out, checked against the verifier contract, once
/// per transport adapter (legacy engine, WMP, DC API).
final class TransactionDataEndToEndTests: XCTestCase {
    private let vct = "https://pay.example/card"
    private let audience = "x509_san_dns:shop.example"
    private let payload = #"{"transaction_id":"tx-1","payee":{"name":"Shop AB","id":"SE1"},"currency":"EUR","amount":49.99}"#

    private func b64(_ s: String) -> String {
        Data(s.utf8).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    private var raw: String {
        b64(#"{"type":"urn:eudi:sca:payment:1","credential_ids":["pay"],"transaction_data_hashes_alg":["sha-256"],"payload":\#(payload)}"#)
    }

    private var metadata: String {
        let claims = #"[{"path":["payload","amount"],"visualisation":1,"display":[{"lang":"en","label":"Amount"}]},{"path":["payload","currency"],"visualisation":1,"display":[{"lang":"en","label":"Currency"}]},{"path":["payload","payee","name"],"visualisation":2,"display":[{"lang":"en","label":"Payee"}]},{"path":["payload","payee","id"],"display":[{"lang":"en","label":"Payee ID"}]},{"path":["payload","transaction_id"],"visualisation":4,"display":[{"lang":"en","label":"Transaction"}]}]"#
        let labels = #"{"affirmative_action_label":[{"lang":"en","value":"Confirm Payment"}]}"#
        return #"{"vct":"\#(vct)","category":"urn:eu:europa:ec:eudi:sua:sca","transaction_data_types":{"urn:eudi:sca:payment:1":{"schema":"urn:eudi:sca:payment:1","claims":\#(claims),"ui_labels":\#(labels)}}}"#
    }

    private struct Fixture {
        let wallet: SirosWallet
        let keystore: SigningKeystore
        let consent: Consent
    }

    private func fixture(enabled: Bool = true, handler: Bool = true, format: String = "dc+sd-jwt", metadataDoc: String? = nil) async throws -> Fixture {
        let jwtPayload = b64(#"{"vct":"\#(vct)"}"#)
        let store = InMemoryCredentialStore()
        await store.save(StoredCredential(
            id: 1, format: format, raw: "eyJhbGciOiJFUzI1NiJ9.\(jwtPayload).c2ln~", metadata: CredentialMetadata(name: "Visa card", vct: vct, doctype: nil),
            batchId: 1, instanceId: 0
        ))
        let keystore = try await SigningKeystore()
        let wallet = try XCTUnwrap(SirosWallet(
            config: WalletConfig(backendUrl: "https://example.invalid", credentialStore: store, transactionDataEnabled: enabled),
            authProvider: NoAuth(), keystore: keystore
        ))
        let doc = metadataDoc ?? metadata
        wallet.vctmFetcher = VctmFetcher(httpGet: { url in url.contains("type-metadata") ? doc : nil })
        wallet.apiClient = BackendApiClient(baseUrl: "https://example.invalid", httpFn: { _, _, _, _ in
            try JSONSerialization.data(withJSONObject: ["decision": true])
        })
        let consent = Consent()
        if handler { wallet.transactionConsentHandler = consent }
        wallet.authenticationFactorsProvider = Factors()
        wallet.transactionDataLocale = "en-GB"
        wallet.snapshotTransactionDataEnablement()
        wallet.snapshotWmpSessionEnablement()
        return Fixture(wallet: wallet, keystore: keystore, consent: consent)
    }

    private func kbClaims(_ vpToken: String) throws -> [String: Any] {
        let kb = try XCTUnwrap(vpToken.split(separator: "~", omittingEmptySubsequences: false).last.map(String.init))
        let part = try XCTUnwrap(kb.split(separator: ".").dropFirst().first.map(String.init))
        var s = part.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        s += String(repeating: "=", count: (4 - s.count % 4) % 4)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: try XCTUnwrap(Data(base64Encoded: s))) as? [String: Any])
    }

    /// The verifier contract of TS12 3.6 / OID4VP Appendix B.
    private func assertVerifierContract(_ claims: [String: Any], responseMode: String, nonce: String, aud: String,
                                        file: StaticString = #filePath, line: UInt = #line) throws {
        let expectedHash = try XCTUnwrap(TransactionDataHashing.hash(raw: raw, algorithm: "sha-256"))
        XCTAssertEqual(claims["transaction_data_hashes"] as? [String], [expectedHash], "hash over the raw string", file: file, line: line)
        XCTAssertEqual(claims["transaction_data_hashes_alg"] as? String, "sha-256", "a string", file: file, line: line)
        XCTAssertEqual(claims["response_mode"] as? String, responseMode, file: file, line: line)
        XCTAssertFalse((claims["jti"] as? String ?? "").isEmpty, file: file, line: line)
        let amr = try XCTUnwrap(claims["amr"] as? [[String: String]], "object-form amr", file: file, line: line)
        XCTAssertEqual(Set(amr.flatMap(\.keys)), ["knowledge", "possession"], file: file, line: line)
        XCTAssertEqual(claims["nonce"] as? String, nonce, file: file, line: line)
        XCTAssertEqual(claims["aud"] as? String, aud, file: file, line: line)
        XCTAssertNotNil(claims["iat"], file: file, line: line)
        XCTAssertNotNil(claims["sd_hash"], file: file, line: line)
    }

    // MARK: - Legacy engine

    private func engineMessage(flow: String = "f1", transactionData: String? = nil, refs: String = #"[{"credential_query_id":"pay","credential_id":"1"}]"#, extra: String = "") throws -> SignRequestMessage {
        let td = transactionData ?? #"[{"raw":"\#(raw)","type":"urn:eudi:sca:payment:1","credential_ids":["pay"],"payload":\#(payload),"transaction_data_hashes_alg":["sha-256"]}]"#
        let json = #"{"type":"sign_request","flow_id":"\#(flow)","message_id":"m1","action":"sign_presentation","params":{"audience":"\#(audience)","nonce":"n-1","response_mode":"direct_post.jwt","credentials_to_include":\#(refs),"transaction_data":\#(td)\#(extra)}}"#
        return try JSONDecoder().decode(SignRequestMessage.self, from: Data(json.utf8))
    }

    func testEngineProducesAContractKbJwt() async throws {
        let f = try await fixture()
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage())
        let token = try XCTUnwrap(sender.sent.first?.vpToken)
        try assertVerifierContract(try kbClaims(token), responseMode: "direct_post.jwt", nonce: "n-1", aud: audience)
        let shown = try XCTUnwrap(f.consent.requests.first)
        XCTAssertEqual(shown.entries.first?.fields.first?.label, "Amount")
        XCTAssertEqual(shown.credentialName, "Visa card")
        let log = await f.wallet.transactionLog()
        XCTAssertEqual(log.first?.outcome, .consented)
        XCTAssertEqual(log.first?.transactionId, "tx-1")
    }

    func testEngineRefusesWithoutAHandlerAndSignsNothing() async throws {
        let f = try await fixture(handler: false)
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage())
        XCTAssertNil(sender.sent.first?.vpToken)
        XCTAssertEqual(sender.sent.count, 1, "answered at once with an empty sign_response")
        XCTAssertEqual(f.keystore.scaCalls + f.keystore.plainCalls, 0)
    }

    func testEngineRefusesWhenDisabled() async throws {
        let f = try await fixture(enabled: false)
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage())
        XCTAssertNil(sender.sent.first?.vpToken)
        XCTAssertEqual(f.keystore.scaCalls + f.keystore.plainCalls, 0)
        XCTAssertTrue(f.consent.requests.isEmpty)
    }

    func testEngineDeclineSignsNothingAndIsLogged() async throws {
        let f = try await fixture()
        f.consent.answer = false
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage())
        XCTAssertNil(sender.sent.first?.vpToken)
        XCTAssertEqual(f.keystore.scaCalls, 0)
        let log = await f.wallet.transactionLog()
        XCTAssertEqual(log.first?.outcome, .declined)
    }

    func testEngineRefusesAnOrchestratorHintThatDisagreesWithRaw() async throws {
        let f = try await fixture()
        let tampered = payload.replacingOccurrences(of: "Shop AB", with: "Evil Ltd")
        let td = #"[{"raw":"\#(raw)","type":"urn:eudi:sca:payment:1","credential_ids":["pay"],"payload":\#(tampered)}]"#
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage(transactionData: td))
        XCTAssertNil(sender.sent.first?.vpToken)
        XCTAssertTrue(f.consent.requests.isEmpty, "the user is not shown a transaction that disagrees with what would be bound")
        let log = await f.wallet.transactionLog()
        XCTAssertEqual(log.first?.reason, "inconsistentWithOrchestrator")
    }

    func testEngineRefusesTransactionDataWithoutCredentialsToInclude() async throws {
        let f = try await fixture()
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage(refs: "[]"))
        XCTAssertNil(sender.sent.first?.vpToken)
        XCTAssertEqual(f.keystore.scaCalls + f.keystore.plainCalls, 0)
    }

    func testEngineRefusesTwoCredentialsForOneQuery() async throws {
        let f = try await fixture()
        let store = try XCTUnwrap(f.wallet.credentialStore as? InMemoryCredentialStore)
        let jwtPayload = b64(#"{"vct":"\#(vct)"}"#)
        await store.save(StoredCredential(
            id: 2, format: "dc+sd-jwt", raw: "eyJhbGciOiJFUzI1NiJ9.\(jwtPayload).c2ln~", metadata: CredentialMetadata(name: "Second", vct: vct, doctype: nil),
            batchId: 2, instanceId: 0
        ))
        let refs = #"[{"credential_query_id":"pay","credential_id":"1"},{"credential_query_id":"pay","credential_id":"2"}]"#
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage(refs: refs))
        XCTAssertNil(sender.sent.first?.vpToken)
        XCTAssertEqual(f.keystore.scaCalls, 0)
    }

    func testEngineRefusesInsufficientFactors() async throws {
        let f = try await fixture()
        f.wallet.authenticationFactorsProvider = InterimAuthenticationFactorsProvider()
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage())
        XCTAssertNil(sender.sent.first?.vpToken, "the default provider cannot establish two factors")
        XCTAssertEqual(f.keystore.scaCalls, 0)
    }

    func testEngineRefusesMdocCredentialForTransactionData() async throws {
        let f = try await fixture(format: "mso_mdoc")
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage())
        XCTAssertNil(sender.sent.first?.vpToken)
        XCTAssertEqual(f.keystore.scaCalls + f.keystore.plainCalls, 0)
    }

    func testEngineRefusesANonScaAttestation() async throws {
        let f = try await fixture(metadataDoc: metadata.replacingOccurrences(of: "urn:eu:europa:ec:eudi:sua:sca", with: "urn:other"))
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage())
        XCTAssertNil(sender.sent.first?.vpToken)
    }

    /// A runtime flip applies to the next flow only.
    func testAFlagFlipAppliesToTheNextFlowOnly() async throws {
        let f = try await fixture()
        f.wallet.transactionDataEnabled = false
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage())
        XCTAssertNotNil(sender.sent.first?.vpToken, "the flow in progress finishes under the setting it started with")
        f.wallet.snapshotTransactionDataEnablement()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage(flow: "f2"))
        XCTAssertNil(sender.sent.last?.vpToken, "the next flow starts disabled")
    }

    /// Two flows in flight keep their own setting: the second one starting
    /// disabled does not change the first.
    func testOverlappingFlowsKeepTheirOwnSnapshot() async throws {
        let f = try await fixture()          // flow A's start: enabled (queue: [true])
        f.wallet.transactionDataEnabled = false
        f.wallet.snapshotTransactionDataEnablement()   // flow B's start: disabled (queue: [true, false])
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage(flow: "A"))
        XCTAssertNotNil(sender.sent.last?.vpToken, "flow A started enabled")
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage(flow: "B"))
        XCTAssertNil(sender.sent.last?.vpToken, "flow B started disabled")
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage(flow: "A"))
        XCTAssertNotNil(sender.sent.last?.vpToken, "flow A still finishes under its own setting")
    }

    func testQueueOrderIsNotAffectedByTheLiveFlagAtProcessingTime() async throws {
        let f = try await fixture()                       // A: enabled
        f.wallet.transactionDataEnabled = false
        f.wallet.snapshotTransactionDataEnablement()      // B: disabled
        f.wallet.transactionDataEnabled = true            // live flag is on again when they are processed
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage(flow: "A"))
        XCTAssertNotNil(sender.sent.last?.vpToken)
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage(flow: "B"))
        XCTAssertNil(sender.sent.last?.vpToken, "B started disabled whatever the flag is now")
    }

    func testWmpSessionKeepsItsOwnSetting() async throws {
        let on = try await fixture()                      // session started enabled
        on.wallet.transactionDataEnabled = false
        _ = try await on.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams())
        let off = try await fixture(enabled: false)       // session started disabled
        off.wallet.transactionDataEnabled = true
        do { _ = try await off.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams()); XCTFail() }
        catch SirosError.transactionData(let e) { XCTAssertEqual(e.reason, .disabled) }
    }

    func testReferencedDocumentsGoThroughTheUnauthenticatedGetterEndToEnd() async throws {
        final class Recorder: @unchecked Sendable {
            private let lock = NSLock(); private var urls: [String] = []
            func add(_ u: String) { lock.lock(); urls.append(u); lock.unlock() }
            var all: [String] { lock.lock(); defer { lock.unlock() }; return urls }
        }
        let labelsUrl = "https://registry.example.attacker.test/labels.json"
        let entry = metadata.replacingOccurrences(of: #""ui_labels":{"affirmative_action_label":[{"lang":"en","value":"Confirm Payment"}]}"#, with: #""ui_labels_uri":"\#(labelsUrl)""#)
        let f = try await fixture(metadataDoc: entry)
        let rec = Recorder()
        f.wallet.transactionResourceGet = { url in
            rec.add(url.absoluteString)
            return Data(#"{"affirmative_action_label":[{"lang":"en","value":"Confirm Payment"}]}"#.utf8)
        }
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage())
        XCTAssertNotNil(sender.sent.first?.vpToken)
        XCTAssertEqual(rec.all, [labelsUrl])
    }

    func testAFactorsProviderThatThrowsIsARefusalAndIsLogged() async throws {
        struct Boom: Error {}
        struct Throwing: AuthenticationFactorsProvider {
            func factors(for context: AuthenticationFactorContext) async throws -> [AuthenticationFactor] { throw Boom() }
        }
        let f = try await fixture()
        f.wallet.authenticationFactorsProvider = Throwing()
        do { _ = try await f.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams()); XCTFail() }
        catch SirosError.transactionData(let e) { XCTAssertEqual(e.reason, .insufficientAuthenticationFactors) }
        let log = await f.wallet.transactionLog()
        XCTAssertEqual(log.first?.reason, "insufficientAuthenticationFactors")
    }

    func testTheDefaultLogIsNotCarriedToTheNextAccount() async throws {
        let f = try await fixture()
        _ = try await f.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams())
        let before = await f.wallet.transactionLog()
        XCTAssertEqual(before.count, 1)
        f.wallet.resetDefaultTransactionLogStore()   // what logout and lock do
        let after = await f.wallet.transactionLog()
        XCTAssertTrue(after.isEmpty)
    }

    func testAHostSuppliedLogStoreSurvivesAnAccountBoundary() async throws {
        let f = try await fixture()
        _ = await f.wallet.transactionLog()               // the default store is created first
        let store = InMemoryTransactionLogStore()
        f.wallet.setTransactionLogStore(store)
        _ = try await f.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams())
        f.wallet.resetDefaultTransactionLogStore()
        let kept = await f.wallet.transactionLog()
        XCTAssertEqual(kept.count, 1, "the wallet still reads the host's store after the boundary")
    }

    func testReferencedDocumentsAreFetchedWithoutCredentials() async throws {
        final class Recorder: @unchecked Sendable {
            private let lock = NSLock(); private var urls: [URL] = []
            func add(_ u: URL) { lock.lock(); urls.append(u); lock.unlock() }
            var all: [URL] { lock.lock(); defer { lock.unlock() }; return urls }
        }
        let rec = Recorder()
        let source = WalletTransactionMetadataSource(
            fetcher: VctmFetcher(httpGet: { _ in "AUTHENTICATED-VCTM-GET-MUST-NOT-BE-USED" }),
            registryUrl: "https://registry.example",
            resourceGet: { rec.add($0); return Data("{}".utf8) }
        )
        // A lookalike of the registry origin gets the unauthenticated getter only.
        let data = await source.fetchResource(uri: "https://registry.example.attacker.test/labels.json")
        XCTAssertEqual(data, Data("{}".utf8))
        XCTAssertEqual(rec.all.map(\.absoluteString), ["https://registry.example.attacker.test/labels.json"])
        for bad in ["http://plain.example/x.json", "file:///etc/passwd", "ftp://x.example/y", "//x.example/y", "not a url"] {
            let none = await source.fetchResource(uri: bad)
            XCTAssertNil(none, bad)
        }
        XCTAssertEqual(rec.all.count, 1, "no non-https reference reached the getter")
    }

    func testThePluginIdOfTheSigningKeyReachesTheFactorsProvider() async throws {
        final class Capture: AuthenticationFactorsProvider, @unchecked Sendable {
            private let lock = NSLock(); private var seen: [AuthenticationFactorContext] = []
            var contexts: [AuthenticationFactorContext] { lock.lock(); defer { lock.unlock() }; return seen }
            func factors(for context: AuthenticationFactorContext) async throws -> [AuthenticationFactor] {
                lock.lock(); seen.append(context); lock.unlock()
                return [AuthenticationFactor(.knowledge, "other"), AuthenticationFactor(.possession, "key_in_remote_wscd")]
            }
        }
        let f = try await fixture()
        let capture = Capture()
        f.wallet.authenticationFactorsProvider = capture
        _ = try await f.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams())
        XCTAssertEqual(capture.contexts.first?.pluginId, "r2ps")
    }

    func testNonScaPresentationUsesTheUnchangedPath() async throws {
        let f = try await fixture(enabled: false)
        let sender = Sender()
        let json = #"{"type":"sign_request","flow_id":"f2","message_id":"m2","action":"sign_presentation","params":{"audience":"\#(audience)","nonce":"n","credentials_to_include":[{"credential_query_id":"q","credential_id":"1"}]}}"#
        await f.wallet.handleSignRequest(engine: sender, msg: try JSONDecoder().decode(SignRequestMessage.self, from: Data(json.utf8)))
        XCTAssertEqual(f.keystore.plainCalls, 1)
        XCTAssertEqual(f.keystore.scaCalls, 0)
        let claims = try kbClaims(try XCTUnwrap(sender.sent.first?.vpToken))
        XCTAssertEqual(Set(claims.keys), ["aud", "iat", "nonce", "sd_hash", "amr"], "no TS12 claims on a plain presentation")
        XCTAssertEqual(claims["amr"] as? [String], ["hwk", "pop", "pin"])
    }

    // MARK: - WMP

    private func wmpParams(transactionData: String? = nil, refs: String = #"[{"credential_query_id":"pay","credential_id":"1"}]"#) throws -> SignSubFlowParams {
        let td = transactionData ?? #"[{"raw":"\#(raw)","type":"urn:eudi:sca:payment:1","credential_ids":["pay"],"payload":\#(payload),"transaction_data_hashes_alg":["sha-256"]}]"#
        let json = #"{"action":"sign_presentation","nonce":"n-1","audience":"\#(audience)","response_mode":"direct_post.jwt","credentials_to_include":\#(refs),"transaction_data":\#(td)}"#
        return try JSONDecoder().decode(SignSubFlowParams.self, from: Data(json.utf8))
    }

    func testWmpProducesAContractKbJwt() async throws {
        let f = try await fixture()
        let result = try await f.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams())
        try assertVerifierContract(try kbClaims(try XCTUnwrap(result.vpToken)), responseMode: "direct_post.jwt", nonce: "n-1", aud: audience)
    }

    /// Through the sub-flow handler the profile calls, not just the helper.
    func testWmpSignSubFlowHandlerRoutesTransactionDataToTheScaPath() async throws {
        let f = try await fixture()
        let result = try await f.wallet.handleWmpSignRequest(flowId: "f1", params: try wmpParams())
        try assertVerifierContract(try kbClaims(try XCTUnwrap(result.vpToken)), responseMode: "direct_post.jwt", nonce: "n-1", aud: audience)
        XCTAssertEqual(f.keystore.scaCalls, 1)
    }

    func testWmpRefusesWhenDisabledOrDeclinedOrInconsistent() async throws {
        let disabled = try await fixture(enabled: false)
        do { _ = try await disabled.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams()); XCTFail() } catch SirosError.transactionData(let e) { XCTAssertEqual(e.reason, .disabled) }

        let declined = try await fixture()
        declined.consent.answer = false
        do { _ = try await declined.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams()); XCTFail() } catch SirosError.transactionData(let e) { XCTAssertEqual(e.reason, .declined) }

        let inconsistent = try await fixture()
        let td = #"[{"raw":"\#(raw)","type":"urn:eudi:sca:login_risk_transaction:1","credential_ids":["pay"]}]"#
        do { _ = try await inconsistent.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams(transactionData: td)); XCTFail() } catch SirosError.transactionData(let e) { XCTAssertEqual(e.reason, .inconsistentWithOrchestrator) }
        XCTAssertEqual(disabled.keystore.scaCalls + declined.keystore.scaCalls + inconsistent.keystore.scaCalls, 0)
    }

    /// The bound credential is listed FIRST: it must not be signed before the later one is found unbound.
    func testWmpSignsNothingWhenALaterReferenceIsNotBound() async throws {
        let f = try await fixture()
        let store = try XCTUnwrap(f.wallet.credentialStore as? InMemoryCredentialStore)
        await store.save(StoredCredential(id: 2, format: "dc+sd-jwt", raw: "a.b.c~", metadata: CredentialMetadata(name: "Age", vct: "urn:age", doctype: nil), batchId: 2, instanceId: 0))
        let refs = #"[{"credential_query_id":"pay","credential_id":"1"},{"credential_query_id":"age","credential_id":"2"}]"#
        do { _ = try await f.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams(refs: refs)); XCTFail() } catch SirosError.transactionData {}
        XCTAssertEqual(f.keystore.scaCalls, 0, "the first credential was not signed before the later guard")
    }

    func testWmpRefusesACombinedPresentation() async throws {
        let f = try await fixture()
        let refs = #"[{"credential_query_id":"pay","credential_id":"1"},{"credential_query_id":"age","credential_id":"2"}]"#
        do { _ = try await f.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams(refs: refs)); XCTFail() } catch SirosError.transactionData {}
        XCTAssertEqual(f.keystore.scaCalls, 0)
    }

    // MARK: - DC API

    private func dcapiRequest(transactionData: String) -> String {
        #"{"requests":[{"protocol":"openid4vp-v1-unsigned","data":{"nonce":"dc-nonce","response_mode":"dc_api","transaction_data":\#(transactionData),"dcql_query":{"credentials":[{"id":"pay","format":"dc+sd-jwt"}]}}}]}"#
    }

    func testDcApiProducesAContractKbJwt() async throws {
        let f = try await fixture()
        let result = try await f.wallet.handleDCAPIRequest(rawRequestJson: dcapiRequest(transactionData: #"["\#(raw)"]"#), origin: "https://shop.example")
        let envelope = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(result.responseJson.utf8)) as? [String: Any])
        let vp = try XCTUnwrap((envelope["data"] as? [String: Any])?["vp_token"] as? [String: [String]])
        let claims = try kbClaims(try XCTUnwrap(vp["pay"]?.first))
        try assertVerifierContract(claims, responseMode: "dc_api", nonce: "dc-nonce", aud: "origin:https://shop.example")
        XCTAssertEqual(f.consent.requests.first?.requestSigned, false, "an unsigned DC API request is flagged for the warning")
    }

    func testDcApiStillRefusesWhenNotEffectivelyEnabled() async throws {
        for (enabled, handler) in [(false, true), (true, false), (false, false)] {
            let f = try await fixture(enabled: enabled, handler: handler)
            do {
                _ = try await f.wallet.handleDCAPIRequest(rawRequestJson: dcapiRequest(transactionData: #"["\#(raw)"]"#), origin: "https://shop.example")
                XCTFail("must refuse enabled=\(enabled) handler=\(handler)")
            } catch SirosError.transactionData(let e) {
                XCTAssertEqual(e.verifierErrorCode, "invalid_transaction_data")
            }
            XCTAssertEqual(f.keystore.scaCalls + f.keystore.plainCalls, 0)
        }
    }

    func testDcApiRefusesMalformedTransactionData() async throws {
        let f = try await fixture()
        for bad in ["5", #"[1,2]"#, "[]", #"["!!!"]"#] {
            do {
                _ = try await f.wallet.handleDCAPIRequest(rawRequestJson: dcapiRequest(transactionData: bad), origin: "https://shop.example")
                XCTFail("must refuse \(bad)")
            } catch SirosError.transactionData {}
        }
        XCTAssertEqual(f.keystore.scaCalls + f.keystore.plainCalls, 0)
    }

    func testDcApiRefusesWhenMoreThanOneCredentialAnswersTheBoundQuery() async throws {
        let f = try await fixture()
        let store = try XCTUnwrap(f.wallet.credentialStore as? InMemoryCredentialStore)
        let jwtPayload = b64(#"{"vct":"\#(vct)"}"#)
        await store.save(StoredCredential(
            id: 2, format: "dc+sd-jwt", raw: "eyJhbGciOiJFUzI1NiJ9.\(jwtPayload).c2ln~", metadata: CredentialMetadata(name: "Second card", vct: vct, doctype: nil),
            batchId: 2, instanceId: 0
        ))
        let req = #"{"requests":[{"protocol":"openid4vp-v1-unsigned","data":{"nonce":"n","response_mode":"dc_api","transaction_data":["\#(raw)"],"dcql_query":{"credentials":[{"id":"pay","format":"dc+sd-jwt","multiple":true}]}}}]}"#
        do {
            _ = try await f.wallet.handleDCAPIRequest(rawRequestJson: req, origin: "https://shop.example")
            XCTFail("must refuse")
        } catch SirosError.transactionData(let e) { XCTAssertEqual(e.reason, .invalidEntry) }
        XCTAssertEqual(f.keystore.scaCalls, 0)
    }

    func testDcApiRefusesAnMdocCredential() async throws {
        let f = try await fixture(format: "mso_mdoc")
        let req = #"{"requests":[{"protocol":"openid4vp-v1-unsigned","data":{"nonce":"n","response_mode":"dc_api","transaction_data":["\#(raw)"],"dcql_query":{"credentials":[{"id":"pay","format":"mso_mdoc"}]}}}]}"#
        do { _ = try await f.wallet.handleDCAPIRequest(rawRequestJson: req, origin: "https://shop.example"); XCTFail() } catch SirosError.transactionData {}
    }
}
#endif

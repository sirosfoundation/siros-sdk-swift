// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
#if canImport(os)
import os
private let logger = Logger(subsystem: "org.siros.sdk", category: "MdocProximitySession")
#endif
#if canImport(Security)
import Security
#endif

/// The user's answer to a `RequestProximityConsent` prompt.
public enum ProximityConsentResult {
    case approved(CredentialFamily)
    case denied
}

/// Outcome of evaluating a proximity reader's authenticated identity - only
/// produced when the reader sent a `readerAuth` AND its COSE_Sign1 signature
/// verified successfully against its own embedded x5chain (see
/// `MdocCose.verify1`); a present-but-invalid signature is treated as
/// `MdocProximitySession` logging a warning and passing `nil` here rather
/// than a `trusted = false` result, since an invalid signature means the
/// reader's claimed identity itself is unproven, not merely untrusted.
/// Ported from the Kotlin SDK's `ReaderTrustResult`.
public struct ReaderTrustResult: Sendable {
    public let trusted: Bool
    /// Human-readable reason for the decision, e.g. why a chain wasn't trusted.
    public let reason: String?
    /// Display name of the reader/relying party, if the trust evaluator could resolve one.
    public let entityName: String?

    public init(trusted: Bool, reason: String? = nil, entityName: String? = nil) {
        self.trusted = trusted
        self.reason = reason
        self.entityName = entityName
    }
}

/// Asks the user to approve a proximity presentation before it's signed and
/// sent - shared by both BLE roles (`MdocProximitySession` is transport-role
/// agnostic), implemented by the host app as an async bridge to its own
/// consent UI.
///
/// - Parameters:
///   - docType: the requested document type.
///   - requestedClaims: the flattened element identifiers the reader asked for.
///   - matchingFamilies: every credential family whose docType matches
///     (never empty - `MdocProximitySession` only invokes this once at least
///     one match exists; see `CredentialFamily` for why this is families, not
///     raw instances), for the user to choose among if there's more than one
///     (e.g. the same docType from two different issuers).
///   - readerTrust: the reader's RICAL trust evaluation result - `nil` if the
///     reader sent no `readerAuth` (optional per §9.1.4) or its signature
///     failed to verify, in which case the host UI should treat the reader as
///     unauthenticated (no badge), not as actively distrusted.
public typealias RequestProximityConsent = (
    _ docType: String,
    _ requestedClaims: [String],
    _ matchingFamilies: [CredentialFamily],
    _ readerTrust: ReaderTrustResult?
) async -> ProximityConsentResult

/// ISO 18013-5 §8.3.3.1.1/§11.1.3 mdoc-side proximity session logic, shared
/// by both BLE roles (`BlePeripheralServer`'s "mdoc peripheral server mode"
/// and `BleCentralClient`'s "mdoc central client mode" in the sample app):
/// given a raw `SessionEstablishment` message, derives the session keys,
/// decrypts and parses the mdoc request, matches stored credentials by
/// `docType`, asks the host to obtain user consent, filters to eligible
/// (unconsumed) instances, picks one at random (preserving unlinkability
/// across repeated presentations), then signs and encrypts the
/// `DeviceResponse`.
///
/// Deliberately excludes anything BLE/GATT-specific (chunking/reassembly,
/// characteristic reads/writes, backpressure, completion signaling) - the
/// two host-app BLE classes differ in exactly those respects (e.g.
/// `CBPeripheralManager` notify backpressure vs fire-and-forget
/// `CBPeripheral.writeValue`), so they stay thin transport glue calling into
/// one instance of this class per session.
///
/// Unlike the Kotlin SDK's equivalent, this does NOT retry an NFC-static-
/// handover `SessionTranscript` variant when deriving session keys: iOS has
/// no `MdocHostApduService`/HCE equivalent (third-party apps cannot emulate
/// an NFC Type 4 Tag - see `NfcHandoverSelect`'s doc comment), so a BLE
/// connection reachable via a given engagement can only ever have arrived
/// via the QR-handover variant (`Handover = nil`) - there is no ambiguity to
/// retry against. This was evaluated deliberately when `BlePeripheralServer`
/// was first ported from Kotlin - do not add a multi-candidate retry loop
/// here unless iOS gains a way to actually serve NFC static handover.
///
/// EC/AEAD primitives (via `ProximitySessionCrypto`) and `DeviceEngagement.Engagement`'s
/// real `privateKey` are Apple-only (`CryptoKit`) - matching this repo's
/// established `#if canImport(CryptoKit)` convention (see `JweKeystore`,
/// `ProximitySessionCrypto`), this whole type is gated; on non-Apple
/// platforms `handleSessionEstablishment` throws rather than silently
/// no-op'ing. There are no callers on non-Apple platforms today - the BLE
/// peripheral/central glue that drives this class is Apple-only - but this
/// class itself is real SDK surface (unlike its Xcode-only callers), so it
/// needs its own platform gate the same way `ProximitySessionCrypto` does.
public final class MdocProximitySession {

    /// Outcome of `handleSessionEstablishment` - the caller decides how to
    /// actually transmit `.response`'s bytes (GATT notify vs GATT write) and
    /// how to signal completion.
    public enum Result {
        /// An encrypted `SessionData` response ready to send back to the reader.
        case response(Data)
        /// The user declined the consent prompt.
        case denied
        /// `reason` is log-only context, not user-facing.
        case failed(reason: String)
    }

    private let engagement: DeviceEngagement.Engagement
    /// Mirrors `SirosWallet.getCredentials` - injected rather than taking a
    /// `SirosWallet`/`WalletViewModel` directly, keeping this class
    /// independent of the app's view-model layer.
    private let getCredentials: () async -> [StoredCredential]
    /// Mirrors `SirosWallet.signMdocPresentationForProximity`.
    private let signPresentation: (_ credentialId: Int64, _ disclosedClaims: [String]?, _ sessionTranscriptBytes: Data) async throws -> Data
    /// See `RequestProximityConsent`'s doc comment.
    private let requestConsent: RequestProximityConsent
    /// Evaluates a reader's already-signature-verified x5chain (leaf first)
    /// for trust - the host app wires this to a remote AuthZEN call against
    /// go-trust's `mdocrical` registry, with a local X.509-path-validation
    /// fallback against a configured RICAL root, per this session's RICAL
    /// plan. Only invoked when a `readerAuth` was present and its signature
    /// verified - see `ReaderTrustResult`'s doc comment for why an invalid
    /// signature skips this entirely rather than calling it with an
    /// already-doomed chain.
    private let evaluateReaderTrust: (_ x5chain: [[UInt8]]) async -> ReaderTrustResult
    /// Mirrors `CredentialUtils.eligibleInstances` bound to the caller's
    /// current `SirosWallet.credentialConsumptionPolicy`/`presentationHistory` -
    /// excludes instances the active consumption policy considers already
    /// used up, so a family the user approves can't sign with an exhausted
    /// instance even if `requestConsent`'s UI failed to grey it out.
    private let filterEligible: ([StoredCredential]) -> [StoredCredential]
    /// Reports a canonical step token (see `FlowStepCatalog.proximitySteps`)
    /// for driving the same progress-bar UI the issuance/presentation flows use.
    private let onStep: (String) -> Void
    /// Log-tag prefix distinguishing which BLE role a given session belongs
    /// to in shared logs (e.g. "BlePeripheralServer", "BleCentralClient").
    private let logTag: String

    public init(
        engagement: DeviceEngagement.Engagement,
        getCredentials: @escaping () async -> [StoredCredential],
        signPresentation: @escaping (Int64, [String]?, Data) async throws -> Data,
        requestConsent: @escaping RequestProximityConsent,
        evaluateReaderTrust: @escaping (_ x5chain: [[UInt8]]) async -> ReaderTrustResult,
        filterEligible: @escaping ([StoredCredential]) -> [StoredCredential],
        onStep: @escaping (String) -> Void,
        logTag: String
    ) {
        self.engagement = engagement
        self.getCredentials = getCredentials
        self.signPresentation = signPresentation
        self.requestConsent = requestConsent
        self.evaluateReaderTrust = evaluateReaderTrust
        self.filterEligible = filterEligible
        self.onStep = onStep
        self.logTag = logTag
    }

    #if canImport(CryptoKit)

    private var deviceCipher: ProximitySessionCrypto.SessionCipher?

    /// True once session keys have been successfully derived for this session.
    public var established: Bool { deviceCipher != nil }

    /// Guards against two overlapping `handleSessionEstablishment` calls for
    /// this session (e.g. a reader retransmitting `SessionEstablishment`
    /// before the first call has finished deriving keys - session-key
    /// derivation genuinely takes non-zero time: ECDH + HKDF + CBOR
    /// parsing). Without this, a second concurrent call could race on
    /// `deviceCipher`, in the worst case building a signed/encrypted
    /// response with a cipher instance that then gets overwritten by the
    /// other call before it's ever used to encrypt.
    private let establishmentLock = NSLock()
    private var handlingEstablishment = false

    public func handleSessionEstablishment(_ message: [UInt8]) async throws -> Result {
        establishmentLock.lock()
        if handlingEstablishment {
            establishmentLock.unlock()
            #if canImport(os)
            logger.warning("\(self.logTag, privacy: .public): dropping overlapping SessionEstablishment - one is already in progress")
            #endif
            return .failed(reason: "session establishment already in progress")
        }
        handlingEstablishment = true
        establishmentLock.unlock()
        defer {
            establishmentLock.lock()
            handlingEstablishment = false
            establishmentLock.unlock()
        }

        onStep("parsing_request")
        let established = try ProximitySessionMessages.parseSessionEstablishment(message)
        let eReaderPublicKey = try ProximitySessionCrypto.parseEReaderKeyPublic(established.eReaderKeyBytes)
        let sessionTranscript = try ProximitySessionTranscript.build(
            deviceEngagementBytes: engagement.deviceEngagementBytes,
            eReaderKeyBytes: established.eReaderKeyBytes,
            handoverSelectMessageBytes: nil
        )
        let keys = try ProximitySessionCrypto.deriveSessionKeys(
            eDeviceKeyPrivate: engagement.privateKey,
            eReaderKeyPublic: eReaderPublicKey,
            sessionTranscript: sessionTranscript
        )
        let requestBytes = try ProximitySessionCrypto.readerCipher(keys.skReader).decrypt(established.encryptedData)
        let cipher = ProximitySessionCrypto.deviceCipher(keys.skDevice)
        deviceCipher = cipher

        let docRequests = try DeviceRequestParser.parse(requestBytes)
        guard let docRequest = docRequests.first else {
            #if canImport(os)
            logger.warning("\(self.logTag, privacy: .public): request contained no documents")
            #endif
            return .failed(reason: "no documents requested")
        }

        onStep("match_credentials")
        let credentials = await getCredentials()
        let matches = CredentialMatcher.matchMdocDocType(credentials, docType: docRequest.docType)
        guard !matches.isEmpty else {
            #if canImport(os)
            logger.warning("\(self.logTag, privacy: .public): no stored credential matches requested docType '\(docRequest.docType, privacy: .public)'")
            #endif
            return .failed(reason: "no matching credential")
        }
        let families = CredentialUtils.groupIntoFamilies(matches)
        guard !families.isEmpty else {
            // matches non-empty doesn't guarantee families non-empty:
            // groupIntoFamilies skips any batch missing an instanceId==0
            // representative (see its own doc comment). Treat that as a
            // non-match rather than calling requestConsent with an empty
            // list, which would violate RequestProximityConsent's
            // documented "never empty" contract.
            #if canImport(os)
            logger.warning("\(self.logTag, privacy: .public): matching credentials exist but none have a representable family (missing instanceId==0 member)")
            #endif
            return .failed(reason: "no representable credential family")
        }

        let readerTrust = await evaluateReaderAuth(docRequest, sessionTranscript: sessionTranscript)

        onStep("awaiting_consent")
        let consent = await requestConsent(docRequest.docType, docRequest.disclosedClaims(), families, readerTrust)
        let family: CredentialFamily
        switch consent {
        case .approved(let approvedFamily):
            family = approvedFamily
        case .denied:
            return .denied
        }
        let eligible = filterEligible(family.instances)
        guard !eligible.isEmpty else {
            #if canImport(os)
            logger.warning("\(self.logTag, privacy: .public): no eligible (unused) instances remain for the approved credential")
            #endif
            return .failed(reason: "no eligible instances")
        }
        // Pick a random instance from the batch rather than always the same
        // one - each instance is bound to its own device key specifically so
        // repeated presentations of "the same" credential can't be
        // correlated by a verifier via a reused public key. Always picking
        // the representative would quietly throw that unlinkability away.
        let credential = eligible.randomElement()!

        onStep("submitting_response")
        let response = try await signPresentation(credential.id, docRequest.disclosedClaims(), Data(sessionTranscript))
        let encrypted = try cipher.encrypt([UInt8](response))
        let sessionData = ProximitySessionMessages.buildSessionData(encryptedData: encrypted)
        return .response(Data(sessionData))
    }

    /// §9.1.4 reader authentication: verifies `docRequest`'s `readerAuth`
    /// COSE_Sign1 (if present) against its own embedded x5chain, then hands
    /// that chain to `evaluateReaderTrust` for the actual trust decision.
    /// Returns `nil` (no badge, not "untrusted") when there's no
    /// `readerAuth` to check or its signature doesn't verify - see
    /// `ReaderTrustResult`'s doc comment.
    private func evaluateReaderAuth(_ docRequest: DeviceRequestParser.DocRequest, sessionTranscript: [UInt8]) async -> ReaderTrustResult? {
        #if canImport(Security)
        guard let readerAuth = docRequest.readerAuth else { return nil }
        let chain = MdocCose.extractX5Chain(readerAuth)
        guard !chain.isEmpty else {
            #if canImport(os)
            logger.warning("\(self.logTag, privacy: .public): readerAuth present but has no x5chain")
            #endif
            return nil
        }
        guard let readerCert = SecCertificateCreateWithData(nil, Data(chain[0]) as CFData),
              let secKey = SecCertificateCopyKey(readerCert) else {
            #if canImport(os)
            logger.warning("\(self.logTag, privacy: .public): failed to parse readerAuth's leaf certificate")
            #endif
            return nil
        }
        var error: Unmanaged<CFError>?
        guard let publicKeyX963 = SecKeyCopyExternalRepresentation(secKey, &error) as Data? else {
            #if canImport(os)
            logger.warning("\(self.logTag, privacy: .public): failed to export readerAuth's public key")
            #endif
            return nil
        }
        guard let readerAuthenticationBytes = try? MdocCose.buildReaderAuthenticationBytes(
            sessionTranscript: sessionTranscript,
            itemsRequestTaggedBytes: docRequest.itemsRequestTaggedBytes
        ) else {
            return nil
        }
        guard MdocCose.verify1(readerAuth, payload: readerAuthenticationBytes, publicKeyX963: Array(publicKeyX963)) else {
            #if canImport(os)
            logger.warning("\(self.logTag, privacy: .public): readerAuth signature verification failed")
            #endif
            return nil
        }
        return await evaluateReaderTrust(chain)
        #else
        // No Security framework on this platform (real Apple platforms
        // always have it alongside CryptoKit, but this class's own
        // top-level gate is CryptoKit-only, so this can't silently rely on
        // that - a real Copilot-review finding) - readerAuth verification
        // needs SecCertificate/SecKey, so it's unavailable here.
        return nil
        #endif
    }

    #else

    // Non-Apple stub: the real implementation needs CryptoKit-only types
    // (`DeviceEngagement.Engagement.privateKey`, `ProximitySessionCrypto`'s
    // real ECDH/HKDF/AES-GCM), unavailable on this platform (matching
    // `ProximitySessionCrypto`'s own established convention). There are no
    // callers on non-Apple platforms today - the BLE peripheral/central glue
    // that drives this class is Apple-only.

    public var established: Bool { false }

    public func handleSessionEstablishment(_: [UInt8]) async throws -> Result {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }

    #endif
}

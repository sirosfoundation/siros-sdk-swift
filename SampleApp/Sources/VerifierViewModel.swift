// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SwiftUI
import SirosVerifier

/// Display-ready claims are created only from `MdocReaderInbound.verified`.
/// That inbound value is emitted by `MdocReaderSession` only after core
/// verification and an explicit go-trust permit for every returned document.
struct MdocVerifierClaim: Identifiable, Equatable {
    let id: String
    let docType: String
    let namespace: String
    let identifier: String
    let value: String
}

enum MdocVerifierPhase: Equatable {
    case idle
    case validating
    case readingNfc
    case startingSession
    case connecting
    case sendingRequest
    case waitingForResponse
    case evaluating
    case verified
    case denied(String)
    case sessionOver(UInt64)
    case failed(String)
    case cancelling
    case cancelled

    var progressMessage: String? {
        switch self {
        case .validating:
            return "Reading device engagement…"
        case .readingNfc:
            return "Hold near the wallet to read NFC handover…"
        case .startingSession:
            return "Starting the verifier…"
        case .connecting:
            return "Connecting over Bluetooth…"
        case .sendingRequest:
            return "Requesting given name and family name…"
        case .waitingForResponse:
            return "Waiting for the mdoc response…"
        case .evaluating:
            return "Verifying the response and checking go-trust…"
        case .cancelling:
            return "Cancelling and closing the connection…"
        default:
            return nil
        }
    }
}

/// Small sample-app seam around the concrete core session. Production uses
/// `MdocReaderSession`; sample tests inject a fake, so they never load native
/// verifier-core or depend on wallet state.
protocol VerifierReaderSession: AnyObject, Sendable {
    func establishmentMessage() async throws -> [UInt8]
    func openResponse(completeSessionData: [UInt8]) async throws -> MdocReaderInbound
    func terminationMessage() async throws -> [UInt8]
    func close() async
}

extension MdocReaderSession: VerifierReaderSession {}

/// Election remains in the resource set after `transport()` returns. Closing
/// it is what deterministically closes losing and still-pending BLE candidates
/// as well as the winner.
protocol VerifierTransportElection: AnyObject, Sendable {
    func transport() async throws -> any MdocMessageTransport
    func close() async
}

extension MdocBleTransportElection: VerifierTransportElection {}

typealias VerifierEngagementProducer = @Sendable (String) throws -> any MdocEngagement
typealias VerifierNfcEngagementProducer = @Sendable () async throws -> any MdocEngagement
typealias VerifierSessionFactory = @Sendable (
    _ engagement: any MdocEngagement,
    _ documents: [MdocDocumentRequest],
    _ evaluationEndpoint: URL,
    _ tenantId: String
) async throws -> any VerifierReaderSession
typealias VerifierElectionFactory = @Sendable (
    _ engagement: any MdocEngagement
) throws -> any VerifierTransportElection

/// Account-free ISO 18013-5 mdoc verifier flow.
///
/// This type deliberately imports neither SirosWallet nor SirosAuth and has no
/// reference to `WalletViewModel` or `WalletState`. QR and NFC static handover
/// are only engagement producers: both return any `MdocEngagement` to the same
/// core-session and BLE path. NFC never carries SessionData in this flow.
@MainActor
final class VerifierViewModel: ObservableObject {
    @Published var evaluationEndpoint: String {
        didSet { defaults.set(evaluationEndpoint, forKey: Self.endpointDefaultsKey) }
    }
    @Published var tenantId: String {
        didSet { defaults.set(tenantId, forKey: Self.tenantDefaultsKey) }
    }

    /// Root navigation is independent of `WalletViewModel.walletState`.
    @Published var isPresented = false
    @Published var isRunning = false
    @Published var phase: MdocVerifierPhase = .idle
    @Published var claims: [MdocVerifierClaim] = []

    private static let endpointDefaultsKey = "siros_verifier_evaluation_endpoint"
    private static let tenantDefaultsKey = "siros_verifier_tenant_id"

    private let defaults: UserDefaults
    private let engagementProducer: VerifierEngagementProducer
    private let nfcEngagementProducer: VerifierNfcEngagementProducer
    private let sessionFactory: VerifierSessionFactory
    private let electionFactory: VerifierElectionFactory
    private var verificationTask: Task<Void, Never>?

    init(
        defaults: UserDefaults = .standard,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        engagementProducer: VerifierEngagementProducer? = nil,
        nfcEngagementProducer: VerifierNfcEngagementProducer? = nil,
        sessionFactory: VerifierSessionFactory? = nil,
        electionFactory: VerifierElectionFactory? = nil
    ) {
        self.defaults = defaults

        #if DEBUG
        let defaultEndpoint = "http://localhost:9095/v1/evaluate"
        let defaultTenant = "default"
        #else
        // Release has no implicit trust service. Both fields must be configured
        // in the verifier screen (or seeded by the host) before scanning.
        let defaultEndpoint = ""
        let defaultTenant = ""
        #endif

        self.evaluationEndpoint = environment["SIROS_VERIFIER_EVALUATION_ENDPOINT"]
            ?? defaults.string(forKey: Self.endpointDefaultsKey)
            ?? defaultEndpoint
        self.tenantId = environment["SIROS_VERIFIER_TENANT_ID"]
            ?? defaults.string(forKey: Self.tenantDefaultsKey)
            ?? defaultTenant

        self.engagementProducer = engagementProducer ?? { qrCode in
            try MdocQrEngagement.parse(qrCode)
        }
        self.nfcEngagementProducer = nfcEngagementProducer ?? {
            #if os(iOS)
            let reader = MdocNfcEngagementReader(
                alertMessage: "Hold the top of your phone near the wallet."
            )
            // Static handover only. The returned engagement continues through
            // the same core SessionEstablishment and BLE SessionData path as QR.
            return try await reader.readHandover(timeout: 20)
            #else
            throw MdocNfcEngagementError.unavailable
            #endif
        }
        self.sessionFactory = sessionFactory ?? { engagement, documents, endpoint, tenant in
            // The complete URL is passed through unchanged. No token, cookie,
            // account session, or wallet authorization header is involved.
            let pdp = HttpAuthZenPdp(evaluationEndpoint: endpoint, tenantId: tenant)
            return try await MdocProximityVerifier(pdp: pdp).start(
                engagement: engagement,
                documents: documents
            )
        }
        self.electionFactory = electionFactory ?? { engagement in
            try MdocBleTransportFactory.start(engagement: engagement)
        }
    }

    /// Parses an `mdoc:` QR payload and starts verification. Any claims from a
    /// previous run are removed synchronously, before parsing or native startup.
    @discardableResult
    func start(qrCode: String) -> Task<Void, Never>? {
        beginVerification { [engagementProducer] in
            try engagementProducer(qrCode)
        }
    }

    /// Reads NFC static handover, then uses the same generic engagement,
    /// verifier-core session, BLE election, and complete-response path as QR.
    @discardableResult
    func startNfc() -> Task<Void, Never>? {
        beginVerification(initialPhase: .readingNfc) { [nfcEngagementProducer] in
            try await nfcEngagementProducer()
        }
    }

    /// Transport-neutral entry point for another engagement producer.
    @discardableResult
    func start(engagement: any MdocEngagement) -> Task<Void, Never>? {
        beginVerification { engagement }
    }

    func open() {
        isPresented = true
    }

    /// Cancels the active operation and does not return until transport,
    /// election (including losers), and core session cleanup have all finished.
    func cancel() async {
        claims.removeAll()
        if isRunning, let verificationTask {
            phase = .cancelling
            verificationTask.cancel()
            await verificationTask.value
        }
        verificationTask = nil
        isRunning = false
        phase = .idle
    }

    func close() async {
        await cancel()
        isPresented = false
    }

    private func beginVerification(
        initialPhase: MdocVerifierPhase = .validating,
        makeEngagement: @escaping () async throws -> any MdocEngagement
    ) -> Task<Void, Never>? {
        guard !isRunning else { return nil }

        claims.removeAll()
        phase = initialPhase
        isRunning = true
        let task = Task {
            await performVerification(makeEngagement: makeEngagement)
        }
        verificationTask = task
        return task
    }

    private func performVerification(
        makeEngagement: () async throws -> any MdocEngagement
    ) async {
        let resources = VerifierFlowResources()
        await withTaskCancellationHandler {
            do {
                let outcome = try await executeVerification(
                    makeEngagement: makeEngagement,
                    resources: resources
                )
                await resources.close()
                try Task.checkCancellation()
                apply(outcome)
            } catch {
                await resources.close()
                // No denial, outage, parse failure, session error, or
                // cancellation may leave claims from this or an earlier run.
                claims.removeAll()
                if error is CancellationError || Task.isCancelled {
                    phase = .cancelled
                } else {
                    phase = map(error)
                }
            }
        } onCancel: {
            // Core/transport operations are not assumed to react to task
            // cancellation by themselves. Closing the shared resource set
            // unblocks pending receive/election work; the operation above then
            // awaits this same idempotent cleanup before completing.
            Task { await resources.close() }
        }
        isRunning = false
    }

    private func executeVerification(
        makeEngagement: () async throws -> any MdocEngagement,
        resources: VerifierFlowResources
    ) async throws -> VerifierRunOutcome {
        let endpoint = try configuredEndpoint()
        let tenant = tenantId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !tenant.isEmpty else {
            throw VerifierConfigurationError.missingTenant
        }

        let engagement = try await makeEngagement()
        try Task.checkCancellation()

        phase = .startingSession
        let session = try await sessionFactory(
            engagement,
            Self.defaultDocumentRequests,
            endpoint,
            tenant
        )
        await resources.register(session: session)
        try Task.checkCancellation()

        phase = .connecting
        let election = try electionFactory(engagement)
        await resources.register(election: election)
        let transport = try await election.transport()
        await resources.register(transport: transport)
        try Task.checkCancellation()

        phase = .sendingRequest
        let establishment = try await session.establishmentMessage()
        try await transport.send(message: establishment)

        phase = .waitingForResponse
        // MdocMessageTransport yields one complete SessionData value, not BLE
        // fragments. Framing/reassembly stays inside the elected transport.
        let completeResponse = try await transport.receive()

        phase = .evaluating
        let inbound = try await session.openResponse(completeSessionData: completeResponse)
        try Task.checkCancellation()

        switch inbound {
        case .sessionOver(let status):
            return .sessionOver(status: status)
        case .verified(let documents):
            // Termination is courteous and optional. A failure to send it does
            // not undo an already verified and fully permitted response, but
            // cancellation still wins and never publishes claims.
            do {
                let termination = try await session.terminationMessage()
                try await transport.send(message: termination)
            } catch {
                if error is CancellationError || Task.isCancelled {
                    throw CancellationError()
                }
            }
            try Task.checkCancellation()

            var result: [MdocVerifierClaim] = []
            for document in documents {
                for (index, element) in document.elements.enumerated() {
                    result.append(MdocVerifierClaim(
                        id: "\(document.docType)|\(element.namespace)|\(element.identifier)|\(index)",
                        docType: document.docType,
                        namespace: element.namespace,
                        identifier: element.identifier,
                        value: displayValue(cbor: element.valueCbor)
                    ))
                }
            }
            return .verified(claims: result)
        }
    }

    private func apply(_ outcome: VerifierRunOutcome) {
        claims.removeAll()
        switch outcome {
        case .verified(let verifiedClaims):
            claims = verifiedClaims
            phase = .verified
        case .sessionOver(let status):
            phase = .sessionOver(status)
        }
    }

    private func configuredEndpoint() throws -> URL {
        let text = evaluationEndpoint.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { throw VerifierConfigurationError.missingEndpoint }
        guard let components = URLComponents(string: text),
              let scheme = components.scheme?.lowercased(),
              scheme == "http" || scheme == "https",
              components.host != nil,
              components.user == nil,
              components.password == nil,
              let url = components.url else {
            throw VerifierConfigurationError.invalidEndpoint
        }
        return url
    }

    private func map(_ error: Error) -> MdocVerifierPhase {
        if let pdpError = error as? AuthZenPdpError, case .denied = pdpError {
            return .denied("go-trust denied this document. No claims were shown.")
        }
        if error is AuthZenPdpError {
            return .failed("The go-trust service is unavailable or returned an invalid response. No claims were shown. \(error.localizedDescription)")
        }
        if let error = error as? MdocVerifierException, error.code == "native_unavailable" {
            return .failed("Verifier core is unavailable. Build with SIROS_VERIFIER_CORE_XCFRAMEWORK_PATH. No claims were shown.")
        }
        if let error = error as? MdocNfcEngagementError {
            switch error {
            case .unavailable:
                return .failed("NFC tag reading is unavailable on this device. No claims were shown.")
            case .timeout:
                return .failed("NFC handover timed out. No claims were shown.")
            default:
                return .failed("NFC handover failed. No claims were shown. \(error.localizedDescription)")
            }
        }
        if error is VerifierConfigurationError || error is MdocQrEngagementError {
            return .failed(String(describing: error))
        }
        return .failed("Verification failed. No claims were shown. \(error.localizedDescription)")
    }

    private static var defaultDocumentRequests: [MdocDocumentRequest] {
        [MdocDocumentRequest(
            docType: "org.iso.18013.5.1.mDL",
            namespaces: [MdocRequestedNamespace(
                namespace: "org.iso.18013.5.1",
                elements: [
                    MdocRequestedElement(identifier: "given_name", intentToRetain: false),
                    MdocRequestedElement(identifier: "family_name", intentToRetain: false),
                ]
            )]
        )]
    }
}

private enum VerifierRunOutcome {
    case verified(claims: [MdocVerifierClaim])
    case sessionOver(status: UInt64)
}

private enum VerifierConfigurationError: Error, CustomStringConvertible {
    case missingEndpoint
    case invalidEndpoint
    case missingTenant

    var description: String {
        switch self {
        case .missingEndpoint:
            return "Configure the complete go-trust evaluation URL before scanning."
        case .invalidEndpoint:
            return "The go-trust evaluation URL must be a complete HTTP(S) URL without embedded credentials."
        case .missingTenant:
            return "Configure the go-trust tenant before scanning."
        }
    }
}

/// Cancellation-safe, idempotent ownership of every asynchronous resource in a
/// run. Registration after cancellation closes the late resource immediately,
/// covering cancellation while native session startup is still in progress.
private actor VerifierFlowResources {
    private var session: (any VerifierReaderSession)?
    private var election: (any VerifierTransportElection)?
    private var transport: (any MdocMessageTransport)?
    private var closeTask: Task<Void, Never>?

    func register(session: any VerifierReaderSession) async {
        if closeTask != nil {
            await session.close()
        } else {
            self.session = session
        }
    }

    func register(election: any VerifierTransportElection) async {
        if closeTask != nil {
            await election.close()
        } else {
            self.election = election
        }
    }

    func register(transport: any MdocMessageTransport) async {
        if closeTask != nil {
            await transport.close()
        } else {
            self.transport = transport
        }
    }

    func close() async {
        if let closeTask {
            await closeTask.value
            return
        }

        let transport = self.transport
        let election = self.election
        let session = self.session
        self.transport = nil
        self.election = nil
        self.session = nil

        let task = Task {
            await transport?.close()
            await election?.close()
            await session?.close()
        }
        closeTask = task
        await task.value
    }
}

/// The default request asks for text names. Decode that useful subset without
/// adding a CBOR dependency to the app; other verified values remain available
/// as unambiguous hex rather than being guessed or coerced.
private func displayValue(cbor: [UInt8]) -> String {
    if cbor == [0xF5] { return "true" }
    if cbor == [0xF4] { return "false" }
    if cbor == [0xF6] { return "null" }

    guard let first = cbor.first, first >> 5 == 3 else {
        return hex(cbor)
    }

    var offset = 1
    guard let length = readCBORLength(cbor, additional: first & 0x1F, offset: &offset),
          length <= cbor.count - offset,
          offset + length == cbor.count,
          let text = String(bytes: cbor[offset...], encoding: .utf8) else {
        return hex(cbor)
    }
    return text
}

private func readCBORLength(_ bytes: [UInt8], additional: UInt8, offset: inout Int) -> Int? {
    if additional < 24 { return Int(additional) }
    let byteCount: Int
    switch additional {
    case 24: byteCount = 1
    case 25: byteCount = 2
    case 26: byteCount = 4
    case 27: byteCount = 8
    default: return nil
    }
    guard byteCount <= bytes.count - offset else { return nil }
    var value: UInt64 = 0
    for byte in bytes[offset..<(offset + byteCount)] {
        value = (value << 8) | UInt64(byte)
    }
    offset += byteCount
    guard value <= UInt64(Int.max) else { return nil }
    return Int(value)
}

private func hex(_ bytes: [UInt8]) -> String {
    "0x" + bytes.map { String(format: "%02x", $0) }.joined()
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import CoreBluetooth
import SirosCredentials
import SirosKeystore

/// ISO 18013-5 §8.3.3.1.1/§11.1.3 "mdoc peripheral server mode": the mdoc
/// acts as the BLE GATT server, advertising
/// `engagement.peripheralServerModeUuid` and exposing the "mdoc service"
/// characteristics (Table 5: `State`, `Client2Server`, `Server2Client`). The
/// reader connects as GATT client, writes the `SessionEstablishment` message
/// (chunked) to `Client2Server`, and this class decrypts the mdoc request,
/// offers every matching stored credential family to the user via
/// `requestConsent`, signs a `DeviceResponse` over the ISO 18013-5 proximity
/// session transcript, and notifies the encrypted `SessionData` response back
/// via `Server2Client`.
///
/// Ported from the Kotlin SDK sample app's `BlePeripheralServer.kt`, using
/// `CoreBluetooth`'s `CBPeripheralManager` instead of Android's
/// `BluetoothGattServer`/`BluetoothLeAdvertiser` - unlike NFC HCE (see
/// `NfcHandoverSelect`'s doc comment), iOS DOES support BLE peripheral
/// (GATT server) mode via CoreBluetooth, so this has a real iOS
/// implementation, not just a scoping note.
///
/// "mdoc central client mode" (this device scanning for and connecting to a
/// reader's own GATT server) is implemented separately in `BleCentralClient`,
/// which runs alongside this class - see `ProximityEngagementScreen`, which
/// wires both simultaneously since it isn't known in advance which mode a
/// given reader will pick.
///
/// Every matching credential FAMILY (see `CredentialFamily`) is offered to
/// the user via `requestConsent` before signing - no auto-selection.
///
/// UNVERIFIED ON REAL HARDWARE beyond compiling - this class has only been
/// verified by code review and reasoning about the CoreBluetooth API
/// surface - it has not been compiled (this repo's Linux dev environment
/// cannot build iOS app targets at all) or exercised against a real mdoc
/// reader. Test on a real iOS device against a real reader (e.g.
/// `sirosfoundation/siros-verifier-app`, Google's `multipaz`, or
/// digital-credentials.dev) before relying on this.
final class BlePeripheralServer: NSObject {

    static let stateUUID = CBUUID(string: "00000001-A123-48CE-896B-4C76973373E6")
    static let client2ServerUUID = CBUUID(string: "00000002-A123-48CE-896B-4C76973373E6")
    static let server2ClientUUID = CBUUID(string: "00000003-A123-48CE-896B-4C76973373E6")

    private static let stateStart: UInt8 = 0x01
    private static let stateEnd: UInt8 = 0x02

    private let engagement: DeviceEngagement.Engagement
    /// Mirrors `SirosWallet.getCredentials` - injected rather than taking a
    /// `SirosWallet`/`WalletViewModel` directly, keeping this BLE/GATT glue
    /// class independent of the app's view-model layer.
    private let getCredentials: () async -> [StoredCredential]
    /// Mirrors `SirosWallet.signMdocPresentationForProximity`.
    private let signPresentation: (_ credentialId: Int64, _ disclosedClaims: [String]?, _ sessionTranscriptBytes: Data) async throws -> Data
    /// See `RequestProximityConsent`'s doc comment.
    private let requestConsent: RequestProximityConsent
    /// Mirrors `CredentialUtils.eligibleInstances` bound to the caller's
    /// current `SirosWallet.credentialConsumptionPolicy`/`presentationHistory` -
    /// excludes instances the active consumption policy considers already
    /// used up, so a family the user approves can't sign with an exhausted
    /// instance even if `requestConsent`'s UI failed to grey it out.
    private let filterEligible: ([StoredCredential]) -> [StoredCredential]
    /// Reports a canonical step token (see `FlowProgress.swift`'s proximity
    /// step list) for driving the same progress-bar UI the issuance/
    /// presentation flows use.
    private let onStep: (String) -> Void
    private let onLog: (String) -> Void
    private let onComplete: (_ success: Bool) -> Void

    private var peripheralManager: CBPeripheralManager?
    private let reassembler = BleMessageChunker.Reassembler()
    private var server2ClientCharacteristic: CBMutableCharacteristic?
    private var deviceCipher: ProximitySessionCrypto.SessionCipher?
    private var pendingNotifications: [Data] = []
    private var completed = false
    /// Distinct from `deviceCipher != nil`: the cipher is created right after
    /// session-key derivation, well before a response is actually signed and
    /// notified back - if the reader sends STATE_END early (e.g. mid-consent,
    /// or after a timeout), `deviceCipher != nil` would already be true and
    /// incorrectly report success. Only set once the response has actually
    /// finished being sent (see `flushPendingNotifications`).
    private var responseSent = false
    /// Set by `sendNotification` once a response has been enqueued - the
    /// next time `flushPendingNotifications` fully drains the queue (whether
    /// synchronously or later via `peripheralManagerIsReady`), that means
    /// this response was completely transmitted, so `responseSent`/
    /// `completeOnce(true)` should fire then, not the instant it was enqueued.
    private var awaitingFinalFlush = false
    /// Guards `onStep("reader_connected")` firing only once per connection -
    /// see `peripheralManager(_:central:didSubscribeTo:)`'s doc comment for
    /// why that callback is used as the "reader connected" signal.
    private var reportedReaderConnected = false

    /// Default BLE ATT MTU before negotiation (23 bytes, per the Bluetooth
    /// Core Spec) - yields a 20-byte max chunk payload (MTU-3). Mirrors the
    /// Kotlin SDK's `BlePeripheralServer.DEFAULT_MTU`.
    private static let defaultMtu = 23

    init(
        engagement: DeviceEngagement.Engagement,
        getCredentials: @escaping () async -> [StoredCredential],
        signPresentation: @escaping (Int64, [String]?, Data) async throws -> Data,
        requestConsent: @escaping RequestProximityConsent,
        filterEligible: @escaping ([StoredCredential]) -> [StoredCredential],
        onStep: @escaping (String) -> Void,
        onLog: @escaping (String) -> Void,
        onComplete: @escaping (Bool) -> Void
    ) {
        self.engagement = engagement
        self.getCredentials = getCredentials
        self.signPresentation = signPresentation
        self.requestConsent = requestConsent
        self.filterEligible = filterEligible
        self.onStep = onStep
        self.onLog = onLog
        self.onComplete = onComplete
        super.init()
    }

    /// Reports the presentation's outcome exactly once - a signed response
    /// being sent and the reader's STATE_END write can both resolve to
    /// "complete" and would otherwise double-report (a real bug found via
    /// Copilot's automated review on the Kotlin SDK this was ported from,
    /// fixed in commit `e7d8872`).
    private func completeOnce(_ success: Bool) {
        guard !completed else { return }
        completed = true
        onComplete(success)
    }

    /// Start advertising the mdoc GATT service. Actual service registration
    /// happens once `peripheralManagerDidUpdateState` reports `.poweredOn` -
    /// CoreBluetooth rejects `add(_:)`/`startAdvertising(_:)` calls made
    /// before that.
    func start() {
        peripheralManager = CBPeripheralManager(delegate: self, queue: nil)
    }

    func stop() {
        peripheralManager?.stopAdvertising()
        peripheralManager?.removeAllServices()
        peripheralManager = nil
        pendingNotifications = []
    }

    private func handleStateWrite(_ value: [UInt8]) {
        guard let first = value.first else { return }
        switch first {
        case Self.stateStart:
            onLog("Reader signaled Start")
        case Self.stateEnd:
            onLog("Reader signaled End")
            stop()
            completeOnce(responseSent)
        default:
            break
        }
    }

    private func handleDataWrite(_ chunk: [UInt8], central: CBCentral) {
        guard let message = reassembler.feed(chunk) else { return }
        Task {
            do {
                if deviceCipher == nil {
                    try await handleSessionEstablishment(message, central: central)
                } else {
                    onLog("Additional SessionData messages after the first request are not yet handled")
                }
            } catch {
                onLog("Presentation failed: \(error.localizedDescription)")
                completeOnce(false)
            }
        }
    }

    /// Decrypts the incoming `SessionEstablishment`, matches stored
    /// credential families against the request, asks the user for consent,
    /// and signs/sends the response.
    ///
    /// Unlike the Kotlin SDK's `BlePeripheralServer.kt` (fixed in commit
    /// `75e4d61` after `e7d8872` initially got it wrong), this does NOT try
    /// both a QR-handover (`Handover = nil`) and an NFC-static-handover
    /// SessionTranscript variant when deriving session keys. That retry
    /// exists on Android because the SAME BLE service is reachable via both
    /// a scanned QR code and a physical NFC tap served by
    /// `MdocHostApduService`, and the BLE layer alone can't tell which one a
    /// given reader used. iOS has no `MdocHostApduService` equivalent -
    /// third-party apps cannot emulate an NFC Type 4 Tag / act as an HCE
    /// host (see `NfcHandoverSelect`'s doc comment) - so this engagement is
    /// NEVER actually reachable via NFC static handover on iOS. There is
    /// only one possible `Handover` value a real reader could have used
    /// (`nil`, the QR variant), so there is no ambiguity to retry against.
    /// This was evaluated deliberately, not missed - do not add a
    /// multi-candidate retry loop here unless iOS gains a way to actually
    /// serve NFC static handover.
    private func handleSessionEstablishment(_ message: [UInt8], central: CBCentral) async throws {
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
            onLog("Request contained no documents")
            completeOnce(false)
            return
        }

        onStep("match_credentials")
        let credentials = await getCredentials()
        let matches = credentials.filter { cred in
            cred.format == "mso_mdoc" && CredentialUtils.parseMdocDocument(cred.raw)?.docType == docRequest.docType
        }
        guard !matches.isEmpty else {
            onLog("No stored credential matches requested docType '\(docRequest.docType)'")
            completeOnce(false)
            return
        }
        let families = groupIntoFamilies(matches)

        onStep("awaiting_consent")
        let consent = await requestConsent(docRequest.docType, docRequest.disclosedClaims(), families)
        let family: CredentialFamily
        switch consent {
        case .approved(let approvedFamily):
            family = approvedFamily
        case .denied:
            completeOnce(false)
            return
        }
        let eligible = filterEligible(family.instances)
        guard !eligible.isEmpty else {
            onLog("No eligible (unused) instances remain for the approved credential")
            completeOnce(false)
            return
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
        onLog("Sending DeviceResponse for \(docRequest.docType)")
        sendNotification(sessionData, to: central)
        // completeOnce(true) fires from flushPendingNotifications once the
        // response has actually finished sending (see `responseSent`'s doc
        // comment) - not eagerly here, which would report success even if
        // CoreBluetooth's backpressure queue never drains (e.g. the reader
        // disconnects mid-transfer).
    }

    private func sendNotification(_ message: [UInt8], to central: CBCentral) {
        guard server2ClientCharacteristic != nil, peripheralManager != nil else {
            completeOnce(false)
            return
        }
        // §11.1.3.4: chunk size must respect BOTH limits, independently -
        // `central.maximumUpdateValueLength` already reflects the
        // negotiated ATT MTU minus its 3-byte header overhead, AND the
        // Bluetooth Core Specification's absolute 512-byte max attribute
        // value length. A real bug found via hardware testing in the
        // Kotlin SDK (`BlePeripheralServer.kt`): enforcing only one of
        // these is not enough - a sufficiently large negotiated MTU can
        // make MTU-3 alone exceed 512. Also floored at `defaultMtu - 3` (20
        // bytes): `BleMessageChunker.chunk` requires `maxChunkSize > 1`, and
        // an unexpected/invalid negotiated MTU should never be allowed to
        // produce a smaller (or negative) value that would crash chunking
        // outright.
        let maxChunkSize = max(min(central.maximumUpdateValueLength, 512), Self.defaultMtu - 3)
        let chunks = BleMessageChunker.chunk(message, maxChunkSize: maxChunkSize)
        pendingNotifications.append(contentsOf: chunks.map { Data($0) })
        awaitingFinalFlush = true
        flushPendingNotifications()
    }

    /// Drain `pendingNotifications` via `updateValue(_:for:onSubscribedCentrals:)`,
    /// stopping (to resume later from `peripheralManagerIsReady(toUpdateSubscribers:)`)
    /// the moment CoreBluetooth's internal transmit queue reports it's full -
    /// unlike Android's `notifyCharacteristicChanged`, CoreBluetooth requires
    /// this explicit backpressure handling; silently dropping a `false`
    /// return here would silently lose chunks. Once the queue is fully
    /// drained AND a response was actually enqueued (`awaitingFinalFlush`),
    /// the presentation is genuinely complete - see `responseSent`'s doc
    /// comment for why this, not `deviceCipher != nil` or an eager call
    /// right after `sendNotification`, is the real completion signal.
    private func flushPendingNotifications() {
        guard let characteristic = server2ClientCharacteristic, let peripheralManager else { return }
        while !pendingNotifications.isEmpty {
            let chunk = pendingNotifications[0]
            let didSend = peripheralManager.updateValue(chunk, for: characteristic, onSubscribedCentrals: nil)
            guard didSend else { return }
            pendingNotifications.removeFirst()
        }
        if awaitingFinalFlush {
            awaitingFinalFlush = false
            responseSent = true
            completeOnce(true)
        }
    }
}

extension BlePeripheralServer: CBPeripheralManagerDelegate {

    /// `.unauthorized` here is this SDK's analogue of a denied runtime
    /// Bluetooth permission - but unlike Android's `ProximityEngagementScreen.kt`
    /// (which tracked a separate `blePermissionsDenied` boolean that a real
    /// Copilot-review bug found was never reset back to false once
    /// permission was later granted), CoreBluetooth has no comparable stale-
    /// flag class of bug to begin with: `state` is read fresh from
    /// `CBPeripheralManager` every time this delegate method fires (including
    /// if the user later grants Bluetooth access and the OS re-invokes it
    /// with `.poweredOn`), not cached into a separate `@State` boolean that
    /// could go stale. Nothing to reset here.
    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        guard peripheral.state == .poweredOn else {
            if peripheral.state == .unauthorized || peripheral.state == .unsupported {
                onLog("Bluetooth is not available/authorized")
                completeOnce(false)
            }
            return
        }

        // §11.1.3.1: "The Peripheral device shall broadcast the service
        // with the UUID as received or sent during device engagement" - the
        // GATT service itself must be identified by this per-engagement
        // UUID (not a fixed constant), since that's what the reader scans
        // for and then does GATT service discovery against after
        // connecting. A real bug found via hardware testing in the Kotlin
        // SDK: registering the service under a separate fixed UUID constant
        // means a real reader never finds it after connecting.
        guard let serviceUuid = engagement.peripheralServerModeUuid else {
            onLog("engagement does not offer peripheral server mode")
            completeOnce(false)
            return
        }

        let state = CBMutableCharacteristic(
            type: Self.stateUUID,
            properties: [.notify, .writeWithoutResponse],
            value: nil,
            permissions: [.writeable]
        )
        let client2Server = CBMutableCharacteristic(
            type: Self.client2ServerUUID,
            properties: [.writeWithoutResponse],
            value: nil,
            permissions: [.writeable]
        )
        let server2Client = CBMutableCharacteristic(
            type: Self.server2ClientUUID,
            properties: [.notify],
            value: nil,
            permissions: []
        )
        server2ClientCharacteristic = server2Client

        // CoreBluetooth automatically adds the Client Characteristic
        // Configuration Descriptor (CCCD, 0x2902) for any `.notify`/
        // `.indicate` characteristic - unlike Android's BluetoothGattServer,
        // where it must be added manually.
        let service = CBMutableService(type: CBUUID(nsuuid: serviceUuid), primary: true)
        service.characteristics = [state, client2Server, server2Client]
        peripheral.add(service)
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didAdd service: CBService, error: Error?) {
        if let error {
            onLog("Failed to add GATT service: \(error.localizedDescription)")
            completeOnce(false)
            return
        }
        guard let serviceUuid = engagement.peripheralServerModeUuid else { return }
        peripheral.startAdvertising([
            CBAdvertisementDataServiceUUIDsKey: [CBUUID(nsuuid: serviceUuid)],
        ])
        onLog("Advertising mdoc peripheral service as \(serviceUuid)")
        onStep("waiting_for_reader")
    }

    func peripheralManagerDidStartAdvertising(_ peripheral: CBPeripheralManager, error: Error?) {
        if let error {
            onLog("BLE advertise failed to start: \(error.localizedDescription)")
            completeOnce(false)
        }
    }

    /// CoreBluetooth's `CBPeripheralManagerDelegate` has no direct
    /// "central connected" callback the way Android's
    /// `BluetoothGattServerCallback.onConnectionStateChange` does - a
    /// central's connection is only implicitly observable once it does
    /// something with the GATT service. A reader subscribing to a
    /// characteristic's notifications is the earliest such signal
    /// (reliably happens before it writes SessionEstablishment data), so
    /// this is used as the `"reader_connected"` progress step trigger,
    /// guarded to fire only once per session via `reportedReaderConnected`.
    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didSubscribeTo characteristic: CBCharacteristic) {
        onLog("Reader subscribed to \(characteristic.uuid)")
        if !reportedReaderConnected {
            reportedReaderConnected = true
            onStep("reader_connected")
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didUnsubscribeFrom characteristic: CBCharacteristic) {
        onLog("Reader unsubscribed from \(characteristic.uuid)")
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
        // Apple's documented convention for a batch write: respond once for
        // the entire batch, passing the FIRST request in `requests`.
        if let first = requests.first {
            peripheral.respond(to: first, withResult: .success)
        }
        for request in requests {
            guard let value = request.value else { continue }
            switch request.characteristic.uuid {
            case Self.stateUUID:
                handleStateWrite([UInt8](value))
            case Self.client2ServerUUID:
                handleDataWrite([UInt8](value), central: request.central)
            default:
                break
            }
        }
    }

    func peripheralManagerIsReady(toUpdateSubscribers peripheral: CBPeripheralManager) {
        flushPendingNotifications()
    }
}

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
/// selects a stored credential via `selectCredential`, signs a
/// `DeviceResponse` over the ISO 18013-5 proximity session transcript, and
/// notifies the encrypted `SessionData` response back via `Server2Client`.
///
/// Ported from the Kotlin SDK sample app's `BlePeripheralServer.kt`, using
/// `CoreBluetooth`'s `CBPeripheralManager` instead of Android's
/// `BluetoothGattServer`/`BluetoothLeAdvertiser` - unlike NFC HCE (see
/// `NfcHandoverSelect`'s doc comment), iOS DOES support BLE peripheral
/// (GATT server) mode via CoreBluetooth, so this has a real iOS
/// implementation, not just a scoping note.
///
/// "mdoc central client mode" (this device scanning for and connecting to a
/// reader's own GATT server) is NOT implemented here, matching the Kotlin
/// SDK's own scope cut - peripheral-server-mode alone is a complete,
/// spec-valid BLE data-retrieval option.
///
/// No consent UI yet: `selectCredential` defaults to
/// `BlePeripheralServer.autoSelectFirstMatch`, which auto-presents the first
/// stored mdoc credential whose real docType matches the request, disclosing
/// exactly the requested element identifiers. This is a real, deliberate
/// scope cut (matching the Kotlin SDK), not an oversight - kept as its own
/// small, swappable closure so a real consent UI can replace it later
/// without touching the surrounding BLE/GATT plumbing.
///
/// UNVERIFIED ON REAL HARDWARE: this class has only been verified by code
/// review and reasoning about the CoreBluetooth API surface - it has not
/// been compiled (this repo's Linux dev environment cannot build iOS app
/// targets at all) or exercised against a real mdoc reader. Test on a real
/// iOS device against a real reader (e.g. `sirosfoundation/siros-verifier-app`,
/// Google's `multipaz`, or digital-credentials.dev) before relying on this.
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
    /// Which credential (if any) to present for an incoming request - see
    /// this type's doc comment for why this is its own swappable closure.
    private let selectCredential: (_ credentials: [StoredCredential], _ request: DeviceRequestParser.DocRequest) -> StoredCredential?
    private let onLog: (String) -> Void
    private let onComplete: (_ success: Bool) -> Void

    private var peripheralManager: CBPeripheralManager?
    private let reassembler = BleMessageChunker.Reassembler()
    private var server2ClientCharacteristic: CBMutableCharacteristic?
    private var deviceCipher: ProximitySessionCrypto.SessionCipher?
    private var pendingNotifications: [Data] = []

    init(
        engagement: DeviceEngagement.Engagement,
        getCredentials: @escaping () async -> [StoredCredential],
        signPresentation: @escaping (Int64, [String]?, Data) async throws -> Data,
        selectCredential: @escaping ([StoredCredential], DeviceRequestParser.DocRequest) -> StoredCredential? = BlePeripheralServer.autoSelectFirstMatch,
        onLog: @escaping (String) -> Void,
        onComplete: @escaping (Bool) -> Void
    ) {
        self.engagement = engagement
        self.getCredentials = getCredentials
        self.signPresentation = signPresentation
        self.selectCredential = selectCredential
        self.onLog = onLog
        self.onComplete = onComplete
        super.init()
    }

    /// Default credential-selection policy: auto-select the first stored
    /// mdoc credential whose real docType (parsed from its own MSO, not
    /// display metadata - see `CredentialUtils.parseMdocDocument`) matches
    /// the request. See this type's doc comment for why this exists as its
    /// own swappable static function.
    static func autoSelectFirstMatch(
        _ credentials: [StoredCredential],
        _ request: DeviceRequestParser.DocRequest
    ) -> StoredCredential? {
        credentials.first { cred in
            cred.format == "mso_mdoc" && CredentialUtils.parseMdocDocument(cred.raw)?.docType == request.docType
        }
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
            let completedOk = deviceCipher != nil
            stop()
            onComplete(completedOk)
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
                onComplete(false)
            }
        }
    }

    private func handleSessionEstablishment(_ message: [UInt8], central: CBCentral) async throws {
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
            return
        }

        let credentials = await getCredentials()
        guard let credential = selectCredential(credentials, docRequest) else {
            onLog("No stored credential matches requested docType '\(docRequest.docType)'")
            onComplete(false)
            return
        }

        let response = try await signPresentation(credential.id, docRequest.disclosedClaims(), Data(sessionTranscript))
        let encrypted = try cipher.encrypt([UInt8](response))
        let sessionData = ProximitySessionMessages.buildSessionData(encryptedData: encrypted)
        sendNotification(sessionData, to: central)
        onLog("Sent DeviceResponse for \(docRequest.docType)")
        onComplete(true)
    }

    private func sendNotification(_ message: [UInt8], to central: CBCentral) {
        guard server2ClientCharacteristic != nil, peripheralManager != nil else { return }
        // §11.1.3.4: chunk size must respect BOTH limits, independently -
        // `central.maximumUpdateValueLength` already reflects the
        // negotiated ATT MTU minus its 3-byte header overhead, AND the
        // Bluetooth Core Specification's absolute 512-byte max attribute
        // value length. A real bug found via hardware testing in the
        // Kotlin SDK (`BlePeripheralServer.kt`): enforcing only one of
        // these is not enough - a sufficiently large negotiated MTU can
        // make MTU-3 alone exceed 512.
        let maxChunkSize = min(central.maximumUpdateValueLength, 512)
        let chunks = BleMessageChunker.chunk(message, maxChunkSize: maxChunkSize)
        pendingNotifications.append(contentsOf: chunks.map { Data($0) })
        flushPendingNotifications()
    }

    /// Drain `pendingNotifications` via `updateValue(_:for:onSubscribedCentrals:)`,
    /// stopping (to resume later from `peripheralManagerIsReady(toUpdateSubscribers:)`)
    /// the moment CoreBluetooth's internal transmit queue reports it's full -
    /// unlike Android's `notifyCharacteristicChanged`, CoreBluetooth requires
    /// this explicit backpressure handling; silently dropping a `false`
    /// return here would silently lose chunks.
    private func flushPendingNotifications() {
        guard let characteristic = server2ClientCharacteristic, let peripheralManager else { return }
        while !pendingNotifications.isEmpty {
            let chunk = pendingNotifications[0]
            let didSend = peripheralManager.updateValue(chunk, for: characteristic, onSubscribedCentrals: nil)
            guard didSend else { return }
            pendingNotifications.removeFirst()
        }
    }
}

extension BlePeripheralServer: CBPeripheralManagerDelegate {

    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        guard peripheral.state == .poweredOn else {
            if peripheral.state == .unauthorized || peripheral.state == .unsupported {
                onLog("Bluetooth is not available/authorized")
                onComplete(false)
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
            onComplete(false)
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
            onComplete(false)
            return
        }
        guard let serviceUuid = engagement.peripheralServerModeUuid else { return }
        peripheral.startAdvertising([
            CBAdvertisementDataServiceUUIDsKey: [CBUUID(nsuuid: serviceUuid)],
        ])
        onLog("Advertising mdoc peripheral service as \(serviceUuid)")
    }

    func peripheralManagerDidStartAdvertising(_ peripheral: CBPeripheralManager, error: Error?) {
        if let error {
            onLog("BLE advertise failed to start: \(error.localizedDescription)")
            onComplete(false)
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral, didSubscribeTo characteristic: CBCharacteristic) {
        onLog("Reader subscribed to \(characteristic.uuid)")
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

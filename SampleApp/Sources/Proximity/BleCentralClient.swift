// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import CoreBluetooth
import SirosCredentials
import SirosKeystore

/// ISO 18013-5 §8.3.3.1.1/§11.1.3 "mdoc central client mode": the mdoc acts
/// as the BLE GATT CLIENT, scanning for and connecting to a reader that
/// advertises `engagement.centralClientModeUuid` as its own GATT service
/// UUID (per §11.1.3.1 - the reader is the peripheral/advertiser in this
/// mode, the mirror image of `BlePeripheralServer`). Discovers the reader's
/// "mdoc reader service" (Table 6: `State`, `Client2Server`,
/// `Server2Client`, `Ident`), verifies the reader's identity via the `Ident`
/// characteristic, then runs the same session-establishment/session-data
/// protocol as `BlePeripheralServer` with the GATT roles reversed: this mdoc
/// WRITES to `Client2Server` and receives via `Server2Client` notify
/// (§11.1.3.4: "Client2Server" always carries GATT-client-to-server traffic
/// and "Server2Client" always carries the reverse, regardless of which side -
/// mdoc or reader - holds the GATT client/server role for a given
/// transaction).
///
/// Ported from the Kotlin SDK sample app's `BleCentralClient.kt`, using
/// `CoreBluetooth`'s `CBCentralManager`/`CBPeripheral` instead of Android's
/// `BluetoothLeScanner`/`BluetoothGatt`.
///
/// Unlike Android's GATT client API, CoreBluetooth has no explicit
/// MTU-negotiation callback (`onMtuChanged`) to hook a `"reader_connected"`-
/// style step or a stored MTU value into - the negotiated write/notification
/// size is queried on demand via `peripheral.maximumWriteValueLength(for:)`
/// at send time instead of cached from a one-time callback. CoreBluetooth
/// also has looser characteristic-discovery/notification-enable sequencing
/// requirements than Android's chained GATT callbacks (`onDescriptorWrite`
/// chaining one subscribe after another) - this reads the `Ident`
/// characteristic and enables notifications on `State`/`Server2Client` in
/// parallel rather than a strict chain, waiting for all three to complete
/// (via `maybeWriteStateStart`) before writing STATE_START, since only the
/// END STATE (not the exact callback order) matters for correctness.
///
/// UNVERIFIED ON REAL HARDWARE beyond compiling - there is no second BLE
/// GATT-server test tool available yet (the same gap the Kotlin SDK's
/// equivalent class doc comment notes: `tools/ble_reader_test.py` uses
/// `bleak`, which is central/client-only on every platform, the same role
/// this class plays - it cannot stand in as a peripheral to test against).
/// Needs testing against either a real ISO 18013-5 reader or a purpose-built
/// BLE-peripheral test script before relying on it. This is a brand-new
/// port with no prior Swift version to carry forward any hardware
/// verification from, unlike `BlePeripheralServer`.
final class BleCentralClient: NSObject {

    // Table 6 - mdoc reader service characteristics (present when the reader is the GATT server).
    static let stateUUID = CBUUID(string: "00000005-A123-48CE-896B-4C76973373E6")
    static let client2ServerUUID = CBUUID(string: "00000006-A123-48CE-896B-4C76973373E6")
    static let server2ClientUUID = CBUUID(string: "00000007-A123-48CE-896B-4C76973373E6")
    static let identUUID = CBUUID(string: "00000008-A123-48CE-896B-4C76973373E6")

    private static let stateStart: UInt8 = 0x01

    private let engagement: DeviceEngagement.Engagement
    /// Mirrors `SirosWallet.getCredentials` - see `BlePeripheralServer`'s matching parameter doc comment.
    private let getCredentials: () async -> [StoredCredential]
    /// Mirrors `SirosWallet.signMdocPresentationForProximity`.
    private let signPresentation: (_ credentialId: Int64, _ disclosedClaims: [String]?, _ sessionTranscriptBytes: Data) async throws -> Data
    /// See `RequestProximityConsent`'s doc comment.
    private let requestConsent: RequestProximityConsent
    /// Reports a canonical step token (see `FlowProgress.swift`'s proximity
    /// step list) for driving the same progress-bar UI the issuance/
    /// presentation flows use.
    private let onStep: (String) -> Void
    private let onLog: (String) -> Void
    private let onComplete: (_ success: Bool) -> Void

    private var centralManager: CBCentralManager?
    private var peripheral: CBPeripheral?
    private let reassembler = BleMessageChunker.Reassembler()
    private var stateCharacteristic: CBCharacteristic?
    private var client2ServerCharacteristic: CBCharacteristic?
    private var deviceCipher: ProximitySessionCrypto.SessionCipher?
    private var identVerified = false
    private var notifyReady: Set<CBUUID> = []
    private var wroteStateStart = false

    init(
        engagement: DeviceEngagement.Engagement,
        getCredentials: @escaping () async -> [StoredCredential],
        signPresentation: @escaping (Int64, [String]?, Data) async throws -> Data,
        requestConsent: @escaping RequestProximityConsent,
        onStep: @escaping (String) -> Void,
        onLog: @escaping (String) -> Void,
        onComplete: @escaping (Bool) -> Void
    ) {
        self.engagement = engagement
        self.getCredentials = getCredentials
        self.signPresentation = signPresentation
        self.requestConsent = requestConsent
        self.onStep = onStep
        self.onLog = onLog
        self.onComplete = onComplete
        super.init()
    }

    /// Start scanning for a reader advertising this engagement's central-client-mode service UUID.
    /// Actual scanning starts once `centralManagerDidUpdateState` reports `.poweredOn`, matching
    /// `BlePeripheralServer.start()`'s deferred-until-poweredOn pattern.
    func start() {
        guard engagement.centralClientModeUuid != nil else {
            onLog("engagement does not offer central client mode")
            onComplete(false)
            return
        }
        centralManager = CBCentralManager(delegate: self, queue: nil)
    }

    func stop() {
        if let peripheral {
            centralManager?.cancelPeripheralConnection(peripheral)
        }
        centralManager?.stopScan()
        centralManager = nil
        peripheral = nil
    }

    /// Writes STATE_START once both prerequisites are satisfied: the
    /// reader's identity has been verified via `Ident`, and notifications
    /// are enabled on both `State` and `Server2Client`. Guarded by
    /// `wroteStateStart` since `Ident`-read completion and
    /// notification-enable completion can arrive in either order (see this
    /// type's doc comment) and both call into this function.
    private func maybeWriteStateStart(_ peripheral: CBPeripheral) {
        guard !wroteStateStart,
              identVerified,
              notifyReady.contains(Self.stateUUID),
              notifyReady.contains(Self.server2ClientUUID),
              let stateCharacteristic
        else { return }
        wroteStateStart = true
        peripheral.writeValue(Data([Self.stateStart]), for: stateCharacteristic, type: .withoutResponse)
    }

    /// Decrypts the incoming `SessionEstablishment`, matches stored
    /// credential families against the request, asks the user for consent,
    /// and signs/sends the response - mirrors `BlePeripheralServer`'s
    /// method of the same name. Unlike that method (and unlike Kotlin's own
    /// `BlePeripheralServer.kt`), this does NOT need a QR-vs-NFC handover
    /// retry: Kotlin's own `BleCentralClient.kt` doesn't have one either -
    /// central-client mode is always initiated by THIS device scanning for
    /// a reader's advertisement, which has no NFC-handover counterpart to be
    /// ambiguous with in the first place.
    private func handleSessionEstablishment(_ message: [UInt8]) async throws {
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
            onComplete(false)
            return
        }

        onStep("match_credentials")
        let credentials = await getCredentials()
        let matches = credentials.filter { cred in
            cred.format == "mso_mdoc" && CredentialUtils.parseMdocDocument(cred.raw)?.docType == docRequest.docType
        }
        guard !matches.isEmpty else {
            onLog("No stored credential matches requested docType '\(docRequest.docType)'")
            onComplete(false)
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
            onComplete(false)
            return
        }
        // See BlePeripheralServer's matching comment: pick a random instance
        // from the batch, not always the same one, to preserve unlinkability.
        let credential = family.instances.randomElement() ?? family.representative

        onStep("submitting_response")
        let response = try await signPresentation(credential.id, docRequest.disclosedClaims(), Data(sessionTranscript))
        let encrypted = try cipher.encrypt([UInt8](response))
        let sessionData = ProximitySessionMessages.buildSessionData(encryptedData: encrypted)
        sendData(sessionData)
        onComplete(true)
    }

    private func sendData(_ message: [UInt8]) {
        guard let characteristic = client2ServerCharacteristic, let peripheral else { return }
        let maxChunkSize = min(peripheral.maximumWriteValueLength(for: .withoutResponse), 512)
        let chunks = BleMessageChunker.chunk(message, maxChunkSize: maxChunkSize)
        for chunk in chunks {
            peripheral.writeValue(Data(chunk), for: characteristic, type: .withoutResponse)
        }
    }
}

extension BleCentralClient: CBCentralManagerDelegate {

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        guard central.state == .poweredOn else {
            if central.state == .unauthorized || central.state == .unsupported {
                onLog("Bluetooth is not available/authorized")
                onComplete(false)
            }
            return
        }
        guard let serviceUuid = engagement.centralClientModeUuid else { return }
        onStep("waiting_for_reader")
        central.scanForPeripherals(withServices: [CBUUID(nsuuid: serviceUuid)], options: nil)
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral, advertisementData: [String: Any], rssi RSSI: NSNumber) {
        central.stopScan()
        self.peripheral = peripheral
        peripheral.delegate = self
        central.connect(peripheral, options: nil)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        onStep("reader_connected")
        guard let serviceUuid = engagement.centralClientModeUuid else { return }
        peripheral.discoverServices([CBUUID(nsuuid: serviceUuid)])
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        onLog("Failed to connect to reader: \(error?.localizedDescription ?? "unknown error")")
        onComplete(false)
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        if deviceCipher == nil {
            onLog("Reader disconnected before completing a presentation")
            onComplete(false)
        }
    }
}

extension BleCentralClient: CBPeripheralDelegate {

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        if let error {
            onLog("Failed to discover services: \(error.localizedDescription)")
            onComplete(false)
            return
        }
        guard let service = peripheral.services?.first else {
            onLog("reader has no service matching this engagement's central-client-mode UUID")
            onComplete(false)
            centralManager?.cancelPeripheralConnection(peripheral)
            return
        }
        peripheral.discoverCharacteristics(
            [Self.stateUUID, Self.client2ServerUUID, Self.server2ClientUUID, Self.identUUID],
            for: service
        )
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        if let error {
            onLog("Failed to discover characteristics: \(error.localizedDescription)")
            onComplete(false)
            return
        }
        let byUUID = Dictionary(uniqueKeysWithValues: (service.characteristics ?? []).map { ($0.uuid, $0) })
        guard let identCharacteristic = byUUID[Self.identUUID],
              let stateCharacteristic = byUUID[Self.stateUUID],
              let client2ServerCharacteristic = byUUID[Self.client2ServerUUID],
              let server2ClientCharacteristic = byUUID[Self.server2ClientUUID]
        else {
            onLog("reader's mdoc reader service is missing required characteristics")
            onComplete(false)
            centralManager?.cancelPeripheralConnection(peripheral)
            return
        }
        self.stateCharacteristic = stateCharacteristic
        self.client2ServerCharacteristic = client2ServerCharacteristic

        peripheral.readValue(for: identCharacteristic)
        peripheral.setNotifyValue(true, for: stateCharacteristic)
        peripheral.setNotifyValue(true, for: server2ClientCharacteristic)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        if let error {
            onLog("Failed to enable notifications for \(characteristic.uuid): \(error.localizedDescription)")
            return
        }
        guard characteristic.isNotifying else { return }
        notifyReady.insert(characteristic.uuid)
        maybeWriteStateStart(peripheral)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        if let error {
            onLog("Failed to read/receive \(characteristic.uuid): \(error.localizedDescription)")
            return
        }
        guard let value = characteristic.value else { return }

        switch characteristic.uuid {
        case Self.identUUID:
            let expected = ProximitySessionCrypto.computeIdent(engagement.eDeviceKeyBytes)
            guard [UInt8](value) == expected else {
                onLog("Ident characteristic mismatch - not the reader this engagement was intended for, terminating")
                onComplete(false)
                centralManager?.cancelPeripheralConnection(peripheral)
                return
            }
            identVerified = true
            maybeWriteStateStart(peripheral)

        case Self.server2ClientUUID:
            guard let message = reassembler.feed([UInt8](value)) else { return }
            Task {
                do {
                    try await handleSessionEstablishment(message)
                } catch {
                    onLog("Proximity presentation failed: \(error.localizedDescription)")
                    onComplete(false)
                }
            }

        default:
            break
        }
    }
}

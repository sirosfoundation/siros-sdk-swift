// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

#if canImport(CoreBluetooth)
import Foundation
import CoreBluetooth
import SirosCredentials

/// ISO 18013-5 §8.3.3.1.1/§11.1.3 "mdoc central client mode": the mdoc acts
/// as the BLE GATT CLIENT, scanning for and connecting to a reader that
/// advertises `engagement.centralClientModeUuid` as its own GATT service
/// UUID (per §11.1.3.1 - the reader is the peripheral/advertiser in this
/// mode, the mirror image of `BlePeripheralServer`). Discovers the reader's
/// "mdoc reader service" (Table 6: `State`, `Client2Server`,
/// `Server2Client`, `Ident`), verifies the reader's identity via the `Ident`
/// characteristic, then runs the same session-establishment/session-data
/// protocol as `BlePeripheralServer` (via the shared `MdocProximitySession`)
/// with the GATT roles reversed: this mdoc WRITES to `Client2Server` and
/// receives via `Server2Client` notify (§11.1.3.4: "Client2Server" always
/// carries GATT-client-to-server traffic and "Server2Client" always carries
/// the reverse, regardless of which side - mdoc or reader - holds the GATT
/// client/server role for a given transaction).
///
/// Ported from the Kotlin SDK's `BleCentralClient.kt`, using
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
/// equivalent class doc comment notes: siros-verifier-cli's `siros-verify
/// read` command, https://github.com/sirosfoundation/siros-verifier-cli,
/// uses `bleak`, which is central/client-only on every platform, the same
/// role this class plays - it cannot stand in as a peripheral to test
/// against).
/// Needs testing against either a real ISO 18013-5 reader or a purpose-built
/// BLE-peripheral test script before relying on it.
public final class BleCentralClient: NSObject {

    // Table 6 - mdoc reader service characteristics (present when the reader is the GATT server).
    static let stateUUID = CBUUID(string: "00000005-A123-48CE-896B-4C76973373E6")
    static let client2ServerUUID = CBUUID(string: "00000006-A123-48CE-896B-4C76973373E6")
    static let server2ClientUUID = CBUUID(string: "00000007-A123-48CE-896B-4C76973373E6")
    static let identUUID = CBUUID(string: "00000008-A123-48CE-896B-4C76973373E6")

    private static let stateStart: UInt8 = 0x01
    private static let stateEnd: UInt8 = 0x02

    /// Default BLE ATT MTU before negotiation (23 bytes, per the Bluetooth
    /// Core Spec) - yields a 20-byte max chunk payload (MTU-3). Mirrors the
    /// Kotlin SDK's `BleCentralClient.DEFAULT_MTU`.
    private static let defaultMtu = 23

    private let engagement: DeviceEngagement.Engagement
    private let onStep: (String) -> Void
    private let onLog: (String) -> Void
    private let onComplete: (_ success: Bool) -> Void
    private let session: MdocProximitySession

    private var centralManager: CBCentralManager?
    private var peripheral: CBPeripheral?
    private let reassembler = BleMessageChunker.Reassembler()
    private var stateCharacteristic: CBCharacteristic?
    private var client2ServerCharacteristic: CBCharacteristic?
    private var identVerified = false
    private var notifyReady: Set<CBUUID> = []
    private var wroteStateStart = false
    /// Set synchronously, before spawning the session-establishment `Task`,
    /// the first time a complete SessionData message arrives - NOT the same
    /// guard as `session.established` (which only flips true partway through
    /// that Task's async body, once key derivation completes). Checking
    /// `session.established` from inside the spawned `Task` was the actual
    /// guard originally, but that's a check-then-act race: unlike Kotlin's
    /// coroutines (serialized onto a single-threaded dispatcher for this
    /// exact reason), an unstructured Swift `Task` has no such guarantee -
    /// two `Task`s spawned from consecutive (CoreBluetooth-serialized)
    /// delegate callbacks can run their bodies concurrently on different
    /// threads, so both could observe `established == false` and both start
    /// processing the same reassembled message. This flag is only ever
    /// touched from `didUpdateValueFor`, which CoreBluetooth already
    /// delivers serially (the manager was created with `queue: nil`), so a
    /// plain `Bool` - checked and set before the `Task` exists at all -
    /// closes the race without needing a lock.
    private var sessionEstablishmentStarted = false
    /// Resumed by `peripheralIsReady(toSendWriteWithoutResponse:)` - see
    /// `waitUntilReadyToWrite`'s doc comment for why this throttling exists.
    private var writeReadyContinuation: CheckedContinuation<Void, Never>?

    public init(
        engagement: DeviceEngagement.Engagement,
        getCredentials: @escaping () async -> [StoredCredential],
        signPresentation: @escaping (Int64, [String]?, Data) async throws -> Data,
        requestConsent: @escaping RequestProximityConsent,
        evaluateReaderTrust: @escaping (_ x5chain: [[UInt8]]) async -> ReaderTrustResult,
        filterEligible: @escaping ([StoredCredential]) -> [StoredCredential],
        onStep: @escaping (String) -> Void,
        onLog: @escaping (String) -> Void,
        onComplete: @escaping (Bool) -> Void
    ) {
        self.engagement = engagement
        self.onStep = onStep
        self.onLog = onLog
        self.onComplete = onComplete
        self.session = MdocProximitySession(
            engagement: engagement,
            getCredentials: getCredentials,
            signPresentation: signPresentation,
            requestConsent: requestConsent,
            evaluateReaderTrust: evaluateReaderTrust,
            filterEligible: filterEligible,
            onStep: onStep,
            logTag: "BleCentralClient"
        )
        super.init()
    }

    /// Start scanning for a reader advertising this engagement's central-client-mode service UUID.
    /// Actual scanning starts once `centralManagerDidUpdateState` reports `.poweredOn`, matching
    /// `BlePeripheralServer.start()`'s deferred-until-poweredOn pattern.
    public func start() {
        guard engagement.centralClientModeUuid != nil else {
            onLog("engagement does not offer central client mode")
            onComplete(false)
            return
        }
        centralManager = CBCentralManager(delegate: self, queue: nil)
    }

    public func stop() {
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

    /// Suspends until CoreBluetooth's internal transmit queue can accept
    /// another `.withoutResponse` write. Unlike Android's
    /// `BluetoothGatt.writeCharacteristic` (which returns `false` and blocks
    /// on `onCharacteristicWrite` when its own queue is full - a real bug
    /// this SDK found and fixed via hardware testing when unpaced), CoreBluetooth's
    /// `.withoutResponse` write is fire-and-forget with no per-write
    /// delivery confirmation to await - but it silently DROPS a write
    /// issued while `canSendWriteWithoutResponse` is false rather than
    /// queuing it, so a large multi-chunk `DeviceResponse` written in a
    /// tight loop can lose chunks exactly the same way the Android bug did,
    /// just via a different mechanism. `BlePeripheralServer`'s
    /// `flushPendingNotifications`/`peripheralManagerIsReady` already
    /// handles this correctly on the peripheral side; this is the
    /// equivalent throttle for the central-role write path.
    private func waitUntilReadyToWrite() async {
        guard let peripheral, !peripheral.canSendWriteWithoutResponse else { return }
        await withCheckedContinuation { continuation in
            writeReadyContinuation = continuation
        }
    }

    /// Writes the encrypted response to `Client2Server`, chunked, then signals
    /// STATE_END on `State` - matching peripheral-server-mode's more careful
    /// state handling (Kotlin's `BleCentralClient.kt` originally omitted this;
    /// a strict reader could otherwise keep the transaction open waiting for
    /// it unnecessarily).
    private func sendData(_ message: [UInt8]) async {
        guard let characteristic = client2ServerCharacteristic, let peripheral else { return }
        // Floored at `defaultMtu - 3` (20 bytes): `BleMessageChunker.chunk`
        // requires `maxChunkSize > 1`, and an unexpected/invalid negotiated
        // write length should never be allowed to produce a smaller (or
        // negative) value that would crash chunking outright.
        let maxChunkSize = max(min(peripheral.maximumWriteValueLength(for: .withoutResponse), 512), Self.defaultMtu - 3)
        let chunks = BleMessageChunker.chunk(message, maxChunkSize: maxChunkSize)
        for chunk in chunks {
            await waitUntilReadyToWrite()
            peripheral.writeValue(Data(chunk), for: characteristic, type: .withoutResponse)
        }
        if let stateCharacteristic {
            await waitUntilReadyToWrite()
            peripheral.writeValue(Data([Self.stateEnd]), for: stateCharacteristic, type: .withoutResponse)
        }
    }
}

extension BleCentralClient: CBCentralManagerDelegate {

    public func centralManagerDidUpdateState(_ central: CBCentralManager) {
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

    public func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral, advertisementData: [String: Any], rssi RSSI: NSNumber) {
        central.stopScan()
        self.peripheral = peripheral
        peripheral.delegate = self
        central.connect(peripheral, options: nil)
    }

    public func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        onStep("reader_connected")
        guard let serviceUuid = engagement.centralClientModeUuid else { return }
        peripheral.discoverServices([CBUUID(nsuuid: serviceUuid)])
    }

    public func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        onLog("Failed to connect to reader: \(error?.localizedDescription ?? "unknown error")")
        onComplete(false)
    }

    public func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        if !session.established {
            onLog("Reader disconnected before completing a presentation")
            onComplete(false)
        }
    }
}

extension BleCentralClient: CBPeripheralDelegate {

    public func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
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

    public func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
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

    public func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        if let error {
            onLog("Failed to enable notifications for \(characteristic.uuid): \(error.localizedDescription)")
            return
        }
        guard characteristic.isNotifying else { return }
        notifyReady.insert(characteristic.uuid)
        maybeWriteStateStart(peripheral)
    }

    public func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
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
            guard !sessionEstablishmentStarted else {
                onLog("Additional SessionData messages after the first request are not yet handled")
                return
            }
            sessionEstablishmentStarted = true
            Task {
                do {
                    switch try await session.handleSessionEstablishment(message) {
                    case .response(let sessionData):
                        await sendData([UInt8](sessionData))
                        onComplete(true)
                    case .denied:
                        onComplete(false)
                    case .failed:
                        onComplete(false)
                    }
                } catch {
                    onLog("Proximity presentation failed: \(error.localizedDescription)")
                    onComplete(false)
                }
            }

        default:
            break
        }
    }

    /// Resumes any write suspended in `waitUntilReadyToWrite` once
    /// CoreBluetooth's internal transmit queue has drained.
    public func peripheralIsReady(toSendWriteWithoutResponse peripheral: CBPeripheral) {
        writeReadyContinuation?.resume()
        writeReadyContinuation = nil
    }
}
#endif

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

#if os(iOS) && canImport(CoreBluetooth)
import CoreBluetooth
import Foundation

/// Reader as GATT client for mdoc peripheral-server mode. Readiness means both
/// notification subscriptions are active and STATE_START has been issued.
internal final class MdocBleGattClientTransport: MdocBleTransportBase,
    CBCentralManagerDelegate, CBPeripheralDelegate, @unchecked Sendable {

    private let serviceUuid: UUID
    private let handshake = MdocBleClientHandshake()
    private let writeGate = MdocBleWriteReadyGate()

    private var centralManager: CBCentralManager?
    private var peripheral: CBPeripheral?
    private var stateCharacteristic: CBCharacteristic?
    private var client2ServerCharacteristic: CBCharacteristic?
    private var stateStartScheduled = false

    init(
        serviceUuid: UUID,
        onReady: @escaping @Sendable (any MdocBleCandidate) -> Void,
        onFailure: @escaping @Sendable (any MdocBleCandidate, Error) -> Void
    ) {
        self.serviceUuid = serviceUuid
        super.init(
            role: "mdoc peripheral-server mode",
            onReady: onReady,
            onFailure: onFailure
        )
    }

    override func startRadio() throws {
        centralManager = CBCentralManager(delegate: self, queue: nil)
    }

    override func closeRadio() {
        writeGate.abort()
        centralManager?.stopScan()
        if let peripheral {
            peripheral.delegate = nil
            centralManager?.cancelPeripheralConnection(peripheral)
        }
        centralManager = nil
        peripheral = nil
        stateCharacteristic = nil
        client2ServerCharacteristic = nil
    }

    override func currentMaxChunkSize() -> Int {
        guard let peripheral else { return MdocBleProtocol.defaultMtu - 3 }
        return MdocBleProtocol.maxChunkSize(
            attributeValueLength: peripheral.maximumWriteValueLength(for: .withoutResponse)
        )
    }

    override func sendChunk(_ chunk: [UInt8]) async throws {
        guard let peripheral, let client2ServerCharacteristic else {
            throw MdocBleTransportError.disconnected("GATT client is disconnected")
        }
        try await write(chunk, to: client2ServerCharacteristic, peripheral: peripheral)
    }

    private func write(
        _ value: [UInt8],
        to characteristic: CBCharacteristic,
        peripheral: CBPeripheral
    ) async throws {
        guard isActive else { throw MdocBleTransportError.closed }
        let outcome = await writeGate.wait(timeoutMs: 5_000) {
            peripheral.canSendWriteWithoutResponse
        }
        guard outcome == .ready, isActive else {
            throw MdocBleTransportError.failed(
                "BLE write was not ready (\(outcome)); the chunk was not issued"
            )
        }
        // ISO 18013-5 declares these writes Without Response. CoreBluetooth
        // provides no per-write acknowledgement for them, so readiness pacing
        // is the available backpressure signal.
        peripheral.writeValue(Data(value), for: characteristic, type: .withoutResponse)
    }

    private func scheduleStateStart() {
        guard !stateStartScheduled, let peripheral, let stateCharacteristic else { return }
        stateStartScheduled = true
        Task { [weak self] in
            guard let self else { return }
            do {
                try await self.write(
                    [MdocBleProtocol.stateStart],
                    to: stateCharacteristic,
                    peripheral: peripheral
                )
                self.handshake.onStateStartWritten()
                if self.handshake.ready { self.markReady() }
            } catch {
                self.fail(error)
            }
        }
    }

    // MARK: CBCentralManagerDelegate

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        switch central.state {
        case .poweredOn:
            guard peripheral == nil else { return }
            central.scanForPeripherals(withServices: [CBUUID(nsuuid: serviceUuid)], options: nil)
        case .unauthorized:
            fail("Bluetooth access is unauthorized")
        case .unsupported:
            fail("BLE is unsupported on this device")
        case .poweredOff:
            fail("Bluetooth is powered off")
        case .unknown, .resetting:
            break
        @unknown default:
            fail("Bluetooth entered an unknown state")
        }
    }

    func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        guard isActive, self.peripheral == nil else { return }
        central.stopScan()
        self.peripheral = peripheral
        peripheral.delegate = self
        central.connect(peripheral, options: nil)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        guard isActive, peripheral == self.peripheral else { return }
        peripheral.discoverServices([CBUUID(nsuuid: serviceUuid)])
    }

    func centralManager(
        _ central: CBCentralManager,
        didFailToConnect peripheral: CBPeripheral,
        error: Error?
    ) {
        guard peripheral == self.peripheral else { return }
        fail("Could not connect to mdoc: \(error?.localizedDescription ?? "unknown error")")
    }

    func centralManager(
        _ central: CBCentralManager,
        didDisconnectPeripheral peripheral: CBPeripheral,
        error: Error?
    ) {
        guard peripheral == self.peripheral else { return }
        writeGate.abort()
        fail(MdocBleTransportError.disconnected(
            "mdoc disconnected: \(error?.localizedDescription ?? "connection ended")"
        ))
    }

    // MARK: CBPeripheralDelegate

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard isActive else { return }
        if let error {
            fail("Service discovery failed: \(error.localizedDescription)")
            return
        }
        let engagedUuid = CBUUID(nsuuid: serviceUuid)
        guard let service = peripheral.services?.first(where: { $0.uuid == engagedUuid }) else {
            fail("mdoc does not expose the engaged service \(serviceUuid.uuidString)")
            return
        }
        peripheral.discoverCharacteristics([
            CBUUID(nsuuid: MdocBleProtocol.mdocStateUuid),
            CBUUID(nsuuid: MdocBleProtocol.mdocClient2ServerUuid),
            CBUUID(nsuuid: MdocBleProtocol.mdocServer2ClientUuid),
        ], for: service)
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didDiscoverCharacteristicsFor service: CBService,
        error: Error?
    ) {
        guard isActive else { return }
        if let error {
            fail("Characteristic discovery failed: \(error.localizedDescription)")
            return
        }
        let characteristics = Dictionary(
            (service.characteristics ?? []).map { ($0.uuid, $0) },
            uniquingKeysWith: { first, _ in first }
        )
        let stateUuid = CBUUID(nsuuid: MdocBleProtocol.mdocStateUuid)
        let clientUuid = CBUUID(nsuuid: MdocBleProtocol.mdocClient2ServerUuid)
        let serverUuid = CBUUID(nsuuid: MdocBleProtocol.mdocServer2ClientUuid)
        guard let state = characteristics[stateUuid],
              let client = characteristics[clientUuid],
              characteristics[serverUuid] != nil else {
            fail("mdoc service is missing State, Client2Server, or Server2Client")
            return
        }
        stateCharacteristic = state
        client2ServerCharacteristic = client
        // Serialize subscription setup. Server2Client is enabled from State's
        // completion callback, then STATE_START follows the second callback.
        peripheral.setNotifyValue(true, for: state)
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didUpdateNotificationStateFor characteristic: CBCharacteristic,
        error: Error?
    ) {
        guard isActive else { return }
        if let error {
            fail("Enabling \(characteristic.uuid.uuidString) notifications failed: \(error.localizedDescription)")
            return
        }
        guard characteristic.isNotifying else {
            fail("\(characteristic.uuid.uuidString) notifications were not enabled")
            return
        }

        let stateUuid = CBUUID(nsuuid: MdocBleProtocol.mdocStateUuid)
        let serverUuid = CBUUID(nsuuid: MdocBleProtocol.mdocServer2ClientUuid)
        switch characteristic.uuid {
        case stateUuid:
            handshake.onNotifications(.state, enabled: true)
            guard let service = characteristic.service,
                  let server = service.characteristics?.first(where: { $0.uuid == serverUuid }) else {
                fail("Server2Client characteristic disappeared during startup")
                return
            }
            peripheral.setNotifyValue(true, for: server)
        case serverUuid:
            handshake.onNotifications(.serverToClient, enabled: true)
            scheduleStateStart()
        default:
            break
        }
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didUpdateValueFor characteristic: CBCharacteristic,
        error: Error?
    ) {
        guard isActive else { return }
        if let error {
            fail("Receiving \(characteristic.uuid.uuidString) failed: \(error.localizedDescription)")
            return
        }
        guard let value = characteristic.value else { return }
        if characteristic.uuid == CBUUID(nsuuid: MdocBleProtocol.mdocServer2ClientUuid) {
            acceptIncomingChunk([UInt8](value))
        } else if characteristic.uuid == CBUUID(nsuuid: MdocBleProtocol.mdocStateUuid) {
            do {
                if try MdocBleState.parse([UInt8](value)) == .end {
                    fail(MdocBleTransportError.disconnected("mdoc sent STATE_END"))
                }
            } catch {
                fail(error)
            }
        }
    }

    func peripheralIsReady(toSendWriteWithoutResponse peripheral: CBPeripheral) {
        writeGate.signalReady()
    }
}
#endif

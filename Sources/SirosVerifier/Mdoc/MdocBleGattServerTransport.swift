// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

#if os(iOS) && canImport(CoreBluetooth)
import CoreBluetooth
import Foundation

/// Reader as GATT server for mdoc central-client mode. The holder reads Ident,
/// subscribes to Server2Client, and writes STATE_START before election.
internal final class MdocBleGattServerTransport: MdocBleTransportBase,
    CBPeripheralManagerDelegate, @unchecked Sendable {

    private let serviceUuid: UUID
    private let ident: Data
    private let handshake = MdocBleServerHandshake()
    private let notificationGate = MdocBleWriteReadyGate()
    private let notificationLock = NSLock()

    private var peripheralManager: CBPeripheralManager?
    private var server2ClientCharacteristic: CBMutableCharacteristic?
    private var connectedCentral: CBCentral?
    private var notificationsReady = true

    init(
        serviceUuid: UUID,
        eDeviceKeyBytes: [UInt8],
        onReady: @escaping @Sendable (any MdocBleCandidate) -> Void,
        onFailure: @escaping @Sendable (any MdocBleCandidate, Error) -> Void
    ) {
        self.serviceUuid = serviceUuid
        self.ident = Data(MdocBleProtocol.computeIdent(eDeviceKeyBytes: eDeviceKeyBytes))
        super.init(
            role: "mdoc central-client mode",
            onReady: onReady,
            onFailure: onFailure
        )
    }

    override func startRadio() throws {
        peripheralManager = CBPeripheralManager(delegate: self, queue: nil)
    }

    override func closeRadio() {
        notificationGate.abort()
        setNotificationsReady(false)
        peripheralManager?.stopAdvertising()
        peripheralManager?.removeAllServices()
        peripheralManager = nil
        server2ClientCharacteristic = nil
        connectedCentral = nil
    }

    override func currentMaxChunkSize() -> Int {
        guard let connectedCentral else { return MdocBleProtocol.defaultMtu - 3 }
        return MdocBleProtocol.maxChunkSize(
            attributeValueLength: connectedCentral.maximumUpdateValueLength
        )
    }

    override func sendChunk(_ chunk: [UInt8]) async throws {
        guard handshake.ready else {
            throw MdocBleTransportError.failed("Server2Client notifications are not enabled")
        }
        guard let peripheralManager, let server2ClientCharacteristic, let connectedCentral else {
            throw MdocBleTransportError.disconnected("mdoc is disconnected")
        }

        while isActive {
            // Clear readiness before updateValue so a callback racing a false
            // return cannot be lost before gate registration.
            setNotificationsReady(false)
            let accepted = peripheralManager.updateValue(
                Data(chunk),
                for: server2ClientCharacteristic,
                onSubscribedCentrals: [connectedCentral]
            )
            if accepted {
                setNotificationsReady(true)
                return
            }
            let outcome = await notificationGate.wait(timeoutMs: 5_000) {
                self.canSendNotifications
            }
            guard outcome == .ready, isActive else {
                throw MdocBleTransportError.failed(
                    "Server2Client notification was not ready (\(outcome)); the chunk was not issued"
                )
            }
        }
        throw MdocBleTransportError.closed
    }

    private var canSendNotifications: Bool {
        notificationLock.lock()
        defer { notificationLock.unlock() }
        return notificationsReady
    }

    private func setNotificationsReady(_ ready: Bool) {
        notificationLock.lock()
        notificationsReady = ready
        notificationLock.unlock()
    }

    private func adopt(_ central: CBCentral) -> Bool {
        if let connectedCentral {
            return connectedCentral.identifier == central.identifier
        }
        connectedCentral = central
        peripheralManager?.stopAdvertising()
        return true
    }

    // MARK: CBPeripheralManagerDelegate

    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        switch peripheral.state {
        case .poweredOn:
            let state = CBMutableCharacteristic(
                type: CBUUID(nsuuid: MdocBleProtocol.readerStateUuid),
                properties: [.notify, .writeWithoutResponse],
                value: nil,
                permissions: [.writeable]
            )
            let client2Server = CBMutableCharacteristic(
                type: CBUUID(nsuuid: MdocBleProtocol.readerClient2ServerUuid),
                properties: [.writeWithoutResponse],
                value: nil,
                permissions: [.writeable]
            )
            let server2Client = CBMutableCharacteristic(
                type: CBUUID(nsuuid: MdocBleProtocol.readerServer2ClientUuid),
                properties: [.notify],
                value: nil,
                permissions: []
            )
            let identCharacteristic = CBMutableCharacteristic(
                type: CBUUID(nsuuid: MdocBleProtocol.readerIdentUuid),
                properties: [.read],
                value: ident,
                permissions: [.readable]
            )
            server2ClientCharacteristic = server2Client

            let service = CBMutableService(type: CBUUID(nsuuid: serviceUuid), primary: true)
            service.characteristics = [state, client2Server, server2Client, identCharacteristic]
            peripheral.add(service)
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

    func peripheralManager(
        _ peripheral: CBPeripheralManager,
        didAdd service: CBService,
        error: Error?
    ) {
        guard isActive, service.uuid == CBUUID(nsuuid: serviceUuid) else { return }
        if let error {
            fail("Adding the mdoc reader service failed: \(error.localizedDescription)")
            return
        }
        peripheral.startAdvertising([
            CBAdvertisementDataServiceUUIDsKey: [CBUUID(nsuuid: serviceUuid)],
        ])
    }

    func peripheralManagerDidStartAdvertising(
        _ peripheral: CBPeripheralManager,
        error: Error?
    ) {
        if let error { fail("BLE advertising failed: \(error.localizedDescription)") }
    }

    func peripheralManager(
        _ peripheral: CBPeripheralManager,
        central: CBCentral,
        didSubscribeTo characteristic: CBCharacteristic
    ) {
        guard isActive, adopt(central) else {
            if isActive { fail("A second GATT client attempted to join the one-session transport") }
            return
        }
        if characteristic.uuid == CBUUID(nsuuid: MdocBleProtocol.readerServer2ClientUuid) {
            handshake.onServer2ClientNotifications(enabled: true)
            if handshake.ready { markReady() }
        }
    }

    func peripheralManager(
        _ peripheral: CBPeripheralManager,
        central: CBCentral,
        didUnsubscribeFrom characteristic: CBCharacteristic
    ) {
        guard isActive, connectedCentral?.identifier == central.identifier else { return }
        if characteristic.uuid == CBUUID(nsuuid: MdocBleProtocol.readerServer2ClientUuid) {
            handshake.onServer2ClientNotifications(enabled: false)
            fail(MdocBleTransportError.disconnected("mdoc disabled Server2Client notifications"))
        } else if characteristic.uuid == CBUUID(nsuuid: MdocBleProtocol.readerStateUuid),
                  handshake.started {
            fail(MdocBleTransportError.disconnected("mdoc disabled State notifications"))
        }
    }

    func peripheralManager(
        _ peripheral: CBPeripheralManager,
        didReceiveWrite requests: [CBATTRequest]
    ) {
        guard isActive else { return }
        for request in requests {
            guard adopt(request.central) else {
                fail("A second GATT client attempted to join the one-session transport")
                return
            }
            guard let value = request.value else { continue }
            if request.characteristic.uuid == CBUUID(nsuuid: MdocBleProtocol.readerStateUuid) {
                do {
                    switch try handshake.onState([UInt8](value)) {
                    case .start:
                        if handshake.ready { markReady() }
                    case .end:
                        fail(MdocBleTransportError.disconnected("mdoc sent STATE_END"))
                        return
                    }
                } catch {
                    fail(error)
                    return
                }
            } else if request.characteristic.uuid == CBUUID(nsuuid: MdocBleProtocol.readerClient2ServerUuid) {
                guard handshake.started else {
                    fail("Client2Server data arrived before STATE_START")
                    return
                }
                acceptIncomingChunk([UInt8](value))
            }
        }
    }

    func peripheralManagerIsReady(toUpdateSubscribers peripheral: CBPeripheralManager) {
        setNotificationsReady(true)
        notificationGate.signalReady()
    }
}
#endif

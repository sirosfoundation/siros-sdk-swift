// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Bounded, race-free hand-off between the `Task` that issues
/// write-without-response GATT writes and the CoreBluetooth delegate queue
/// that reports when the radio can take another one. Kept outside the
/// `canImport(CoreBluetooth)` gate below so the hand-off logic itself is
/// unit-testable on Linux; `BleCentralClient` is its only production user.
///
/// This is the CoreBluetooth-native counterpart of the Kotlin SDK's
/// `pendingWriteAck` (`@Volatile CompletableDeferred<Boolean>` completed
/// from `onCharacteristicWrite`, awaited under `WRITE_ACK_TIMEOUT_MS`).
/// CoreBluetooth gives no per-write ack for `.withoutResponse` writes
/// (`peripheral(_:didWriteValueFor:error:)` only fires for `.withResponse`),
/// so what is awaited here is "the transmit queue has room again"
/// (`peripheralIsReady(toSendWriteWithoutResponse:)`) rather than "the
/// previous write was queued for the radio" - but the failure it bounds is
/// the same one: a reader that drops mid-transfer must fail the session
/// within a few seconds, not leave the sending `Task` suspended forever.
///
/// Three hazards of the naive "check `canSendWriteWithoutResponse`, then
/// store a continuation" version this replaces, all closed here:
/// - Lost wake-up: readiness flipping between the check and the store meant
///   the `peripheralIsReady` callback had already come and gone with nothing
///   to resume, and the write hung. `wait` re-checks `isReady()` under the
///   lock AFTER registering, so a signal that raced the registration is
///   observed as "already ready" instead of being missed.
/// - Unsynchronised handoff: the continuation slot was a plain `var` written
///   on the sending `Task` and read/cleared on the CoreBluetooth queue. Every
///   access here goes through `lock`.
/// - Re-entry: a second waiter overwriting an un-resumed continuation leaks
///   the first (and traps under `withCheckedContinuation`). A second waiter
///   is refused with `.contended` instead - the caller treats it as a failed
///   write, which is loud and recoverable, unlike a hang.
final class BleWriteReadyGate: @unchecked Sendable {

    enum Outcome: Equatable {
        /// The radio can take another write - issue it now.
        case ready
        /// No readiness signal arrived within the timeout; the peer has most
        /// likely gone away without a disconnect callback (yet).
        case timedOut
        /// `abort()` was called - the connection is gone or the client was
        /// stopped - either while waiting, or before this wait began.
        case aborted
        /// Another waiter was already suspended. Only one write path may be
        /// in flight at a time (STATE_START, then the single response
        /// `Task`); hitting this is a sequencing bug, surfaced as a failed
        /// write rather than a leaked continuation.
        case contended
    }

    private let lock = NSLock()
    private var waiter: CheckedContinuation<Outcome, Never>?
    private var timeoutTask: Task<Void, Never>?
    /// Incremented per registered waiter so a timeout `Task` that lost the
    /// race to a `signalReady` (and was cancelled slightly too late) can
    /// never time out a LATER waiter by mistake.
    private var generation: UInt64 = 0
    /// Latched by `abort()`: once the connection is known to be gone, every
    /// subsequent `wait` fails immediately rather than waiting out the full
    /// timeout against a peripheral that will never signal again.
    private var aborted = false

    /// Synchronous on purpose: `NSLock.lock()` is flagged in async contexts
    /// (it would pin the suspending thread), so `wait` reads the latch via
    /// this non-suspending accessor instead.
    private var isAborted: Bool {
        lock.lock()
        defer { lock.unlock() }
        return aborted
    }

    /// Suspends until `signalReady()` is called, `isReady()` is observed true,
    /// `abort()` is called, or `timeoutMs` elapses - whichever comes first.
    /// `isReady` is consulted once before registering (unlocked) and once
    /// more under the lock after registering (see the type doc comment), so
    /// it must be a plain state read that does not call back into this gate
    /// from that second call (production: `canSendWriteWithoutResponse`).
    func wait(timeoutMs: UInt64, isReady: () -> Bool) async -> Outcome {
        // Once latched, the peripheral is not consulted at all: after a
        // disconnect its state is meaningless (and `stop()` may have dropped
        // the reference the closure captured), so the answer is known
        // without asking.
        if isAborted { return .aborted }
        if isReady() {
            // The fast path decides `.ready` without holding the lock across
            // `isReady()`, so an `abort()` can land while it runs. `aborted`
            // is monotonic (set once, never cleared), which makes reading it
            // AFTER `isReady()` returned sufficient: any abort that happened
            // before this point - including one racing the readiness check
            // - is observed, and the latch wins over readiness. An abort
            // landing after this return is not a lost latch, just a normal
            // "decided, then the connection went away".
            return isAborted ? .aborted : .ready
        }

        return await withCheckedContinuation { (continuation: CheckedContinuation<Outcome, Never>) in
            lock.lock()
            if aborted {
                lock.unlock()
                continuation.resume(returning: .aborted)
                return
            }
            guard waiter == nil else {
                lock.unlock()
                continuation.resume(returning: .contended)
                return
            }
            generation &+= 1
            let myGeneration = generation
            waiter = continuation
            // Registered - now re-check. A `signalReady()` that fired between
            // the unlocked check above and this store found no waiter and
            // was dropped; if readiness is (still) true we must not sit here
            // waiting for a signal that has already been and gone.
            if isReady() {
                waiter = nil
                lock.unlock()
                continuation.resume(returning: .ready)
                return
            }
            timeoutTask = Task { [weak self] in
                try? await Task.sleep(nanoseconds: timeoutMs * 1_000_000)
                guard !Task.isCancelled else { return }
                self?.resume(.timedOut, onlyIfGeneration: myGeneration)
            }
            lock.unlock()
        }
    }

    /// Called from the CoreBluetooth queue when the transmit queue has room again.
    func signalReady() {
        resume(.ready, onlyIfGeneration: nil)
    }

    /// Connection lost / client stopped: resume any current waiter with
    /// `.aborted` and make every later `wait` fail immediately.
    func abort() {
        lock.lock()
        aborted = true
        lock.unlock()
        resume(.aborted, onlyIfGeneration: nil)
    }

    private func resume(_ outcome: Outcome, onlyIfGeneration expected: UInt64?) {
        lock.lock()
        guard let waiter, expected == nil || expected == generation else {
            lock.unlock()
            return
        }
        self.waiter = nil
        let timer = timeoutTask
        timeoutTask = nil
        lock.unlock()
        timer?.cancel()
        waiter.resume(returning: outcome)
    }
}

#if canImport(CoreBluetooth)
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
/// Verified against real ISO 18013-5 readers in this role at the Geneva 2026
/// interop event (30-31 August 2026; e.g. com.ingenutec.sigil_id, see
/// `stateEndDelayMs` below), with transport fixes landing through
/// 7 September 2026. What is still true: there is no local GATT-server test
/// tool for regression runs - siros-verifier-cli's `siros-verify read`
/// (https://github.com/sirosfoundation/siros-verifier-cli) uses `bleak`,
/// which is central/client-only on every platform, the same role this class
/// plays - so exercising this path again needs a real reader or a
/// purpose-built BLE-peripheral script.
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

    /// How long a single write waits for CoreBluetooth's transmit queue to
    /// have room before the session is failed (e.g. the reader dropped the
    /// connection mid-transfer and no disconnect callback has arrived yet)
    /// rather than hanging forever. Mirrors the Kotlin SDK's
    /// `WRITE_ACK_TIMEOUT_MS`; see `BleWriteReadyGate`'s doc comment for how
    /// the two differ mechanically.
    private static let writeReadyTimeoutMs: UInt64 = 5000

    /// A real reader (com.ingenutec.sigil_id) logged "Peripheral Server
    /// error: mDL terminated transaction" firing on its main thread within
    /// milliseconds of receiving our final response chunk - concurrently
    /// with (not after) its own background thread's decrypt/MSO/signature
    /// verification, which went on to succeed. Root-caused via that
    /// reader's own log timeline (against the Kotlin SDK, whose
    /// `STATE_END_DELAY_MS` this mirrors): writing STATE_END back-to-back
    /// with the last data chunk (zero delay, only paced by the local
    /// transmit queue having room - which just means "queued for the
    /// radio", not "the peer finished processing it") is what the reader's
    /// library reads as the mdoc abruptly ending the transaction before
    /// verification could complete, and its main thread locks in that
    /// failure well before the real, successful result arrives. This grace
    /// delay gives a real device's decrypt+parse a chance to at least get
    /// underway before we signal transaction-end, without meaningfully
    /// slowing down the happy path.
    private static let stateEndDelayMs: UInt64 = 500

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
    /// Set synchronously, on the CoreBluetooth queue, the moment all of
    /// `maybeWriteStateStart`'s prerequisites are met - BEFORE the `Task`
    /// that actually performs the write is spawned. It records that the
    /// write has been SCHEDULED, not that it has happened: the write itself
    /// only goes out once the radio is ready (see `maybeWriteStateStart`),
    /// and can still fail. The two delegate paths that can complete the
    /// prerequisites (`Ident` read, notification-enable) are serialized on
    /// the CoreBluetooth queue, so this plain `Bool` is enough to make sure
    /// only one write `Task` is ever spawned - the same pattern as
    /// `sessionEstablishmentStarted` below.
    private var stateStartScheduled = false
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
    /// Signalled by `peripheralIsReady(toSendWriteWithoutResponse:)`, aborted
    /// on disconnect/`stop()` - see `waitUntilReadyToWrite`'s doc comment for
    /// why this throttling exists and `BleWriteReadyGate` for the hand-off.
    private let writeGate = BleWriteReadyGate()
    /// Guards `completeOnce` - the failure paths added for the handshake
    /// (STATE_START never issued, a write that never became ready) run on
    /// the sending `Task`, while a disconnect for the same underlying cause
    /// is reported on the CoreBluetooth queue; both must not each report a
    /// completion. Same guard `BlePeripheralServer` uses.
    private var completed = false
    private let completionLock = NSLock()

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
            completeOnce(false)
            return
        }
        centralManager = CBCentralManager(delegate: self, queue: nil)
    }

    public func stop() {
        writeGate.abort()
        if let peripheral {
            centralManager?.cancelPeripheralConnection(peripheral)
        }
        centralManager?.stopScan()
        centralManager = nil
        peripheral = nil
    }

    /// Reports the presentation's outcome exactly once. Unlike Kotlin's
    /// coroutine-on-one-dispatcher port, the write-failure paths here run on
    /// an unstructured `Task` while the disconnect callback for the same
    /// event runs on the CoreBluetooth queue, so the guard needs a lock.
    private func completeOnce(_ success: Bool) {
        completionLock.lock()
        let alreadyCompleted = completed
        completed = true
        completionLock.unlock()
        guard !alreadyCompleted else { return }
        onComplete(success)
    }

    /// Fail the session the way the sibling delegate error paths do: log
    /// why, report failure, and drop the connection so the reader sees a
    /// clean disconnect instead of a silent peer.
    private func terminate(_ reason: String, _ peripheral: CBPeripheral) {
        onLog(reason)
        completeOnce(false)
        centralManager?.cancelPeripheralConnection(peripheral)
    }

    /// Writes STATE_START once both prerequisites are satisfied: the
    /// reader's identity has been verified via `Ident`, and notifications
    /// are enabled on both `State` and `Server2Client`. Guarded by
    /// `stateStartScheduled` since `Ident`-read completion and
    /// notification-enable completion can arrive in either order (see this
    /// type's doc comment) and both call into this function.
    ///
    /// The write is `.withoutResponse`: ISO 18013-5 Table 6 declares the
    /// `State` characteristic's properties as Notify + Write Without
    /// Response, so `.withResponse` is not something a conforming reader is
    /// required to accept (and the Kotlin SDK's `writeNoResponse` uses
    /// `WRITE_TYPE_NO_RESPONSE` for the same reason). That means
    /// CoreBluetooth gives no per-write success/failure callback for it -
    /// the detectable failure here is the radio never becoming ready to
    /// take the write (timeout) or the connection going away during the
    /// wait, and either of those fails the session rather than leaving a
    /// STATE_START the reader never received with both sides waiting on
    /// each other. Before this, the write was issued without waiting for
    /// `canSendWriteWithoutResponse` at all - and CoreBluetooth silently
    /// drops a `.withoutResponse` write issued while that is false (see
    /// `waitUntilReadyToWrite`), which in the handshake position is exactly
    /// the "session sits silent until the reader gives up" failure.
    private func maybeWriteStateStart(_ peripheral: CBPeripheral) {
        guard !stateStartScheduled,
              identVerified,
              notifyReady.contains(Self.stateUUID),
              notifyReady.contains(Self.server2ClientUUID),
              let stateCharacteristic
        else { return }
        stateStartScheduled = true
        Task {
            let outcome = await waitUntilReadyToWrite()
            guard outcome == .ready else {
                terminate("STATE_START write not issued (\(outcome)) - reader never saw the session begin", peripheral)
                return
            }
            peripheral.writeValue(Data([Self.stateStart]), for: stateCharacteristic, type: .withoutResponse)
        }
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
    ///
    /// Bounded by `writeReadyTimeoutMs` and aborted on disconnect/`stop()`;
    /// anything but `.ready` means the write must NOT be issued and the
    /// caller should fail the session.
    private func waitUntilReadyToWrite() async -> BleWriteReadyGate.Outcome {
        guard let peripheral else { return .aborted }
        return await writeGate.wait(timeoutMs: Self.writeReadyTimeoutMs) {
            peripheral.canSendWriteWithoutResponse
        }
    }

    /// Writes the encrypted response to `Client2Server`, chunked, then signals
    /// STATE_END on `State` - matching peripheral-server-mode's more careful
    /// state handling (Kotlin's `BleCentralClient.kt` originally omitted this;
    /// a strict reader could otherwise keep the transaction open waiting for
    /// it unnecessarily).
    ///
    /// - Returns: `false` if any chunk could not be issued because the radio
    ///   never became ready (timeout) or the connection went away - the
    ///   reader will not have received a complete response. STATE_END's own
    ///   outcome does not affect the result (as in the Kotlin SDK): by then
    ///   the response is fully out and a reader that has already gone is
    ///   not made worse off.
    private func sendData(_ message: [UInt8]) async -> Bool {
        guard let characteristic = client2ServerCharacteristic, let peripheral else { return false }
        // Floored at `defaultMtu - 3` (20 bytes): `BleMessageChunker.chunk`
        // requires `maxChunkSize > 1`, and an unexpected/invalid negotiated
        // write length should never be allowed to produce a smaller (or
        // negative) value that would crash chunking outright.
        let maxChunkSize = max(min(peripheral.maximumWriteValueLength(for: .withoutResponse), 512), Self.defaultMtu - 3)
        let chunks = BleMessageChunker.chunk(message, maxChunkSize: maxChunkSize)
        for (index, chunk) in chunks.enumerated() {
            let outcome = await waitUntilReadyToWrite()
            guard outcome == .ready else {
                onLog("Client2Server chunk \(index + 1)/\(chunks.count) not issued (\(outcome))")
                return false
            }
            peripheral.writeValue(Data(chunk), for: characteristic, type: .withoutResponse)
        }
        // §11.1.3.1: signal the end of this side's transaction once the
        // response has been fully written. See `stateEndDelayMs`'s doc
        // comment for why this isn't sent immediately after the last chunk.
        try? await Task.sleep(nanoseconds: Self.stateEndDelayMs * 1_000_000)
        if let stateCharacteristic {
            let outcome = await waitUntilReadyToWrite()
            if outcome == .ready {
                peripheral.writeValue(Data([Self.stateEnd]), for: stateCharacteristic, type: .withoutResponse)
            } else {
                onLog("STATE_END not issued (\(outcome)) - response was already fully written")
            }
        }
        return true
    }
}

extension BleCentralClient: CBCentralManagerDelegate {

    public func centralManagerDidUpdateState(_ central: CBCentralManager) {
        guard central.state == .poweredOn else {
            if central.state == .unauthorized || central.state == .unsupported {
                onLog("Bluetooth is not available/authorized")
                completeOnce(false)
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
        completeOnce(false)
    }

    public func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        // Any write currently waiting for the radio (STATE_START, a response
        // chunk) must fail now, not after its full timeout: nothing will
        // ever signal readiness on this connection again.
        writeGate.abort()
        if !session.established {
            onLog("Reader disconnected before completing a presentation")
            completeOnce(false)
        }
    }
}

extension BleCentralClient: CBPeripheralDelegate {

    public func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        if let error {
            onLog("Failed to discover services: \(error.localizedDescription)")
            completeOnce(false)
            return
        }
        guard let service = peripheral.services?.first else {
            onLog("reader has no service matching this engagement's central-client-mode UUID")
            completeOnce(false)
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
            completeOnce(false)
            return
        }
        let byUUID = Dictionary(uniqueKeysWithValues: (service.characteristics ?? []).map { ($0.uuid, $0) })
        guard let identCharacteristic = byUUID[Self.identUUID],
              let stateCharacteristic = byUUID[Self.stateUUID],
              let client2ServerCharacteristic = byUUID[Self.client2ServerUUID],
              let server2ClientCharacteristic = byUUID[Self.server2ClientUUID]
        else {
            onLog("reader's mdoc reader service is missing required characteristics")
            completeOnce(false)
            centralManager?.cancelPeripheralConnection(peripheral)
            return
        }
        self.stateCharacteristic = stateCharacteristic
        self.client2ServerCharacteristic = client2ServerCharacteristic

        peripheral.readValue(for: identCharacteristic)
        peripheral.setNotifyValue(true, for: stateCharacteristic)
        peripheral.setNotifyValue(true, for: server2ClientCharacteristic)
    }

    /// A failed notification enable (the CoreBluetooth equivalent of
    /// Android's CCCD `onDescriptorWrite` returning a non-success status)
    /// means this side will never hear that characteristic. Carrying on
    /// would send STATE_START to a reader whose replies this side can no
    /// longer receive, and the session would then sit silent until the
    /// reader gave up - indistinguishable, to the user, from a reader that
    /// never answered. Fail now, with the reason in the log. This only ever
    /// asks to ENABLE notifications, so a callback reporting
    /// `isNotifying == false` without an error is the same failure by
    /// another route (the peripheral declined), not a state to wait out.
    public func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        if let error {
            terminate("enabling notifications on \(characteristic.uuid) failed: \(error.localizedDescription)", peripheral)
            return
        }
        guard characteristic.isNotifying else {
            terminate("enabling notifications on \(characteristic.uuid) was requested but the reader reports them off", peripheral)
            return
        }
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
                completeOnce(false)
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
                        guard await sendData([UInt8](sessionData)) else {
                            onLog("a write could not be issued - reader will not receive the full response")
                            completeOnce(false)
                            return
                        }
                        completeOnce(true)
                    case .denied:
                        completeOnce(false)
                    case .failed:
                        completeOnce(false)
                    }
                } catch {
                    onLog("Proximity presentation failed: \(error.localizedDescription)")
                    completeOnce(false)
                }
            }

        default:
            break
        }
    }

    /// Resumes any write suspended in `waitUntilReadyToWrite` once
    /// CoreBluetooth's internal transmit queue has drained.
    public func peripheralIsReady(toSendWriteWithoutResponse peripheral: CBPeripheral) {
        writeGate.signalReady()
    }
}
#endif

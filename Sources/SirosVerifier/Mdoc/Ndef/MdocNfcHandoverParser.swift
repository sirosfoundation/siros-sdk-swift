// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Bounded, transport-independent parser for NFC Forum/ISO 18013-5 static handover.
public enum MdocNfcHandoverParser {
    /// Maximum complete NDEF Handover Select message size accepted by `parse`.
    public static let maximumHandoverSelectSize = 64 * 1024

    private static let ndefMB: UInt8 = 0x80
    private static let ndefME: UInt8 = 0x40
    private static let ndefCF: UInt8 = 0x20
    private static let ndefSR: UInt8 = 0x10
    private static let ndefIL: UInt8 = 0x08
    private static let ndefTNF: UInt8 = 0x07

    private static let tnfEmpty: UInt8 = 0x00
    private static let tnfWellKnown: UInt8 = 0x01
    private static let tnfMIME: UInt8 = 0x02
    private static let tnfExternal: UInt8 = 0x04
    private static let tnfUnknown: UInt8 = 0x05

    private static let adTypeComplete128BitServiceUUIDs: UInt8 = 0x07
    private static let adTypeLERole: UInt8 = 0x1C
    private static let uuidByteCount = 16

    private static let handoverSelectType = Array("Hs".utf8)
    private static let bluetoothLEOOBType = Array("application/vnd.bluetooth.le.oob".utf8)
    private static let deviceEngagementType = Array("iso.org:18013:deviceengagement".utf8)

    /// Parse a complete raw NDEF Handover Select message.
    ///
    /// Exactly one `iso.org:18013:deviceengagement` external record is required.
    /// Its bytes are base64url-encoded only to reuse `MdocQrEngagement`'s strict
    /// validator; all returned transcript bytes retain their original binary form.
    public static func parse(_ handoverSelectBytes: [UInt8]) throws -> MdocNfcHandover {
        guard handoverSelectBytes.count <= maximumHandoverSelectSize else {
            throw MdocNfcHandoverError.handoverTooLarge
        }
        let records = try parseNDEFMessage(handoverSelectBytes)
        let first = records[0]
        guard first.tnf == tnfWellKnown, first.type == handoverSelectType else {
            throw MdocNfcHandoverError.invalidHandover(
                "Handover Select must begin with a well-known Hs record"
            )
        }

        let deviceEngagementRecords = records.filter {
            $0.tnf == tnfExternal && $0.type == deviceEngagementType
        }
        guard deviceEngagementRecords.count == 1 else {
            throw MdocNfcHandoverError.invalidHandover(
                "Handover Select must contain exactly one DeviceEngagement record"
            )
        }
        let engagement = try parseDeviceEngagement(deviceEngagementRecords[0].payload)
        let carrierRecords = records.filter {
            $0.tnf == tnfMIME && $0.type == bluetoothLEOOBType
        }
        let ble = try mergeBLEMetadata(carrierRecords, engagementBLE: engagement.ble)

        return MdocNfcHandover(
            handoverSelectBytes: handoverSelectBytes,
            handoverCbor: nfcHandoverCBOR(handoverSelectBytes),
            engagement: engagement,
            ble: ble
        )
    }

    private static func parseDeviceEngagement(_ bytes: [UInt8]) throws -> MdocQrEngagement {
        let encoded = Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        do {
            return try MdocQrEngagement.parse("mdoc:" + encoded)
        } catch {
            throw MdocNfcHandoverError.invalidDeviceEngagement(String(describing: error))
        }
    }

    private static func parseNDEFMessage(_ bytes: [UInt8]) throws -> [NDEFRecord] {
        guard !bytes.isEmpty else {
            throw MdocNfcHandoverError.malformedNDEF("Handover Select NDEF message is empty")
        }
        var reader = NDEFReader(bytes: bytes)
        var records: [NDEFRecord] = []
        var messageEnded = false

        while reader.remaining > 0 {
            guard !messageEnded else {
                throw MdocNfcHandoverError.malformedNDEF(
                    "Trailing bytes after the NDEF message-end record"
                )
            }
            let header = try reader.u8()
            guard header & ndefCF == 0 else {
                throw MdocNfcHandoverError.malformedNDEF("Chunked NDEF records are not supported")
            }
            let tnf = header & ndefTNF
            guard tnf != 0x06, tnf != 0x07 else {
                throw MdocNfcHandoverError.malformedNDEF("Reserved or unchanged NDEF TNF")
            }

            let messageBegin = header & ndefMB != 0
            let messageEnd = header & ndefME != 0
            if records.isEmpty {
                guard messageBegin else {
                    throw MdocNfcHandoverError.malformedNDEF("First NDEF record does not set MB")
                }
            } else {
                guard !messageBegin else {
                    throw MdocNfcHandoverError.malformedNDEF("Only the first NDEF record may set MB")
                }
            }

            let shortRecord = header & ndefSR != 0
            let hasID = header & ndefIL != 0
            let typeLength = Int(try reader.u8())
            let payloadLength = shortRecord ? UInt64(try reader.u8()) : UInt64(try reader.u32())
            guard payloadLength <= UInt64(Int.max) else {
                throw MdocNfcHandoverError.malformedNDEF("NDEF payload length is too large")
            }
            let idLength = hasID ? Int(try reader.u8()) : 0

            if tnf == tnfEmpty {
                guard typeLength == 0, idLength == 0, payloadLength == 0 else {
                    throw MdocNfcHandoverError.malformedNDEF(
                        "Empty-TNF NDEF record has type, ID, or payload data"
                    )
                }
            }
            if tnf == tnfUnknown {
                guard typeLength == 0 else {
                    throw MdocNfcHandoverError.malformedNDEF(
                        "Unknown-TNF NDEF record must not have a type"
                    )
                }
            }

            let type = try reader.take(typeLength)
            _ = try reader.take(idLength)
            let payload = try reader.take(Int(payloadLength))
            records.append(NDEFRecord(tnf: tnf, type: type, payload: payload))
            messageEnded = messageEnd
        }

        guard messageEnded else {
            throw MdocNfcHandoverError.malformedNDEF("NDEF message has no message-end record")
        }
        return records
    }

    private struct BLEAdvertisement {
        let role: LERole?
        let uuids: Set<UUID>
    }

    private static func mergeBLEMetadata(
        _ carrierRecords: [NDEFRecord],
        engagementBLE: MdocQrEngagement.BleRetrievalMetadata?
    ) throws -> MdocQrEngagement.BleRetrievalMetadata? {
        let advertisement = try parseBLEAdvertisement(carrierRecords)
        if let engagementBLE {
            return try reconcileBLEMetadata(advertisement, engagementBLE: engagementBLE)
        }
        return try metadataWithoutEngagement(advertisement)
    }

    private static func parseBLEAdvertisement(_ records: [NDEFRecord]) throws -> BLEAdvertisement {
        var role: LERole?
        var advertisedUUIDs = Set<UUID>()
        for carrier in records {
            var offset = 0
            while offset < carrier.payload.count {
                let length = Int(carrier.payload[offset])
                guard length != 0 else {
                    throw MdocNfcHandoverError.malformedBluetoothOOB(
                        "Bluetooth OOB contains a zero-length AD structure"
                    )
                }
                let end = offset + 1 + length
                guard end <= carrier.payload.count else {
                    throw MdocNfcHandoverError.malformedBluetoothOOB(
                        "Truncated Bluetooth OOB AD structure"
                    )
                }
                let type = carrier.payload[offset + 1]
                let dataStart = offset + 2
                let dataLength = length - 1
                switch type {
                case adTypeLERole:
                    guard dataLength == 1 else {
                        throw MdocNfcHandoverError.malformedBluetoothOOB(
                            "Bluetooth LE Role AD must contain exactly one byte"
                        )
                    }
                    let parsedRole = try LERole(value: carrier.payload[dataStart])
                    if let existingRole = role, existingRole != parsedRole {
                        throw MdocNfcHandoverError.inconsistentBluetoothMetadata(
                            "Conflicting Bluetooth LE Role values"
                        )
                    }
                    role = parsedRole
                case adTypeComplete128BitServiceUUIDs:
                    guard dataLength > 0, dataLength % uuidByteCount == 0 else {
                        throw MdocNfcHandoverError.malformedBluetoothOOB(
                            "Complete 128-bit Service UUIDs AD has an invalid length"
                        )
                    }
                    var uuidOffset = dataStart
                    while uuidOffset < end {
                        advertisedUUIDs.insert(uuidFromBluetooth(carrier.payload, offset: uuidOffset))
                        uuidOffset += uuidByteCount
                    }
                default:
                    break
                }
                offset = end
            }
        }
        return BLEAdvertisement(role: role, uuids: advertisedUUIDs)
    }

    private static func reconcileBLEMetadata(
        _ advertisement: BLEAdvertisement,
        engagementBLE: MdocQrEngagement.BleRetrievalMetadata
    ) throws -> MdocQrEngagement.BleRetrievalMetadata {
        if let role = advertisement.role,
           role.supportsPeripheral != engagementBLE.supportsPeripheralServerMode ||
            role.supportsCentral != engagementBLE.supportsCentralClientMode {
            throw MdocNfcHandoverError.inconsistentBluetoothMetadata(
                "Bluetooth LE Role conflicts with DeviceEngagement BleOptions"
            )
        }
        let engagementUUIDs = Set([
            engagementBLE.peripheralServerModeUuid,
            engagementBLE.centralClientModeUuid,
        ].compactMap { $0 })
        guard advertisement.uuids.isSubset(of: engagementUUIDs) else {
            throw MdocNfcHandoverError.inconsistentBluetoothMetadata(
                "Bluetooth OOB Service UUID conflicts with DeviceEngagement BleOptions"
            )
        }
        if advertisement.uuids.count == 1, let role = advertisement.role,
           role.supportsPeripheral, role.supportsCentral {
            let preferredUUID = role.preferPeripheral
                ? engagementBLE.peripheralServerModeUuid
                : engagementBLE.centralClientModeUuid
            guard advertisement.uuids.first == preferredUUID else {
                throw MdocNfcHandoverError.inconsistentBluetoothMetadata(
                    "Bluetooth OOB Service UUID conflicts with the preferred LE Role"
                )
            }
        }
        return engagementBLE
    }

    private static func metadataWithoutEngagement(
        _ advertisement: BLEAdvertisement
    ) throws -> MdocQrEngagement.BleRetrievalMetadata? {
        guard let role = advertisement.role, !advertisement.uuids.isEmpty else { return nil }
        if role.supportsPeripheral, !role.supportsCentral {
            guard let uuid = advertisement.uuids.first, advertisement.uuids.count == 1 else {
                throw MdocNfcHandoverError.inconsistentBluetoothMetadata(
                    "Peripheral-only handover must advertise exactly one Service UUID"
                )
            }
            return MdocQrEngagement.BleRetrievalMetadata(
                supportsPeripheralServerMode: true,
                supportsCentralClientMode: false,
                peripheralServerModeUuid: uuid,
                centralClientModeUuid: nil
            )
        }
        if role.supportsCentral, !role.supportsPeripheral {
            guard let uuid = advertisement.uuids.first, advertisement.uuids.count == 1 else {
                throw MdocNfcHandoverError.inconsistentBluetoothMetadata(
                    "Central-only handover must advertise exactly one Service UUID"
                )
            }
            return MdocQrEngagement.BleRetrievalMetadata(
                supportsPeripheralServerMode: false,
                supportsCentralClientMode: true,
                peripheralServerModeUuid: nil,
                centralClientModeUuid: uuid
            )
        }
        return nil
    }

    private static func uuidFromBluetooth(_ bytes: [UInt8], offset: Int) -> UUID {
        let bigEndian = Array(bytes[offset..<(offset + uuidByteCount)].reversed())
        return UUID(uuid: (
            bigEndian[0], bigEndian[1], bigEndian[2], bigEndian[3],
            bigEndian[4], bigEndian[5], bigEndian[6], bigEndian[7],
            bigEndian[8], bigEndian[9], bigEndian[10], bigEndian[11],
            bigEndian[12], bigEndian[13], bigEndian[14], bigEndian[15]
        ))
    }

    /// Canonical CBOR for `NFCHandover = [HandoverSelectBytes, null]`.
    private static func nfcHandoverCBOR(_ select: [UInt8]) -> [UInt8] {
        var result: [UInt8] = [0x82]
        result.reserveCapacity(select.count + 7)
        switch select.count {
        case 0..<24:
            result.append(0x40 | UInt8(select.count))
        case 24...0xFF:
            result.append(contentsOf: [0x58, UInt8(select.count)])
        case 0x100...0xFFFF:
            result.append(contentsOf: [
                0x59,
                UInt8((select.count >> 8) & 0xFF),
                UInt8(select.count & 0xFF),
            ])
        default:
            result.append(contentsOf: [
                0x5A,
                UInt8((select.count >> 24) & 0xFF),
                UInt8((select.count >> 16) & 0xFF),
                UInt8((select.count >> 8) & 0xFF),
                UInt8(select.count & 0xFF),
            ])
        }
        result.append(contentsOf: select)
        result.append(0xF6)
        return result
    }

    private struct NDEFRecord {
        let tnf: UInt8
        let type: [UInt8]
        let payload: [UInt8]
    }

    private enum LERole: Equatable {
        case peripheralOnly
        case centralOnly
        case bothPeripheralPreferred
        case bothCentralPreferred

        init(value: UInt8) throws {
            switch value {
            case 0x00: self = .peripheralOnly
            case 0x01: self = .centralOnly
            case 0x02: self = .bothPeripheralPreferred
            case 0x03: self = .bothCentralPreferred
            default:
                throw MdocNfcHandoverError.malformedBluetoothOOB(
                    "Unsupported Bluetooth LE Role value: \(value)"
                )
            }
        }

        var supportsPeripheral: Bool {
            self == .peripheralOnly || self == .bothPeripheralPreferred || self == .bothCentralPreferred
        }

        var supportsCentral: Bool {
            self == .centralOnly || self == .bothPeripheralPreferred || self == .bothCentralPreferred
        }

        var preferPeripheral: Bool {
            self == .peripheralOnly || self == .bothPeripheralPreferred
        }
    }

    private struct NDEFReader {
        let bytes: [UInt8]
        var offset = 0

        var remaining: Int { bytes.count - offset }

        mutating func u8() throws -> UInt8 {
            guard remaining >= 1 else {
                throw MdocNfcHandoverError.malformedNDEF("Truncated NDEF record header")
            }
            defer { offset += 1 }
            return bytes[offset]
        }

        mutating func u32() throws -> UInt32 {
            guard remaining >= 4 else {
                throw MdocNfcHandoverError.malformedNDEF("Truncated NDEF payload length")
            }
            var result: UInt32 = 0
            for _ in 0..<4 {
                result = (result << 8) | UInt32(try u8())
            }
            return result
        }

        mutating func take(_ length: Int) throws -> [UInt8] {
            guard length >= 0, length <= remaining else {
                throw MdocNfcHandoverError.malformedNDEF(
                    "NDEF record exceeds the Handover Select message"
                )
            }
            let end = offset + length
            let result = Array(bytes[offset..<end])
            offset = end
            return result
        }
    }
}

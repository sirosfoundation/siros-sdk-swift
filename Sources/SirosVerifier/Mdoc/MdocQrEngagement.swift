// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#elseif canImport(Crypto)
import Crypto
#endif

/// Transport-neutral engagement inputs shared by QR and NFC static handover.
public protocol MdocEngagement: Sendable {
    var deviceEngagementBytes: [UInt8] { get }
    var eDeviceKeyBytes: [UInt8] { get }
    var handoverCbor: [UInt8] { get }
    var ble: MdocQrEngagement.BleRetrievalMetadata? { get }
}

/// A validated ISO/IEC 18013-5 QR device engagement for an mdoc verifier.
///
/// The byte arrays are slices of the QR payload, never a CBOR re-encoding. In
/// particular, a native Reader wrapper can put them directly into its session
/// transcript without changing non-canonical integer widths or map ordering.
public struct MdocQrEngagement: Sendable, Equatable, MdocEngagement {
    public static let maximumDecodedSize = 16_384

    /// BLE retrieval metadata advertised by the single supported retrieval
    /// method. Nil when DeviceEngagement omits DeviceRetrievalMethods entirely.
    public struct BleRetrievalMetadata: Sendable, Equatable {
        public let supportsPeripheralServerMode: Bool
        public let supportsCentralClientMode: Bool
        public let peripheralServerModeUuid: UUID?
        public let centralClientModeUuid: UUID?

        public init(
            supportsPeripheralServerMode: Bool,
            supportsCentralClientMode: Bool,
            peripheralServerModeUuid: UUID?,
            centralClientModeUuid: UUID?
        ) {
            self.supportsPeripheralServerMode = supportsPeripheralServerMode
            self.supportsCentralClientMode = supportsCentralClientMode
            self.peripheralServerModeUuid = peripheralServerModeUuid
            self.centralClientModeUuid = centralClientModeUuid
        }
    }

    /// The exact original, untagged DeviceEngagement CBOR bytes.
    public let deviceEngagementBytes: [UInt8]
    /// The exact original `#6.24(bstr .cbor EDeviceKey)` item, including tag 24.
    public let eDeviceKeyBytes: [UInt8]
    /// QRHandover is CBOR null. Its complete encoding is the single byte 0xF6.
    public let qrHandover: [UInt8]
    /// Optional BLE mode flags and discovery UUIDs.
    public let ble: BleRetrievalMetadata?

    /// Alias useful at a session-transcript call site.
    public var handover: [UInt8] { qrHandover }
    public var handoverCbor: [UInt8] { qrHandover }
    public var bleRetrievalMetadata: BleRetrievalMetadata? { ble }
    public var peripheralServerModeUuid: UUID? { ble?.peripheralServerModeUuid }
    public var centralClientModeUuid: UUID? { ble?.centralClientModeUuid }

    private init(
        deviceEngagementBytes: [UInt8],
        eDeviceKeyBytes: [UInt8],
        ble: BleRetrievalMetadata?
    ) {
        self.deviceEngagementBytes = deviceEngagementBytes
        self.eDeviceKeyBytes = eDeviceKeyBytes
        self.qrHandover = [0xF6]
        self.ble = ble
    }

    public init(mdocURI: String) throws {
        self = try Self.parse(mdocURI)
    }

    /// Parse `mdoc:` followed by canonical, unpadded base64url.
    public static func parse(_ mdocURI: String) throws -> MdocQrEngagement {
        let bytes = try decodeURI(mdocURI)
        let root = try decodeCBOR(bytes)
        let top = try integerMap(root)
        guard top.keys.allSatisfy({ $0 == 0 || $0 == 1 || $0 == 2 }),
              let versionNode = top[0], let securityNode = top[1] else {
            throw MdocQrEngagementError.unsupportedDeviceEngagement(
                "DeviceEngagement must contain only keys 0, 1 and optional 2, with keys 0 and 1 present"
            )
        }
        guard versionNode.text == "1.0" else {
            throw MdocQrEngagementError.unsupportedDeviceEngagement("DeviceEngagement version must be exactly 1.0")
        }

        guard let security = securityNode.array, security.count == 2,
              security[0].unsigned == 1 else {
            throw MdocQrEngagementError.unsupportedDeviceEngagement(
                "Security must be [cipher suite 1, EDeviceKeyBytes]"
            )
        }
        guard case .tag(24, let keyPayloadNode) = security[1].kind,
              let coseKeyBytes = keyPayloadNode.bytes else {
            throw MdocQrEngagementError.malformedCBOR("EDeviceKeyBytes must be tag 24 containing a byte string")
        }
        try validateCOSEKey(coseKeyBytes)

        var ble: BleRetrievalMetadata?
        if let methodsNode = top[2] {
            ble = try parseSingleBLERetrievalMethod(methodsNode)
        }
        return MdocQrEngagement(
            deviceEngagementBytes: bytes,
            eDeviceKeyBytes: Array(bytes[security[1].range]),
            ble: ble
        )
    }

    public static func parse(mdocUri: String) throws -> MdocQrEngagement {
        try parse(mdocUri)
    }

    private static func decodeURI(_ uri: String) throws -> [UInt8] {
        guard uri.hasPrefix("mdoc:") else {
            throw MdocQrEngagementError.invalidURI("expected lowercase mdoc: scheme")
        }
        let payload = String(uri.dropFirst(5))
        let ascii = Array(payload.utf8)
        guard !ascii.isEmpty, ascii.allSatisfy(isBase64URLByte) else {
            throw MdocQrEngagementError.invalidURI("payload must be nonempty unpadded base64url")
        }
        let maximumEncodedSize = (maximumDecodedSize * 8 + 5) / 6
        guard ascii.count <= maximumEncodedSize else {
            throw MdocQrEngagementError.payloadTooLarge
        }
        guard ascii.count % 4 != 1 else {
            throw MdocQrEngagementError.invalidURI("invalid base64url length")
        }

        var standard = payload.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        standard += String(repeating: "=", count: (4 - standard.count % 4) % 4)
        guard let decoded = Data(base64Encoded: standard) else {
            throw MdocQrEngagementError.invalidURI("malformed base64url payload")
        }
        // Data's decoder is deliberately not relied on to reject nonzero unused
        // bits. Re-encoding also proves this spelling is the unique canonical one.
        guard base64URL(decoded) == payload else {
            throw MdocQrEngagementError.invalidURI("non-canonical base64url payload")
        }
        guard decoded.count <= maximumDecodedSize else {
            throw MdocQrEngagementError.payloadTooLarge
        }
        return [UInt8](decoded)
    }

    private static func isBase64URLByte(_ byte: UInt8) -> Bool {
        (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A) ||
            (byte >= 0x30 && byte <= 0x39) || byte == 0x2D || byte == 0x5F
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func decodeCBOR(_ bytes: [UInt8]) throws -> StrictCBOR.Node {
        do {
            return try StrictCBOR.parse(bytes)
        } catch {
            throw MdocQrEngagementError.malformedCBOR(String(describing: error))
        }
    }

    private static func integerMap(_ node: StrictCBOR.Node) throws -> [Int: StrictCBOR.Node] {
        do {
            return try StrictCBOR.integerMap(node)
        } catch {
            throw MdocQrEngagementError.malformedCBOR(String(describing: error))
        }
    }

    private static func validateCOSEKey(_ bytes: [UInt8]) throws {
        let key = try integerMap(decodeCBOR(bytes))
        guard key.count == 4, let kty = key[1]?.unsigned, let curve = key[-1]?.unsigned,
              let x = key[-2]?.bytes, let y = key[-3]?.bytes else {
            throw MdocQrEngagementError.unsupportedDeviceEngagement(
                "EDeviceKey must contain exactly kty, crv, x and y"
            )
        }
        guard kty == 2, curve == 1, x.count == 32, y.count == 32 else {
            throw MdocQrEngagementError.unsupportedDeviceEngagement(
                "EDeviceKey must be an EC2 P-256 key with 32-byte coordinates"
            )
        }
        #if canImport(CryptoKit) || canImport(Crypto)
        let uncompressedPoint = Data([0x04] + x + y)
        guard (try? P256.Signing.PublicKey(x963Representation: uncompressedPoint)) != nil else {
            throw MdocQrEngagementError.unsupportedDeviceEngagement("EDeviceKey coordinates are not on P-256")
        }
        #else
        throw MdocQrEngagementError.unsupportedDeviceEngagement("P-256 validation is unavailable on this platform")
        #endif
    }

    private static func parseSingleBLERetrievalMethod(
        _ node: StrictCBOR.Node
    ) throws -> BleRetrievalMetadata {
        guard let methods = node.array, methods.count == 1,
              let method = methods[0].array, method.count == 3,
              method[0].unsigned == 2, method[1].unsigned == 1 else {
            throw MdocQrEngagementError.unsupportedDeviceEngagement(
                "DeviceRetrievalMethods must contain exactly one BLE version 1 method"
            )
        }
        let options = try integerMap(method[2])
        guard options.keys.allSatisfy({ $0 == 0 || $0 == 1 || $0 == 10 || $0 == 11 }),
              let peripheral = options[0]?.boolean, let central = options[1]?.boolean else {
            throw MdocQrEngagementError.unsupportedDeviceEngagement(
                "BleOptions has unknown keys or missing/non-boolean mode flags"
            )
        }
        let peripheralBytes = options[10]?.bytes
        let centralBytes = options[11]?.bytes
        if options[10] != nil && peripheralBytes == nil || options[11] != nil && centralBytes == nil {
            throw MdocQrEngagementError.malformedCBOR("BLE mode UUIDs must be byte strings")
        }
        guard peripheral == (peripheralBytes != nil), central == (centralBytes != nil) else {
            throw MdocQrEngagementError.unsupportedDeviceEngagement(
                "BLE mode flags and UUID presence are inconsistent"
            )
        }
        guard peripheral || central else {
            throw MdocQrEngagementError.unsupportedDeviceEngagement("BLE retrieval method offers no BLE mode")
        }
        if let peripheralBytes {
            guard peripheralBytes.count == 16 else {
                throw MdocQrEngagementError.malformedCBOR("peripheral-server UUID must contain 16 bytes")
            }
        }
        if let centralBytes {
            guard centralBytes.count == 16 else {
                throw MdocQrEngagementError.malformedCBOR("central-client UUID must contain 16 bytes")
            }
        }
        return BleRetrievalMetadata(
            supportsPeripheralServerMode: peripheral,
            supportsCentralClientMode: central,
            peripheralServerModeUuid: peripheralBytes.map(uuid),
            centralClientModeUuid: centralBytes.map(uuid)
        )
    }

    private static func uuid(_ bytes: [UInt8]) -> UUID {
        UUID(uuid: (
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15]
        ))
    }
}

public enum MdocQrEngagementError: Error, Equatable, CustomStringConvertible {
    case invalidURI(String)
    case payloadTooLarge
    case malformedCBOR(String)
    case unsupportedDeviceEngagement(String)

    public var description: String {
        switch self {
        case .invalidURI(let reason):
            return "Invalid mdoc QR URI: \(reason)"
        case .payloadTooLarge:
            return "mdoc DeviceEngagement exceeds \(MdocQrEngagement.maximumDecodedSize) bytes"
        case .malformedCBOR(let reason):
            return "Malformed mdoc DeviceEngagement CBOR: \(reason)"
        case .unsupportedDeviceEngagement(let reason):
            return "Unsupported mdoc DeviceEngagement: \(reason)"
        }
    }
}

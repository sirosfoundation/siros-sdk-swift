// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
@preconcurrency import SwiftCBOR
#if canImport(CryptoKit)
import CryptoKit
#endif

/// ISO 18013-5 §8.2.1.1/§8.2.2.3 device engagement: builds the `DeviceEngagement`
/// CBOR structure and its `mdoc:` URI encoding for QR-code proximity presentation.
///
/// Cipher suite 1 only (ECDH/ECDSA over curve P-256, per §9.1.5.2 Table 22 - the
/// only cipher suite this document's session-encryption mechanisms describe).
///
/// Generates a fresh `EDeviceKey` ephemeral keypair per engagement - the private
/// key is returned (never encoded into the CBOR) since it's needed later for the
/// ECKA-DH session-key derivation once a reader connects (§9.1.1.4/§9.1.1.5).
///
/// Mirrors `org.siros.sdk.keystore.mdoc.DeviceEngagement` (Kotlin). Key
/// generation needs a real P-256 keypair (`CryptoKit.P256.KeyAgreement`),
/// which is Apple-only - this repo's established convention (see
/// `JweKeystore`) for anything EC-key-related is a `#if canImport(CryptoKit)`
/// dual implementation; on non-Apple platforms `create()` throws rather than
/// producing a fake/absent engagement.
public enum DeviceEngagement {

    /// Cipher suite identifier per §9.1.5.2 - this document only defines suite 1.
    private static let cipherSuite1: UInt64 = 1

    // COSE_Key labels (RFC 8152 §7/13.1.1) for an EC2 (P-256) public key.
    private static let coseKeyKty: CBOR = 1
    private static let coseKeyCrv: CBOR = -1
    private static let coseKeyX: CBOR = -2
    private static let coseKeyY: CBOR = -3
    private static let coseKtyEc2: UInt64 = 2
    private static let coseCrvP256: UInt64 = 1

    // DeviceRetrievalMethod type/version per Table 7.
    private static let retrievalTypeBle: UInt64 = 2
    private static let retrievalVersionBle: UInt64 = 1

    // BleOptions keys per §8.2.2.3.
    private static let bleSupportsPeripheralServerMode: CBOR = 0
    private static let bleSupportsCentralClientMode: CBOR = 1
    private static let blePeripheralServerModeUuid: CBOR = 10
    private static let bleCentralClientModeUuid: CBOR = 11

    #if canImport(CryptoKit)

    /// The result of generating a device engagement: bytes/URI to hand to a
    /// reader, plus the key material needed later for session encryption.
    public struct Engagement: @unchecked Sendable {
        /// Raw `DeviceEngagement` CBOR bytes - needed verbatim (as
        /// `DeviceEngagementBytes`) when building the proximity `SessionTranscript`.
        public let deviceEngagementBytes: [UInt8]
        /// `"mdoc:" + base64url-without-padding(deviceEngagementBytes)`, per
        /// §8.2.2.3 - the QR code payload.
        public let mdocUri: String
        /// The ephemeral `EDeviceKey` key pair generated for this engagement -
        /// a `KeyAgreement` (not `Signing`) key, since it's only ever used for
        /// ECKA-DH (see `ProximitySessionCrypto`), never to produce a signature.
        public let privateKey: P256.KeyAgreement.PrivateKey
        public var publicKey: P256.KeyAgreement.PublicKey { privateKey.publicKey }
        /// `EDeviceKeyBytes` (`#6.24(bstr .cbor EDeviceKey)`) exactly as
        /// embedded in `deviceEngagementBytes` - needed as the `Ident`
        /// characteristic's IKM (§11.1.3.1) when verifying a reader's
        /// identity in mdoc central client mode; kept as its own field
        /// rather than re-parsed from `deviceEngagementBytes` each time.
        public let eDeviceKeyBytes: [UInt8]
        /// Fresh UUID advertised for BLE peripheral-server-mode discovery, if that mode is offered.
        public let peripheralServerModeUuid: UUID?
        /// Fresh UUID advertised for BLE central-client-mode discovery, if that mode is offered.
        public let centralClientModeUuid: UUID?

        public init(
            deviceEngagementBytes: [UInt8],
            mdocUri: String,
            privateKey: P256.KeyAgreement.PrivateKey,
            eDeviceKeyBytes: [UInt8],
            peripheralServerModeUuid: UUID?,
            centralClientModeUuid: UUID?
        ) {
            self.deviceEngagementBytes = deviceEngagementBytes
            self.mdocUri = mdocUri
            self.privateKey = privateKey
            self.eDeviceKeyBytes = eDeviceKeyBytes
            self.peripheralServerModeUuid = peripheralServerModeUuid
            self.centralClientModeUuid = centralClientModeUuid
        }
    }

    /// Build a fresh device engagement offering BLE data retrieval.
    ///
    /// - Parameters:
    ///   - supportsCentralClientMode: advertise mdoc-as-GATT-client mode (§8.3.3.1.1).
    ///   - supportsPeripheralServerMode: advertise mdoc-as-GATT-server mode (§8.3.3.1.1).
    public static func create(
        supportsCentralClientMode: Bool = true,
        supportsPeripheralServerMode: Bool = true
    ) throws -> Engagement {
        guard supportsCentralClientMode || supportsPeripheralServerMode else {
            throw KeystoreError.invalidParameter("device engagement must offer at least one BLE mode")
        }

        let privateKey = P256.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey

        let peripheralUuid: UUID? = supportsPeripheralServerMode ? UUID() : nil
        let centralUuid: UUID? = supportsCentralClientMode ? UUID() : nil

        let deviceEngagementBytes = encode(
            publicKey: publicKey,
            supportsCentralClientMode: supportsCentralClientMode,
            supportsPeripheralServerMode: supportsPeripheralServerMode,
            peripheralUuid: peripheralUuid,
            centralUuid: centralUuid
        )
        let mdocUri = "mdoc:" + base64UrlNoPadding(deviceEngagementBytes)

        return Engagement(
            deviceEngagementBytes: deviceEngagementBytes,
            mdocUri: mdocUri,
            privateKey: privateKey,
            eDeviceKeyBytes: eDeviceKeyBytes(publicKey),
            peripheralServerModeUuid: peripheralUuid,
            centralClientModeUuid: centralUuid
        )
    }

    /// `EDeviceKeyBytes = #6.24(bstr .cbor EDeviceKey)`, per §9.1/§12.2.4.
    static func eDeviceKeyBytes(_ publicKey: P256.KeyAgreement.PublicKey) -> [UInt8] {
        CBOR.tagged(.encodedCBORDataItem, .byteString(coseKey(publicKey).encode())).encode()
    }

    /// Encode the `DeviceEngagement` CBOR structure per §8.2.1.1:
    /// ```
    /// DeviceEngagement = { 0: "1.0", 1: Security, 2: DeviceRetrievalMethods }
    /// Security = [ 1, EDeviceKeyBytes ]
    /// DeviceRetrievalMethods = [ [ 2, 1, BleOptions ] ]
    /// ```
    static func encode(
        publicKey: P256.KeyAgreement.PublicKey,
        supportsCentralClientMode: Bool,
        supportsPeripheralServerMode: Bool,
        peripheralUuid: UUID?,
        centralUuid: UUID?
    ) -> [UInt8] {
        let eDeviceKeyBytesTagged: CBOR = .tagged(.encodedCBORDataItem, .byteString(coseKey(publicKey).encode()))

        let security: CBOR = .array([.unsignedInt(cipherSuite1), eDeviceKeyBytesTagged])

        var bleOptions: [CBOR: CBOR] = [
            bleSupportsPeripheralServerMode: .boolean(supportsPeripheralServerMode),
            bleSupportsCentralClientMode: .boolean(supportsCentralClientMode),
        ]
        if let peripheralUuid {
            bleOptions[blePeripheralServerModeUuid] = .byteString(uuidBytes(peripheralUuid))
        }
        if let centralUuid {
            bleOptions[bleCentralClientModeUuid] = .byteString(uuidBytes(centralUuid))
        }

        let bleRetrievalMethod: CBOR = .array([
            .unsignedInt(retrievalTypeBle),
            .unsignedInt(retrievalVersionBle),
            .map(bleOptions),
        ])

        let deviceEngagement: CBOR = .map([
            CBOR.unsignedInt(0): .utf8String("1.0"),
            CBOR.unsignedInt(1): security,
            CBOR.unsignedInt(2): .array([bleRetrievalMethod]),
        ])

        return deviceEngagement.encode()
    }

    /// COSE_Key (RFC 8152 §13.1.1) for an uncompressed P-256 public point.
    ///
    /// Uses `x963Representation` (0x04 || X || Y) and manually slices X/Y,
    /// matching `JweKeystore.buildWalletStateV3`'s established pattern for
    /// extracting EC point coordinates from a CryptoKit public key.
    private static func coseKey(_ publicKey: P256.KeyAgreement.PublicKey) -> CBOR {
        let x963 = publicKey.x963Representation
        let x = Data(x963[1..<33])
        let y = Data(x963[33..<65])
        return .map([
            coseKeyKty: .unsignedInt(coseKtyEc2),
            coseKeyCrv: .unsignedInt(coseCrvP256),
            coseKeyX: .byteString([UInt8](x)),
            coseKeyY: .byteString([UInt8](y)),
        ])
    }

    #else

    /// Non-Apple stub: EC key generation requires CryptoKit, which isn't
    /// available on this platform (matching `JweKeystore`'s established
    /// convention). There is no engagement to build without a real
    /// `EDeviceKey`, so `create()` throws rather than returning a
    /// placeholder.
    public struct Engagement: Sendable {
        public let deviceEngagementBytes: [UInt8]
        public let mdocUri: String
        public let eDeviceKeyBytes: [UInt8]
        public let peripheralServerModeUuid: UUID?
        public let centralClientModeUuid: UUID?
    }

    public static func create(
        supportsCentralClientMode: Bool = true,
        supportsPeripheralServerMode: Bool = true
    ) throws -> Engagement {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }

    #endif

    private static func uuidBytes(_ uuid: UUID) -> [UInt8] {
        withUnsafeBytes(of: uuid.uuid) { Array($0) }
    }

    private static func base64UrlNoPadding(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

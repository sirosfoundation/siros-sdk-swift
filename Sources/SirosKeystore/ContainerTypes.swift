// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

// MARK: - Container data model

/// Parsed encrypted container matching the wallet-frontend format.
public struct ContainerData: Sendable {
    public var jwe: String
    public var mainKey: MainKeyInfo?
    public var prfKeys: [PrfKeyInfo]

    public init(jwe: String, mainKey: MainKeyInfo? = nil, prfKeys: [PrfKeyInfo] = []) {
        self.jwe = jwe
        self.mainKey = mainKey
        self.prfKeys = prfKeys
    }
}

public struct MainKeyInfo: Sendable {
    public var publicKey: EncapsulationPublicKeyInfo
    public var unwrapKey: MainUnwrapKeyInfo
}

public struct MainUnwrapKeyInfo: Sendable {
    public var format: String
    public var unwrapAlgo: String
    public var unwrappedKeyAlgo: AesGcmKeyAlgorithm
}

public struct AesGcmKeyAlgorithm: Sendable {
    public var name: String
    public var length: Int
}

public struct EncapsulationPublicKeyInfo: Sendable {
    public var importKey: ImportKeyInfo
}

public struct ImportKeyInfo: Sendable {
    public var format: String
    public var keyData: Data
    public var algorithm: EcKeyAlgorithm
}

public struct EcKeyAlgorithm: Sendable {
    public var name: String
    public var namedCurve: String
}

public struct EncapsulationKeypairInfo: Sendable {
    public var publicKey: EncapsulationPublicKeyInfo
    public var privateKey: EncapsulationPrivateKeyInfo
}

public struct EncapsulationPrivateKeyInfo: Sendable {
    public var unwrapKey: PrivateKeyUnwrapInfo
}

public struct PrivateKeyUnwrapInfo: Sendable {
    public var format: String
    public var wrappedKey: Data
    public var unwrapAlgo: AesGcmAlgo
    public var unwrappedKeyAlgo: EcKeyAlgorithm
}

public struct AesGcmAlgo: Sendable {
    public var name: String
    public var iv: Data
}

public struct StaticUnwrapKeyInfo: Sendable {
    public var wrappedKey: Data
    public var unwrappingKey: UnwrappingKeyInfo
}

public struct UnwrappingKeyInfo: Sendable {
    public var deriveKey: DeriveKeyInfo
}

public struct DeriveKeyInfo: Sendable {
    public var algorithm: AlgorithmName
    public var derivedKeyAlgorithm: AesKwAlgorithm
}

public struct AlgorithmName: Sendable {
    public var name: String
}

public struct AesKwAlgorithm: Sendable {
    public var name: String
    public var length: Int
}

public struct PrfKeyInfo: Sendable {
    public var credentialId: Data
    public var transports: [String]?
    public var prfSalt: Data
    public var hkdfSalt: Data
    public var hkdfInfo: Data
    public var algorithm: AesGcmKeyAlgorithm?
    public var keypair: EncapsulationKeypairInfo
    public var unwrapKey: StaticUnwrapKeyInfo
}

/// Result of wrapping a main key for a PRF key entry.
public struct PrfKeyEncapsulation: Sendable {
    public var keypair: EncapsulationKeypairInfo
    public var unwrapKey: StaticUnwrapKeyInfo
}

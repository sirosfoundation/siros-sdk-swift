// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SirosCredentials
import SirosKeystore

#if os(iOS)
extension SirosWallet {
    /// Assembles `init`'s mdoc+BBS ZK proof-system registry and the
    /// residency they share - split out of `init` itself to keep
    /// `SirosWallet.swift` under SwiftLint's `file_length` error threshold.
    static func makeIOSZkProofSystemRegistry(
        config: WalletConfig,
        keystore: KeystoreManager,
        credentialStore: CredentialStore,
        zkCircuitClient: ZkCircuitClient
    ) -> (registry: ZkProofSystemRegistry, residency: ZkProverResidency) {
        // BbsProofSystem (like Longfellow/Vega) is iOS-only - its native
        // zk-cred-bbs XCFramework ships iOS slices only, so the type itself
        // does not exist outside `#if os(iOS)` (see BbsProofSystem.swift's
        // own gating comment).
        //
        // Its holder state lives in this wallet's own keystore (see
        // `BbsHolderStateVault`'s doc comment) - unlike
        // LongfellowZkProofSystem/VegaProofSystem, which need no
        // wallet-local state at all, so it is assembled here rather than
        // being a fixed member of the mdoc ZK registry. Mirrors Kotlin's
        // `SirosWallet.bbsHolderStateVault`/`bbsHolderStateStore`: only
        // constructed when both the keystore in use can hold extension
        // entries (`ExtensionStore`) and the deployment actually declares
        // BBS credential types - an empty `config.bbsCredentialTypes` means
        // this deployment issues no BBS credentials, so `BbsProofSystem`
        // should not even be registered (see `WalletConfig.bbsCredentialTypes`'s
        // doc comment for why "registered but empty" is the wrong shape).
        //
        // The proof system keys on the JWP itself (all it has at
        // presentation time); the vault keys on credential id (privatedata-
        // spec §6.1.1 requires an entry key to name a tracked entity) - this
        // closure is the join between the two, same as Kotlin's.
        var bbsProofSystem: BbsProofSystem?
        if !config.bbsCredentialTypes.isEmpty, let extensionStore = keystore as? ExtensionStore {
            let bbsHolderStateVault = BbsHolderStateVault(keystore: extensionStore)
            let bbsHolderStateStore: BbsHolderStateStore = { issuedJwp in
                guard let credential = await credentialStore.getAll().first(where: { $0.raw == issuedJwp }) else {
                    return nil
                }
                return await bbsHolderStateVault.get(credentialId: String(credential.id))
            }
            bbsProofSystem = BbsProofSystem(
                holderState: bbsHolderStateStore,
                supportedVcts: config.bbsCredentialTypes
            )
        }

        // One residency shared by every mdoc ZK proof system constructed
        // here - see `ZkProverResidency`'s own doc comment for why. BBS has
        // no native prover/residency concept at all (no XCFramework, no
        // large resident artifact - see `BbsProofSystem`'s own doc comment),
        // so it is appended after, not threaded through the residency.
        let zkProverResidency = ZkProverResidency()
        var zkSystems: [ZkProofSystem] = [
            LongfellowZkProofSystem(zkCircuitClient: zkCircuitClient, residency: zkProverResidency),
            VegaProofSystem(zkCircuitClient: zkCircuitClient, residency: zkProverResidency),
        ]
        if let bbsProofSystem { zkSystems.append(bbsProofSystem) }
        return (ZkProofSystemRegistry(systems: zkSystems), zkProverResidency)
    }
}
#endif

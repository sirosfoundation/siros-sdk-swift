// swift-tools-version: 5.10
// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import PackageDescription

let package = Package(
    name: "SirosSDK",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(name: "SirosCredentials", targets: ["SirosCredentials"]),
        .library(name: "SirosTransport", targets: ["SirosTransport"]),
        .library(name: "SirosAuth", targets: ["SirosAuth"]),
        .library(name: "SirosKeystore", targets: ["SirosKeystore"]),
        .library(name: "SirosFlow", targets: ["SirosFlow"]),
        .library(name: "SirosWallet", targets: ["SirosWallet"]),
    ],
    dependencies: [
        .package(url: "https://github.com/swiftlang/swift-docc-plugin", from: "1.4.3"),
        .package(url: "https://github.com/valpackett/SwiftCBOR", from: "0.5.0"),
        // Cross-platform SHA-256 for ZkCircuitClient's artifact hash
        // verification. On Apple platforms CryptoKit is used directly (see
        // ZkCircuitClient.swift's `#if canImport(CryptoKit)`); swift-crypto's
        // `Crypto` module is only actually compiled/linked in on Linux,
        // where CryptoKit doesn't exist at all.
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.5.1"),
        // Circuits fetched from go-zk-circuits (see ZkCircuitClient,
        // SirosCredentials) are zstd-compressed; zk-cred-longfellow's
        // initializeProver expects already-decompressed bytes (confirmed
        // against wallet-frontend's feat/longfellow-zk reference
        // implementation) - decompression is the caller's responsibility,
        // not the native crate's. facebook/zstd ships its own SPM manifest
        // (a plain C target, no Swift wrapper) exposing this as `libzstd`.
        .package(url: "https://github.com/facebook/zstd.git", from: "1.5.6"),
    ],
    targets: [
        // --- zk-cred-longfellow UniFFI bindings (XCFramework) ---
        // Built by `make xcframework` in the zk-cred-longfellow crate; the
        // module name is the crate name + "FFI" (`zk_cred_longfellowFFI`),
        // matching siros_wscd_managerFFI's own naming convention below -
        // confirmed by inspecting the real published XCFramework's
        // module.modulemap.
        .binaryTarget(
            name: "zk_cred_longfellowFFI",
            url: "https://github.com/sirosfoundation/zk-cred-longfellow/releases/download/v0.1.1/zk_cred_longfellow.xcframework.zip",
            checksum: "dcbbaaeb5b1075d9794e1c2be830218742558a62aa19276b7b789dd05c6727f6"
        ),

        // --- Credentials: data models, DCQL matcher, VCTM types ---
        .target(
            name: "SirosCredentials",
            dependencies: [
                .product(name: "SwiftCBOR", package: "SwiftCBOR"),
                // AnyCodable (for ZkCircuitDescriptor.params' generic
                // map[string]any) already exists in SirosTransport - reused
                // here rather than duplicated. SirosTransport has no
                // dependencies of its own, so this doesn't introduce a cycle.
                "SirosTransport",
                .product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux])),
                // zk_cred_longfellowFFI's XCFramework only ships iOS slices
                // (device + simulator) - no macOS slice exists, and this
                // package's CI builds/tests the whole thing on bare macOS
                // too, so this dependency must be scoped to iOS only.
                // FFI-dependent code in this target is correspondingly
                // wrapped in `#if os(iOS)` (see Generated/zk_cred_longfellow.swift).
                .target(name: "zk_cred_longfellowFFI", condition: .when(platforms: [.iOS])),
            ],
            path: "Sources/SirosCredentials"
        ),
        .testTarget(
            name: "SirosCredentialsTests",
            dependencies: [
                "SirosCredentials",
                "SirosTransport",
                .product(name: "SwiftCBOR", package: "SwiftCBOR"),
            ],
            path: "Tests/SirosCredentialsTests"
        ),

        // --- Transport: WebSocket + WMP protocol ---
        .target(
            name: "SirosTransport",
            path: "Sources/SirosTransport"
        ),
        .testTarget(
            name: "SirosTransportTests",
            dependencies: ["SirosTransport"],
            path: "Tests/SirosTransportTests"
        ),

        // --- Auth: WebAuthn / passkey authentication ---
        .target(
            name: "SirosAuth",
            dependencies: ["SirosTransport", "SirosCredentials", "SirosKeystore"],
            path: "Sources/SirosAuth"
        ),
        .testTarget(
            name: "SirosAuthTests",
            dependencies: ["SirosAuth"],
            path: "Tests/SirosAuthTests"
        ),

        // --- siros-wscd-manager UniFFI bindings (XCFramework) ---
        // Built by `make xcframework` in the siros-wscd-manager crate;
        // the module name is the crate name + "FFI"
        // (`siros_wscd_managerFFI`, NOT a friendlier name like
        // "SirosWscdFFI" - confirmed by inspecting the real published
        // XCFramework's module.modulemap).
        .binaryTarget(
            name: "siros_wscd_managerFFI",
            url: "https://github.com/sirosfoundation/siros-wscd-manager/releases/download/v0.7.4/siros_wscd_manager.xcframework.zip",
            checksum: "10965e843c38e01b9be4d2b4663ad11c754131457240bed4b2100601280445bd"
        ),

        // --- Keystore: JWE-encrypted key management ---
        .target(
            name: "SirosKeystore",
            dependencies: [
                "SirosCredentials",
                // siros_wscd_managerFFI's XCFramework only ships iOS slices
                // (device + simulator) - no macOS slice exists, and this
                // package's CI builds/tests the whole thing on bare macOS
                // too (swift.yml's test-macos job), so this dependency must
                // be scoped to iOS only. FFI-dependent code in this target
                // is correspondingly wrapped in `#if os(iOS)`.
                .target(name: "siros_wscd_managerFFI", condition: .when(platforms: [.iOS])),
                .product(name: "SwiftCBOR", package: "SwiftCBOR"),
                // Only used by LongfellowZkProofSystem.swift, which is
                // itself `#if os(iOS)`-gated (see that file) since the
                // native zk_cred_longfellowFFI it wraps is iOS-only.
                .product(name: "libzstd", package: "zstd", condition: .when(platforms: [.iOS])),
            ],
            path: "Sources/SirosKeystore"
        ),
        .testTarget(
            name: "SirosKeystoreTests",
            dependencies: [
                "SirosKeystore",
                // Needed by LongfellowZkVectorTests for the vendored
                // zk_cred_longfellow UniFFI bindings (initializeProver,
                // proveWithPpid, CircuitVersion), which live in
                // SirosCredentials's own module, not SirosKeystore's.
                "SirosCredentials",
                .product(name: "SwiftCBOR", package: "SwiftCBOR"),
                .product(name: "libzstd", package: "zstd", condition: .when(platforms: [.iOS])),
            ],
            path: "Tests/SirosKeystoreTests",
            resources: [.copy("Resources")]
        ),

        // --- Flow: OID4VCI / OID4VP flow orchestration ---
        .target(
            name: "SirosFlow",
            dependencies: ["SirosTransport", "SirosKeystore", "SirosAuth"],
            path: "Sources/SirosFlow"
        ),
        .testTarget(
            name: "SirosFlowTests",
            dependencies: ["SirosFlow"],
            path: "Tests/SirosFlowTests"
        ),

        // --- Wallet: main facade ---
        .target(
            name: "SirosWallet",
            dependencies: [
                "SirosTransport",
                "SirosAuth",
                "SirosKeystore",
                "SirosFlow",
                "SirosCredentials",
            ],
            path: "Sources/SirosWallet"
        ),
        .testTarget(
            name: "SirosWalletTests",
            dependencies: ["SirosWallet"],
            path: "Tests/SirosWalletTests"
        ),
    ]
)

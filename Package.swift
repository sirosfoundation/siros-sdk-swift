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
    ],
    targets: [
        // --- Credentials: data models, DCQL matcher, VCTM types ---
        .target(
            name: "SirosCredentials",
            dependencies: [
                .product(name: "SwiftCBOR", package: "SwiftCBOR"),
            ],
            path: "Sources/SirosCredentials"
        ),
        .testTarget(
            name: "SirosCredentialsTests",
            dependencies: [
                "SirosCredentials",
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
            url: "https://github.com/sirosfoundation/siros-wscd-manager/releases/download/v0.7.2/siros_wscd_manager.xcframework.zip",
            checksum: "a7ac1dcd6407cb47785e4f02fe3e4d085c82317ecde4e81378b65302b998984c"
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
            ],
            path: "Sources/SirosKeystore"
        ),
        .testTarget(
            name: "SirosKeystoreTests",
            dependencies: [
                "SirosKeystore",
                .product(name: "SwiftCBOR", package: "SwiftCBOR"),
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

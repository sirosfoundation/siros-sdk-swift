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
    ],
    targets: [
        // --- Credentials: data models, DCQL matcher, VCTM types ---
        .target(
            name: "SirosCredentials",
            path: "Sources/SirosCredentials"
        ),
        .testTarget(
            name: "SirosCredentialsTests",
            dependencies: ["SirosCredentials"],
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

        // --- Keystore: JWE-encrypted key management ---
        .target(
            name: "SirosKeystore",
            dependencies: ["SirosCredentials"],
            path: "Sources/SirosKeystore"
        ),
        .testTarget(
            name: "SirosKeystoreTests",
            dependencies: ["SirosKeystore"],
            path: "Tests/SirosKeystoreTests"
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

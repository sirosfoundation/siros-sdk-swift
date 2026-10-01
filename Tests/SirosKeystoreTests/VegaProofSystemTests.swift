// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

// The native zk_cred_vega XCFramework only ships iOS slices - see
// VegaProofSystem.swift's own `#if os(iOS)` gating.
#if os(iOS)

import XCTest
import SirosCredentials
@testable import SirosKeystore

/// `VegaProofSystem.validateCircuitParams` - checks the real circuit
/// catalog's own published `params` (confirmed live against the deployed
/// `vega-mc-p256-v1-*-key-r12` entries: `curve: "P-256"`, `numClaims: "4"`)
/// against what this type hardcodes, so a future circuit version whose
/// shape has genuinely changed fails fast and locally, with a clear
/// diagnostic - instead of only surfacing as an opaque native
/// prove()/verify() failure much later. Ports Kotlin's `VegaProofSystemTest`
/// (siros-sdk-kotlin#244) - same four cases.
final class VegaProofSystemTests: XCTestCase {

    private func descriptor(_ params: [String: String]) -> ZkCircuitDescriptor {
        ZkCircuitDescriptor(
            id: "vega-mc-p256-v1-prover-key-r12",
            system: "vega-mc",
            systemVersion: "12",
            published: true,
            status: "active",
            params: params.mapValues { .string($0) },
            publishedAt: "2026-08-27T20:53:51Z"
        )
    }

    func testValidateCircuitParams_realCatalogShape_passes() throws {
        try VegaProofSystem.validateCircuitParams(
            descriptor(["curve": "P-256", "numClaims": "4", "maxClaimBytes": "176"])
        )
    }

    func testValidateCircuitParams_wrongCurve_throws() {
        XCTAssertThrowsError(
            try VegaProofSystem.validateCircuitParams(descriptor(["curve": "P-384", "numClaims": "4"]))
        )
    }

    func testValidateCircuitParams_wrongNumClaims_throws() {
        XCTAssertThrowsError(
            try VegaProofSystem.validateCircuitParams(descriptor(["curve": "P-256", "numClaims": "8"]))
        )
    }

    func testValidateCircuitParams_missingParams_throws() {
        XCTAssertThrowsError(try VegaProofSystem.validateCircuitParams(descriptor([:])))
    }
}

#endif // os(iOS)

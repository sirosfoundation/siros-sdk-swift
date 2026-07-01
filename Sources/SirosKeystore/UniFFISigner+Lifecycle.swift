// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

#if canImport(SirosWscdFFI)
import SirosWscdFFI

extension UniFFISigner: SignerLifecycleManager {
    public func lifecycleStatus(pluginId: String, contextId: String) async throws -> LifecycleStatus {
        try await onFFIQueue {
            try self.ffi.lifecycleStatus(pluginId: pluginId, contextId: contextId).toSdkLifecycleStatus()
        }
    }

    public func registerLifecycle(request: RegisterLifecycleRequest) async throws -> RegistrationOutcome {
        try await onFFIQueue {
            try self.ffi.registerLifecycle(
                request: request.toFfiRequest(),
                auth: self.authCallbackBridge(),
                progress: NoOpProgressCallback()
            ).toSdkRegistrationOutcome()
        }
    }

    public func activateLifecycle(request: ActivateLifecycleRequest) async throws -> ActivationOutcome {
        try await onFFIQueue {
            try self.ffi.activateLifecycle(
                request: request.toFfiRequest(),
                auth: self.authCallbackBridge(),
                progress: NoOpProgressCallback()
            ).toSdkActivationOutcome()
        }
    }

    public func rotateLifecycle(request: RotateLifecycleRequest) async throws -> RotationOutcome {
        try await onFFIQueue {
            try self.ffi.rotateLifecycle(
                request: request.toFfiRequest(),
                auth: self.authCallbackBridge(),
                progress: NoOpProgressCallback()
            ).toSdkRotationOutcome()
        }
    }

    public func destroyLifecycle(request: DestroyLifecycleRequest) async throws -> DestructionOutcome {
        try await onFFIQueue {
            try self.ffi.destroyLifecycle(
                request: request.toFfiRequest(),
                auth: self.authCallbackBridge(),
                progress: NoOpProgressCallback()
            ).toSdkDestructionOutcome()
        }
    }
}

private extension RegisterLifecycleRequest {
    func toFfiRequest() -> FfiRegisterLifecycleRequest {
        FfiRegisterLifecycleRequest(
            pluginId: pluginId,
            contextId: contextId,
            factorKind: factorKind.toFfiFactorKind()
        )
    }
}

private extension ActivateLifecycleRequest {
    func toFfiRequest() -> FfiActivateLifecycleRequest {
        FfiActivateLifecycleRequest(pluginId: pluginId, contextId: contextId)
    }
}

private extension RotateLifecycleRequest {
    func toFfiRequest() -> FfiRotateLifecycleRequest {
        FfiRotateLifecycleRequest(pluginId: pluginId, contextId: contextId)
    }
}

private extension DestroyLifecycleRequest {
    func toFfiRequest() -> FfiDestroyLifecycleRequest {
        FfiDestroyLifecycleRequest(
            pluginId: pluginId,
            contextId: contextId,
            mode: mode.toFfiDestroyMode(),
            reason: reason
        )
    }
}

private extension FactorKind {
    func toFfiFactorKind() -> FfiFactorKind {
        switch self {
        case .opaque: return .opaque
        case .webAuthn: return .webAuthn
        case .rawSign: return .rawSign
        }
    }
}

private extension DestroyMode {
    func toFfiDestroyMode() -> FfiDestroyMode {
        switch self {
        case .localOnly: return .localOnly
        case .remoteRevokeIfSupported: return .remoteRevokeIfSupported
        case .strict: return .strict
        }
    }
}

private extension FfiFactorKind {
    func toSdkFactorKind() -> FactorKind {
        switch self {
        case .opaque: return .opaque
        case .webAuthn: return .webAuthn
        case .rawSign: return .rawSign
        }
    }
}

private extension FfiLifecycleState {
    func toSdkLifecycleState() -> LifecycleState {
        switch self {
        case .uninitialized: return .uninitialized
        case .registered: return .registered
        case .active: return .active
        case .suspended: return .suspended
        case .destroyed: return .destroyed
        }
    }
}

private extension FfiLifecycleStatus {
    func toSdkLifecycleStatus() -> LifecycleStatus {
        LifecycleStatus(
            contextId: contextId,
            pluginId: pluginId,
            factorKind: factorKind.toSdkFactorKind(),
            state: state.toSdkLifecycleState(),
            updatedAt: updatedAt
        )
    }
}

private extension FfiRegistrationOutcome {
    func toSdkRegistrationOutcome() -> RegistrationOutcome {
        RegistrationOutcome(contextId: contextId, state: state.toSdkLifecycleState())
    }
}

private extension FfiActivationOutcome {
    func toSdkActivationOutcome() -> ActivationOutcome {
        ActivationOutcome(contextId: contextId, state: state.toSdkLifecycleState())
    }
}

private extension FfiRotationOutcome {
    func toSdkRotationOutcome() -> RotationOutcome {
        RotationOutcome(contextId: contextId, state: state.toSdkLifecycleState())
    }
}

private extension FfiDestructionOutcome {
    func toSdkDestructionOutcome() -> DestructionOutcome {
        DestructionOutcome(
            contextId: contextId,
            state: state.toSdkLifecycleState(),
            remotePerformed: remotePerformed
        )
    }
}

#endif

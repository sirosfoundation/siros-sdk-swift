// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Explicit lifecycle operations for WSCD-backed signers.
///
/// This is separate from `Signer` so existing integrations that only need
/// raw key operations remain source-compatible.
public protocol SignerLifecycleManager: AnyObject, Sendable {
    func lifecycleStatus(pluginId: String, contextId: String) async throws -> LifecycleStatus
    func registerLifecycle(request: RegisterLifecycleRequest) async throws -> RegistrationOutcome
    func activateLifecycle(request: ActivateLifecycleRequest) async throws -> ActivationOutcome
    func rotateLifecycle(request: RotateLifecycleRequest) async throws -> RotationOutcome
    func destroyLifecycle(request: DestroyLifecycleRequest) async throws -> DestructionOutcome
}

public enum FactorKind: Sendable, Equatable {
    case opaque
    case webAuthn
    case rawSign
}

public enum LifecycleState: Sendable, Equatable {
    case uninitialized
    case registered
    case active
    case suspended
    case destroyed
}

public enum DestroyMode: Sendable, Equatable {
    case localOnly
    case remoteRevokeIfSupported
    case strict
}

public struct LifecycleStatus: Sendable, Equatable {
    public let contextId: String
    public let pluginId: String
    public let factorKind: FactorKind
    public let state: LifecycleState
    public let updatedAt: Int64

    public init(contextId: String, pluginId: String, factorKind: FactorKind, state: LifecycleState, updatedAt: Int64) {
        self.contextId = contextId
        self.pluginId = pluginId
        self.factorKind = factorKind
        self.state = state
        self.updatedAt = updatedAt
    }
}

public struct RegisterLifecycleRequest: Sendable, Equatable {
    public let pluginId: String
    public let contextId: String
    public let factorKind: FactorKind

    public init(pluginId: String, contextId: String, factorKind: FactorKind) {
        self.pluginId = pluginId
        self.contextId = contextId
        self.factorKind = factorKind
    }
}

public struct ActivateLifecycleRequest: Sendable, Equatable {
    public let pluginId: String
    public let contextId: String

    public init(pluginId: String, contextId: String) {
        self.pluginId = pluginId
        self.contextId = contextId
    }
}

public struct RotateLifecycleRequest: Sendable, Equatable {
    public let pluginId: String
    public let contextId: String

    public init(pluginId: String, contextId: String) {
        self.pluginId = pluginId
        self.contextId = contextId
    }
}

public struct DestroyLifecycleRequest: Sendable, Equatable {
    public let pluginId: String
    public let contextId: String
    public let mode: DestroyMode
    public let reason: String?

    public init(pluginId: String, contextId: String, mode: DestroyMode, reason: String? = nil) {
        self.pluginId = pluginId
        self.contextId = contextId
        self.mode = mode
        self.reason = reason
    }
}

public struct RegistrationOutcome: Sendable, Equatable {
    public let contextId: String
    public let state: LifecycleState

    public init(contextId: String, state: LifecycleState) {
        self.contextId = contextId
        self.state = state
    }
}

public struct ActivationOutcome: Sendable, Equatable {
    public let contextId: String
    public let state: LifecycleState

    public init(contextId: String, state: LifecycleState) {
        self.contextId = contextId
        self.state = state
    }
}

public struct RotationOutcome: Sendable, Equatable {
    public let contextId: String
    public let state: LifecycleState

    public init(contextId: String, state: LifecycleState) {
        self.contextId = contextId
        self.state = state
    }
}

public struct DestructionOutcome: Sendable, Equatable {
    public let contextId: String
    public let state: LifecycleState
    public let remotePerformed: Bool

    public init(contextId: String, state: LifecycleState, remotePerformed: Bool) {
        self.contextId = contextId
        self.state = state
        self.remotePerformed = remotePerformed
    }
}
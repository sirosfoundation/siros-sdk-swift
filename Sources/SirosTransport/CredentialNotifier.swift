// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Transport-independent protocol for sending OID4VCI §10 credential
/// lifecycle notifications.
///
/// Both ``WalletEngineSession`` (legacy WebSocket) and
/// ``FlowClient`` (WMP) conform, allowing callers to send
/// notifications without knowing which transport is active.
public protocol CredentialNotifier: AnyObject, Sendable {
    /// Send a credential lifecycle notification.
    ///
    /// Implementations are fire-and-forget: errors are logged, never thrown.
    /// Calling this when the transport is disconnected is a safe no-op.
    func sendCredentialNotification(
        flowId: String,
        notificationId: String,
        event: String,
        eventDescription: String?
    )
}

/// Default parameter for eventDescription.
public extension CredentialNotifier {
    func sendCredentialNotification(
        flowId: String,
        notificationId: String,
        event: String
    ) {
        sendCredentialNotification(
            flowId: flowId,
            notificationId: notificationId,
            event: event,
            eventDescription: nil
        )
    }
}

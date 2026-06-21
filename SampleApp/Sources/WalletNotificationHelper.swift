// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import UserNotifications

/// Helper for showing platform-native notifications for credential lifecycle events.
final class WalletNotificationHelper: @unchecked Sendable {

    static let shared = WalletNotificationHelper()

    private init() {}

    /// Request notification permission. Call this early (e.g. on app launch).
    func requestPermission() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    /// Show a notification that a credential was received.
    func notifyCredentialReceived(credentialName: String?) {
        let title = "Credential Received"
        let body = credentialName.map { "\"\($0)\" has been added to your wallet" }
            ?? "A new credential has been added to your wallet"
        showNotification(title: title, body: body, identifier: "credential-received-\(UUID().uuidString)")
    }

    /// Show a notification that a credential was deleted.
    func notifyCredentialDeleted(credentialName: String?) {
        let title = "Credential Deleted"
        let body = credentialName.map { "\"\($0)\" has been removed from your wallet" }
            ?? "A credential has been removed from your wallet"
        showNotification(title: title, body: body, identifier: "credential-deleted-\(UUID().uuidString)")
    }

    private func showNotification(title: String, body: String, identifier: String) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default

        let request = UNNotificationRequest(identifier: identifier, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request) { _ in }
    }
}

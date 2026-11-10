// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials

extension CredentialWithInstances {

    /// Whether this credential belongs under "Needs attention": the SDK
    /// reports a status that stops it being used (`statuses`, see
    /// `WalletViewModel.credentialStatuses`), or no copy of it is left to
    /// present - the state its card shows as renew-only
    /// (`credentialBatchExhausted`).
    func needsAttention(statuses: [Int64: CredentialStatus]) -> Bool {
        if let status = statuses[credential.id], status != .valid { return true }
        return !instances.contains { $0.sigCount == 0 }
    }
}

extension StoredCredential {

    /// Whether `query` occurs in the name the credential is listed under. A
    /// blank query matches every credential.
    func matchesSearch(_ query: String) -> Bool {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return true }
        return (metadata?.name ?? format).localizedCaseInsensitiveContains(trimmed)
    }
}

/// Whether a history record mentions `query` in its verifier or its
/// credentials. A blank query matches all.
func matchesHistoryQuery(verifierName: String?, credentialNames: [String], query: String) -> Bool {
    let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
    if trimmed.isEmpty { return true }
    if let verifierName, verifierName.localizedCaseInsensitiveContains(trimmed) { return true }
    return credentialNames.contains { $0.localizedCaseInsensitiveContains(trimmed) }
}

/// The day heading a record at `timestamp` (Unix milliseconds) falls under,
/// as seen at `now`: `today`, `yesterday`, or the date.
func historyDayLabel(
    timestamp: Int64,
    now: Date,
    today: String,
    yesterday: String,
    calendar: Calendar = .current,
    locale: Locale = .current
) -> String {
    let date = Date(timeIntervalSince1970: TimeInterval(timestamp) / 1000.0)
    let days = calendar.dateComponents(
        [.day],
        from: calendar.startOfDay(for: date),
        to: calendar.startOfDay(for: now)
    ).day ?? 0
    switch days {
    case 0: return today
    case 1: return yesterday
    default:
        let formatter = DateFormatter()
        formatter.calendar = calendar
        formatter.timeZone = calendar.timeZone
        formatter.locale = locale
        formatter.dateFormat = "d MMMM yyyy"
        return formatter.string(from: date)
    }
}

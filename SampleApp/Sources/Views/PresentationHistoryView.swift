// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosCredentials

/// History: the wallet's log of presentations, newest first under day
/// headings, with a search over who it was shown to and what was shown.
/// Supports optional credential filtering. Chrome-free - `ContentView`
/// frames it.
struct PresentationHistoryView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    var filterCredentialId: Int64? = nil

    @State private var query = ""

    /// The records to show, newest first, under their day headings.
    private var groups: [(day: String, records: [PresentationRecord])] {
        let today = L10n.string("history.today")
        let yesterday = L10n.string("history.yesterday")
        let now = Date()
        let records = viewModel.presentationHistory
            .filter { record in filterCredentialId.map { record.credentialIds.contains($0) } ?? true }
            .filter { matchesHistoryQuery(verifierName: $0.verifierName, credentialNames: $0.credentialNames, query: query) }
            .sorted { $0.timestamp > $1.timestamp }
        var result: [(day: String, records: [PresentationRecord])] = []
        for record in records {
            let day = historyDayLabel(timestamp: record.timestamp, now: now, today: today, yesterday: yesterday)
            if let last = result.indices.last, result[last].day == day {
                result[last].records.append(record)
            } else {
                result.append((day: day, records: [record]))
            }
        }
        return result
    }

    var body: some View {
        let groups = self.groups
        VStack(alignment: .leading, spacing: 12) {
            Text(L10n.string("menu.history"))
                .font(.title2.weight(.medium))
                .foregroundColor(SirosTheme.ink)
            HStack {
                TextField(L10n.string("history.search"), text: $query)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                Image(systemName: "magnifyingglass")
                    .foregroundColor(SirosTheme.hairline)
            }
            .padding(.horizontal, 14)
            .frame(minHeight: 44)
            .overlay(RoundedRectangle(cornerRadius: SirosTheme.cardCorner).stroke(SirosTheme.hairline, lineWidth: 1))
            .accessibilityIdentifier("history-search")

            if groups.isEmpty {
                Text(L10n.string("history.empty"))
                    .font(.body)
                    .foregroundColor(SirosTheme.secondaryText)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 16) {
                        ForEach(groups, id: \.day) { group in
                            Text(group.day)
                                .font(.title3.weight(.semibold))
                                .foregroundColor(SirosTheme.ink)
                            ForEach(group.records, id: \.id) { record in
                                PresentationRecordRow(record: record)
                                    .walletCard(padding: 14)
                            }
                        }
                    }
                    .padding(.top, 4)
                    .padding(.bottom, 24)
                }
            }
        }
        .padding(.horizontal, SirosTheme.screenMargin)
        .padding(.top, 24)
        .background(SirosTheme.screenBackground)
    }
}

// MARK: - Record Row (expandable)

struct PresentationRecordRow: View {
    let record: PresentationRecord
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Summary row
            Button(action: { withAnimation { expanded.toggle() } }) {
                HStack(spacing: 12) {
                    Image(systemName: record.success ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .font(.title3)
                        .foregroundColor(record.success ? SirosTheme.brand : SirosTheme.error)

                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text(record.verifierName ?? L10n.string("history.unknownVerifier"))
                                .font(.body.weight(.semibold))
                                .foregroundColor(SirosTheme.onSurface)
                                .lineLimit(1)
                            // A ZK proof disclosed nothing the verifier could
                            // link across presentations - worth a glance-level
                            // signal in the row, matching the Android sample.
                            if record.zkProof {
                                Image(systemName: "lock.fill")
                                    .font(.caption2)
                                    .foregroundColor(SirosTheme.brand)
                                    .accessibilityLabel(L10n.string("history.zkProof"))
                            }
                        }

                        if !record.credentialNames.isEmpty {
                            Text(record.credentialNames.joined(separator: ", "))
                                .font(.body)
                                .foregroundColor(SirosTheme.ink)
                                .lineLimit(1)
                        }

                        Text(formatTimestamp(record.timestamp))
                            .font(.body)
                            .foregroundColor(SirosTheme.ink)
                    }

                    Spacer()

                    Image(systemName: expanded ? "chevron.up" : "chevron.down")
                        .font(.caption)
                        .foregroundColor(SirosTheme.onSurfaceVariant)
                }
            }
            .buttonStyle(.plain)
            .padding(.vertical, 4)

            // Expandable detail
            if expanded {
                VStack(alignment: .leading, spacing: 4) {
                    Divider()

                    if !record.credentialNames.isEmpty {
                        Text(L10n.string("history.credentialsSharedLabel"))
                            .font(.caption2)
                            .foregroundColor(SirosTheme.onSurfaceVariant)
                        ForEach(record.credentialNames, id: \.self) { name in
                            Text("  • \(name)")
                                .font(.caption)
                        }
                    }

                    if !record.requestedClaims.flatMap({ $0 }).isEmpty {
                        Text(L10n.string("history.dataDisclosedLabel"))
                            .font(.caption2)
                            .foregroundColor(SirosTheme.onSurfaceVariant)
                        ForEach(record.requestedClaims.flatMap({ $0 }), id: \.self) { claim in
                            Text("  • \(formatClaimName(claim))")
                                .font(.caption)
                        }
                    }

                    Text(L10n.string("history.flowIdLabel", record.flowId))
                        .font(.caption2)
                        .foregroundColor(SirosTheme.border)
                    Text(L10n.string("history.statusLabel", record.success ? L10n.string("history.statusSuccessful") : L10n.string("history.statusFailed")))
                        .font(.caption2)
                        .foregroundColor(record.success ? SirosTheme.brand : SirosTheme.error)
                }
                .padding(.top, 4)
                .padding(.bottom, 8)
            }
        }
    }

    private func formatTimestamp(_ timestamp: Int64) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(timestamp) / 1000.0)
        return date.formatted(date: .numeric, time: .standard)
    }

    private func formatClaimName(_ claim: String) -> String {
        claim.split(separator: ".").flatMap { $0.split(separator: "_") }
            .map { $0.prefix(1).uppercased() + $0.dropFirst() }
            .joined(separator: " ")
    }
}

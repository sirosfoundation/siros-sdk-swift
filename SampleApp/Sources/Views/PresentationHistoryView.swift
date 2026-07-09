// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosCredentials

/// Displays presentation history — a log of credential presentations
/// made to verifiers. Supports optional credential filtering.
struct PresentationHistoryView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    var filterCredentialId: String? = nil

    var body: some View {
        let history = filterCredentialId.map { credId in
            viewModel.presentationHistory.filter { $0.credentialIds.contains(credId) }
        } ?? viewModel.presentationHistory

        NavigationStack {
            Group {
                if history.isEmpty {
                    Text("No presentation history")
                        .font(.body)
                        .foregroundColor(SirosTheme.onSurfaceVariant)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    List(history, id: \.id) { record in
                        PresentationRecordRow(record: record)
                    }
                    .listStyle(.plain)
                }
            }
            .navigationTitle("Presentation History")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Back") { viewModel.closeHistory() }
                }
            }
        }
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
                        Text(record.verifierName ?? "Unknown Verifier")
                            .font(.body.weight(.medium))
                            .foregroundColor(SirosTheme.onSurface)
                            .lineLimit(1)

                        if !record.credentialNames.isEmpty {
                            Text(record.credentialNames.joined(separator: ", "))
                                .font(.caption)
                                .foregroundColor(SirosTheme.onSurfaceVariant)
                                .lineLimit(1)
                        }

                        Text(formatTimestamp(record.timestamp))
                            .font(.caption2)
                            .foregroundColor(SirosTheme.onSurfaceVariant)
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
                        Text("Credentials shared:")
                            .font(.caption2)
                            .foregroundColor(SirosTheme.onSurfaceVariant)
                        ForEach(record.credentialNames, id: \.self) { name in
                            Text("  • \(name)")
                                .font(.caption)
                        }
                    }

                    if !record.requestedClaims.flatMap({ $0 }).isEmpty {
                        Text("Data disclosed:")
                            .font(.caption2)
                            .foregroundColor(SirosTheme.onSurfaceVariant)
                        ForEach(record.requestedClaims.flatMap({ $0 }), id: \.self) { claim in
                            Text("  • \(formatClaimName(claim))")
                                .font(.caption)
                        }
                    }

                    Text("Flow ID: \(record.flowId)")
                        .font(.caption2)
                        .foregroundColor(SirosTheme.border)
                    Text("Status: \(record.success ? "Successful" : "Failed")")
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
        return date.formatted(date: .abbreviated, time: .shortened)
    }

    private func formatClaimName(_ claim: String) -> String {
        claim.split(separator: ".").flatMap { $0.split(separator: "_") }
            .map { $0.prefix(1).uppercased() + $0.dropFirst() }
            .joined(separator: " ")
    }
}

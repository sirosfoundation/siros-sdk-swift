// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosCredentials

/// Displays presentation history — a log of credential presentations
/// made to verifiers.
struct PresentationHistoryView: View {
    @EnvironmentObject var viewModel: WalletViewModel

    var body: some View {
        NavigationStack {
            Group {
                if viewModel.presentationHistory.isEmpty {
                    Text("No presentation history")
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    List(viewModel.presentationHistory, id: \.id) { record in
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

// MARK: - Record Row

struct PresentationRecordRow: View {
    let record: PresentationRecord

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: record.success ? "checkmark.circle.fill" : "xmark.circle.fill")
                .font(.title3)
                .foregroundStyle(record.success ? .green : .red)

            VStack(alignment: .leading, spacing: 2) {
                Text(record.verifierName ?? "Unknown Verifier")
                    .font(.body.weight(.medium))
                    .lineLimit(1)

                HStack(spacing: 4) {
                    Text(record.credentialNames.joined(separator: ", "))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }

                Text(formatTimestamp(record.timestamp))
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }

            Spacer()
        }
        .padding(.vertical, 4)
    }

    private func formatTimestamp(_ timestamp: Int64) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(timestamp))
        return date.formatted(date: .abbreviated, time: .shortened)
    }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosCredentials

/// A monospaced, pretty-printed text block with a copy-to-clipboard button.
///
/// Pretty-prints `text` as JSON or XML/SVG if it parses as either (via the
/// SDK's `CredentialUtils.prettyPrintJson`/`prettyPrintXml`), otherwise shows
/// it as-is. The copy button always copies the ORIGINAL (non-pretty-printed)
/// text, so pasting elsewhere reproduces the exact source value.
struct CopyableTextBlock: View {
    let text: String
    var label: String?

    @State private var justCopied = false

    private var displayText: String {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("{") || trimmed.hasPrefix("[") {
            return CredentialUtils.prettyPrintJson(text)
        }
        if trimmed.hasPrefix("<") {
            return CredentialUtils.prettyPrintXml(text)
        }
        return text
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            if let label {
                Text(label)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            ZStack(alignment: .topTrailing) {
                ScrollView(.horizontal, showsIndicators: false) {
                    Text(displayText)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(12)
                        .padding(.trailing, 28)
                }
                .background(
                    RoundedRectangle(cornerRadius: 8)
                        .fill(Color(.secondarySystemBackground))
                )

                Button(action: copyToClipboard) {
                    Image(systemName: justCopied ? "checkmark" : "doc.on.doc")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .padding(8)
                }
                .buttonStyle(.borderless)
            }
        }
    }

    private func copyToClipboard() {
        #if canImport(UIKit)
        UIPasteboard.general.string = text
        #endif
        justCopied = true
        Task {
            try? await Task.sleep(nanoseconds: 1_200_000_000)
            justCopied = false
        }
    }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosCredentials

/// Credit-card style credential display.
///
/// Uses background_color/text_color from credential metadata when available,
/// otherwise falls back to system colors.
/// Aspect ratio 1.6:1 matches the web frontend's card proportions.
struct CredentialCardView: View {
    let credential: StoredCredential

    var body: some View {
        let meta = credential.metadata
        let bgColor = meta?.backgroundColor.flatMap { Color(hex: $0) } ?? .accentColor
        let fgColor = meta?.textColor.flatMap { Color(hex: $0) } ?? .white

        VStack(alignment: .leading, spacing: 0) {
            // Top: issuer badge
            HStack(spacing: 8) {
                issuerBadge(meta: meta, fgColor: fgColor)
                Text(meta?.issuer?.name ?? "Unknown Issuer")
                    .font(.caption)
                    .foregroundStyle(fgColor.opacity(0.8))
                Spacer()
                Text(credential.format.uppercased())
                    .font(.caption2.bold())
                    .foregroundStyle(fgColor.opacity(0.6))
            }

            Spacer()

            // Bottom: credential name
            Text(meta?.name ?? credential.format)
                .font(.title3.bold())
                .foregroundStyle(fgColor)
                .lineLimit(2)

            if let description = meta?.description {
                Text(description)
                    .font(.caption)
                    .foregroundStyle(fgColor.opacity(0.7))
                    .lineLimit(1)
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity)
        .aspectRatio(1.6, contentMode: .fit)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(bgColor)
        )
        .shadow(color: bgColor.opacity(0.3), radius: 8, y: 4)
    }

    @ViewBuilder
    private func issuerBadge(meta: CredentialMetadata?, fgColor: Color) -> some View {
        let initial = (meta?.issuer?.name ?? "?").prefix(1).uppercased()
        Circle()
            .fill(fgColor.opacity(0.15))
            .frame(width: 32, height: 32)
            .overlay(
                Text(initial)
                    .font(.caption.bold())
                    .foregroundStyle(fgColor)
            )
    }
}

// MARK: - Color hex extension

extension Color {
    init?(hex: String) {
        var hexString = hex.trimmingCharacters(in: .whitespacesAndNewlines)
        if hexString.hasPrefix("#") {
            hexString.removeFirst()
        }
        guard hexString.count == 6,
              let value = UInt64(hexString, radix: 16) else {
            return nil
        }
        let r = Double((value >> 16) & 0xFF) / 255.0
        let g = Double((value >> 8) & 0xFF) / 255.0
        let b = Double(value & 0xFF) / 255.0
        self.init(red: r, green: g, blue: b)
    }
}

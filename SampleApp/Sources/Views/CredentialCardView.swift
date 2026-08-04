// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosCredentials
import SVGView

/// Credit-card style credential display.
///
/// Uses background_color/text_color from credential metadata when available,
/// otherwise falls back to system colors.
/// Aspect ratio 1.6:1 matches the web frontend's card proportions.
///
/// If the issuer's VCTM published `rendering.svg_templates`, this renders the
/// real branded SVG (claims substituted into its `{{svg_id}}` placeholders)
/// instead of the flat color+logo layout - shows a spinner while fetching
/// rather than flashing the flat layout first, and falls back to it if the
/// fetch/substitution fails for any reason.
struct CredentialCardView: View {
    let credential: StoredCredential
    /// Every copy in this credential's batch (see `StoredCredential.batchId`),
    /// including itself - mirrors wallet-frontend's `vcEntity.instances`: the
    /// ribbon shows how many copies haven't been used in a presentation yet.
    /// Nil (the default) hides the ribbon entirely and never treats the card
    /// as exhausted - for callers, like the detail screen's compact header,
    /// that don't have batch/usage data on hand rather than showing a
    /// misleading "0".
    var instances: [CredentialInstance]? = nil
    /// Called when the card is tapped, UNLESS it's exhausted (every batch
    /// instance already used - see `instances`) - mirrors the Kotlin sample
    /// app's `CredentialCard` owning its own click-vs-exhausted gating
    /// internally rather than leaving it to the caller.
    var onClick: (() -> Void)? = nil
    /// Called when the user taps "Renew" on a fully-exhausted credential.
    /// Only ever shown/invoked when `instances` is non-nil and every
    /// instance's `sigCount > 0`; ignored (no button rendered) if nil.
    var onRenewClick: (() -> Void)? = nil

    @Environment(\.colorScheme) private var colorScheme
    @State private var svgState: SvgLoadState = .notApplicable

    /// Nil when the caller doesn't have batch/usage data on hand (see
    /// `instances`'s doc comment) - only gates the greyed-out/Renew state
    /// when we actually know the count, never on the strength of an absence.
    private var unusedCount: Int? { instances?.filter { $0.sigCount == 0 }.count }
    private var isExhausted: Bool { unusedCount == 0 }

    var body: some View {
        let meta = credential.metadata
        let bgColor = meta?.backgroundColor.flatMap { Color(hex: $0) } ?? .accentColor
        let fgColor = meta?.textColor.flatMap { Color(hex: $0) } ?? .white

        Group {
            switch svgState {
            case .loaded(let svgText):
                SVGView(string: svgText)
                    .aspectRatio(1.6, contentMode: .fit)
                    .frame(maxWidth: .infinity)
                    .clipShape(RoundedRectangle(cornerRadius: 16))
            case .loading:
                RoundedRectangle(cornerRadius: 16)
                    .fill(bgColor)
                    .aspectRatio(1.6, contentMode: .fit)
                    .frame(maxWidth: .infinity)
                    .overlay { ProgressView().tint(fgColor) }
            case .notApplicable, .failed:
                flatCard(meta: meta, bgColor: bgColor, fgColor: fgColor)
            }
        }
        .overlay(alignment: .topTrailing) {
            if isExpired {
                Text("EXPIRED")
                    .font(.caption2.bold())
                    .foregroundColor(.white)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(
                        RoundedRectangle(cornerRadius: 4)
                            .fill(SirosTheme.error)
                    )
                    .padding(8)
            } else if let unusedCount {
                // Remaining-copies ribbon - mirrors wallet-frontend's
                // UsagesRibbon: count of batch copies not yet used in a
                // presentation (sigCount == 0), so it counts down as copies
                // get consumed rather than showing the fixed batch size.
                // Only shown when EXPIRED isn't (they'd otherwise collide in
                // the same corner) - matches this card's single top-trailing
                // badge slot.
                Text("\(unusedCount)")
                    .font(.caption2.bold())
                    .foregroundColor(unusedCount > 0 ? SirosTheme.onSurfaceVariant : .white)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(
                        Capsule()
                            .fill(unusedCount > 0 ? SirosTheme.surfaceVariant : SirosTheme.error)
                    )
                    .padding(8)
            }
        }
        .overlay {
            // Every batch instance already used - grey the whole card out
            // (it can no longer be presented, see
            // CredentialUtils.eligibleInstances) and offer Renew instead of
            // leaving it looking like a normal, selectable credential.
            if isExhausted {
                ZStack {
                    Color.black.opacity(0.55)
                    if let onRenewClick {
                        Button(action: onRenewClick) {
                            Text(L10n.string("credentials.renew"))
                                .font(.body.bold())
                                .foregroundColor(.white)
                        }
                    }
                }
                .clipShape(RoundedRectangle(cornerRadius: 16))
            }
        }
        .contentShape(Rectangle())
        .onTapGesture {
            guard !isExhausted else { return }
            onClick?()
        }
        .task(id: SvgLoadKey(credentialId: credential.id, isDark: colorScheme == .dark)) {
            await loadSvg(preferDark: colorScheme == .dark)
        }
    }

    @ViewBuilder
    private func flatCard(meta: CredentialMetadata?, bgColor: Color, fgColor: Color) -> some View {
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

    private var isExpired: Bool {
        // expiresAt is a JWT `exp` claim - always epoch seconds, not millis.
        guard let expiresAt = credential.expiresAt, expiresAt > 0 else { return false }
        return Date(timeIntervalSince1970: Double(expiresAt)) < Date()
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

    private func loadSvg(preferDark: Bool) async {
        guard let templates = credential.metadata?.svgTemplates, !templates.isEmpty else {
            svgState = .notApplicable
            return
        }
        svgState = .loading
        let preferredScheme = preferDark ? "dark" : "light"
        let template = templates.first(where: { $0.colorScheme == preferredScheme }) ?? templates[0]
        guard let url = URL(string: template.uri) else {
            svgState = .failed
            return
        }
        do {
            let (data, response) = try await URLSession.shared.data(from: url)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode),
                  let svgText = String(data: data, encoding: .utf8) else {
                svgState = .failed
                return
            }
            let claims = CredentialUtils.extractClaims(credential)
            svgState = .loaded(SvgTemplateRenderer.substitute(svgText, claims: claims))
        } catch {
            svgState = .failed
        }
    }
}

/// Loading state for a credential card's VCTM SVG template rendering.
private enum SvgLoadState: Equatable {
    /// This credential's metadata has no svg_templates - render the flat card immediately.
    case notApplicable
    /// Fetch/substitution in progress - show a spinner, not the flat card.
    case loading
    case loaded(String)
    /// Fetch or render failed - fall back to the flat card.
    case failed
}

private struct SvgLoadKey: Equatable {
    let credentialId: Int64
    let isDark: Bool
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

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI

/// The three slots of the bottom bar every main screen carries.
enum WalletNavItem {
    case home
    case scanQr
    case menu
}

/// The frame every signed-in screen sits in: the wallet header on top, the
/// screen's own content, and either the Home / Scan QR / Menu bar or a single
/// Back button underneath.
///
/// `onBack` non-nil selects the Back button - the design uses it for the
/// full-attention screens (the camera, the displayed QR code) where the
/// three-way bar would compete with the one thing the user is doing.
/// `brandHeader` paints the header in brand blue so Home's hero continues up
/// behind it.
struct WalletChrome<Content: View>: View {
    @EnvironmentObject var viewModel: WalletViewModel

    var selected: WalletNavItem?
    var brandHeader = false
    var onBack: (() -> Void)?
    @ViewBuilder var content: () -> Content

    var body: some View {
        VStack(spacing: 0) {
            WalletHeader(displayName: viewModel.displayName, onBrand: brandHeader) {
                viewModel.go(.settings)
            }
            content()
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            Group {
                if let onBack {
                    BackBar(onBack: onBack)
                } else {
                    WalletBottomBar(
                        selected: selected,
                        onHome: { viewModel.go(.home) },
                        onScanQr: { viewModel.scanQr() },
                        onMenu: { viewModel.openMenu() }
                    )
                }
            }
            // Reports the bar's real height (see `BottomBarHeightKey`) so
            // ContentView's message banner floats above it.
            .background(
                GeometryReader { proxy in
                    Color.clear.preference(key: BottomBarHeightKey.self, value: proxy.size.height)
                }
            )
        }
        .background(SirosTheme.screenBackground)
    }
}

/// Mark and product name on the left, the signed-in user's wallet on the right.
struct WalletHeader: View {
    let displayName: String?
    let onBrand: Bool
    let onAccount: () -> Void

    private var foreground: Color { onBrand ? .white : SirosTheme.ink }

    private var walletLabel: String {
        if let displayName, !displayName.isEmpty {
            return L10n.string("chrome.walletOf", displayName)
        }
        return L10n.string("chrome.myWallet")
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                SirosMarkView(size: 28)
                    .frame(width: 28, height: 28)
                    .overlay(Circle().stroke(onBrand ? Color.white : Color.clear, lineWidth: 1.5))
                Text(L10n.string("chrome.title"))
                    .font(.body.weight(.semibold))
                    .foregroundColor(foreground)
                    .lineLimit(1)
                Spacer(minLength: 12)
                Button(action: onAccount) {
                    HStack(spacing: 8) {
                        Image(systemName: "person.circle")
                            .font(.system(size: 22))
                        Text(walletLabel)
                            .font(.body)
                            .lineLimit(1)
                    }
                    .foregroundColor(foreground)
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("chrome-account")
            }
            .padding(.horizontal, SirosTheme.screenMargin)
            .padding(.vertical, 14)
            if !onBrand {
                Rectangle().fill(SirosTheme.hairline).frame(height: 1)
            }
        }
        .background((onBrand ? SirosTheme.brand : SirosTheme.screenBackground).ignoresSafeArea(edges: .top))
    }
}

/// Home, Scan QR (the raised black button) and Menu.
struct WalletBottomBar: View {
    let selected: WalletNavItem?
    let onHome: () -> Void
    let onScanQr: () -> Void
    let onMenu: () -> Void

    var body: some View {
        HStack(alignment: .bottom) {
            item(L10n.string("nav.home"), selected == .home, "nav-home", onHome) { tint in
                Image(systemName: "house")
                    .font(.system(size: 26))
                    .foregroundColor(tint)
            }
            Spacer()
            item(L10n.string("nav.scanQr"), selected == .scanQr, "nav-scan-qr", onScanQr) { _ in
                ZStack {
                    Circle().fill(SirosTheme.scanButton)
                    Image(systemName: "qrcode")
                        .font(.system(size: 22))
                        .foregroundColor(SirosTheme.onScanButton)
                }
                .frame(width: 48, height: 48)
            }
            Spacer()
            item(L10n.string("nav.menu"), selected == .menu, "nav-menu", onMenu) { tint in
                Image(systemName: "line.3.horizontal")
                    .font(.system(size: 26))
                    .foregroundColor(tint)
            }
        }
        .padding(.horizontal, 32)
        .padding(.top, 8)
        .padding(.bottom, 8)
        .background(SirosTheme.screenBackground)
    }

    private func item<Icon: View>(
        _ label: String,
        _ isSelected: Bool,
        _ identifier: String,
        _ action: @escaping () -> Void,
        @ViewBuilder icon: (Color) -> Icon
    ) -> some View {
        let tint = isSelected ? SirosTheme.ink : SirosTheme.secondaryText
        return Button(action: action) {
            VStack(spacing: 4) {
                icon(tint)
                    .frame(height: 48)
                Text(label)
                    .font(.subheadline.weight(.semibold))
                    .foregroundColor(tint)
            }
            .frame(minWidth: 88)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier(identifier)
    }
}

/// The single full-width Back button that replaces the bottom bar on
/// full-attention screens.
struct BackBar: View {
    let onBack: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            Rectangle().fill(SirosTheme.hairline).frame(height: 1)
            Button(action: onBack) {
                HStack(spacing: 10) {
                    Image(systemName: "arrow.left")
                    Text(L10n.string("nav.back"))
                        .font(.body.weight(.semibold))
                }
                .foregroundColor(SirosTheme.ink)
                .frame(maxWidth: .infinity, minHeight: 48)
                .background(
                    RoundedRectangle(cornerRadius: SirosTheme.cardCorner).fill(SirosTheme.altSurface)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: SirosTheme.cardCorner).stroke(SirosTheme.hairline, lineWidth: 1)
                )
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("chrome-back")
            .padding(.horizontal, 10)
            .padding(.vertical, 16)
        }
        .background(SirosTheme.screenBackground)
    }
}

/// A screen's heading with the rule under it. With `onBack` it becomes the
/// smaller "arrow + title" heading of a screen one step down from a main one.
struct ScreenTitle: View {
    let text: String
    var onBack: (() -> Void)?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 12) {
                if let onBack {
                    Button(action: onBack) {
                        Image(systemName: "arrow.left")
                            .font(.title3)
                            .foregroundColor(SirosTheme.ink)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(L10n.string("nav.back"))
                }
                Text(text)
                    .font(onBack == nil ? .largeTitle.weight(.medium) : .title2.weight(.medium))
                    .foregroundColor(SirosTheme.ink)
            }
            Rectangle().fill(SirosTheme.hairline).frame(height: 1)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// The design's bordered card: a hairline border on a white (or given) surface.
struct WalletCard: ViewModifier {
    var fill: Color = SirosTheme.screenBackground
    var padding: CGFloat = 16

    func body(content: Content) -> some View {
        content
            .padding(padding)
            .background(RoundedRectangle(cornerRadius: SirosTheme.cardCorner).fill(fill))
            .overlay(RoundedRectangle(cornerRadius: SirosTheme.cardCorner).stroke(SirosTheme.hairline, lineWidth: 1))
            .contentShape(RoundedRectangle(cornerRadius: SirosTheme.cardCorner))
    }
}

extension View {
    func walletCard(fill: Color = SirosTheme.screenBackground, padding: CGFloat = 16) -> some View {
        modifier(WalletCard(fill: fill, padding: padding))
    }
}

/// A square brand-blue tile holding a white icon - the lead of an action card.
struct BrandIconTile: View {
    let systemImage: String

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 4).fill(SirosTheme.brand)
            Image(systemName: systemImage)
                .font(.system(size: 28))
                .foregroundColor(.white)
        }
        .frame(width: 64, height: 64)
    }
}

/// A pale-blue tile holding a brand-blue icon - the lead of an informational row.
struct SoftIconTile: View {
    let systemImage: String
    var size: CGFloat = 44
    var circular = false

    var body: some View {
        ZStack {
            if circular {
                Circle().fill(SirosTheme.iconTile)
            } else {
                RoundedRectangle(cornerRadius: 4).fill(SirosTheme.iconTile)
            }
            Image(systemName: systemImage)
                .font(.system(size: size * 0.45))
                .foregroundColor(SirosTheme.iconTileContent)
        }
        .frame(width: size, height: size)
    }
}

/// An action card: title, one line of explanation, and a brand tile. The tile
/// leads and a chevron trails (`tileLeading`, Share In-Person), or the tile
/// trails on its own (Add Credentials).
struct ActionCard: View {
    let title: String
    let subtitle: String
    let systemImage: String
    var tileLeading = false
    var identifier: String?
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 14) {
                if tileLeading { BrandIconTile(systemImage: systemImage) }
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.body.weight(.medium))
                        .foregroundColor(SirosTheme.ink)
                    Text(subtitle)
                        .font(.body)
                        .foregroundColor(SirosTheme.secondaryText)
                        .multilineTextAlignment(.leading)
                }
                Spacer(minLength: 8)
                if tileLeading {
                    Image(systemName: "chevron.right")
                        .font(.title3)
                        .foregroundColor(SirosTheme.brandOnPage)
                } else {
                    BrandIconTile(systemImage: systemImage)
                }
            }
            .walletCard(padding: 14)
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier(identifier ?? "")
    }
}

/// The brand-blue panel of the full-attention screens: one focal element (a
/// camera view, a QR code), a rule, and one line of instruction.
struct BrandPanel<Focus: View>: View {
    let caption: String
    @ViewBuilder var focus: () -> Focus

    var body: some View {
        VStack(spacing: 24) {
            focus()
            Rectangle().fill(Color.white).frame(height: 1)
            Text(caption)
                .font(.body.weight(.medium))
                .foregroundColor(.white)
                .multilineTextAlignment(.center)
                .padding(.bottom, 8)
        }
        .padding(.horizontal, 40)
        .padding(.vertical, 28)
        .frame(maxWidth: .infinity)
        .background(RoundedRectangle(cornerRadius: 4).fill(SirosTheme.brand))
    }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI

/// What kind of transient message a `MessageBannerView` is showing - drives
/// both its color and how long it stays up before auto-dismissing.
enum BannerKind: Equatable {
    case info
    case error
}

/// A single transient banner message plus its auto-dismiss timing.
///
/// Replaces the blocking `.alert()` this app previously showed for
/// `WalletViewModel.errorMessage`/`infoMessage` - modal alerts required
/// tapping "OK" before the rest of the UI was usable again, with no
/// dismiss-without-blocking option. Mirrors the identical fix shipped in the
/// Kotlin sample app (siros-sdk-kotlin PR #106): a non-blocking snackbar with
/// an explicit dismiss action, `SnackbarDuration.Long` for errors, and a
/// shorter duration for transient info toasts.
///
/// `id` gives every distinct message its own identity so SwiftUI's
/// `.task(id:)` (used by `MessageBannerView` for auto-dismiss) restarts its
/// countdown whenever the message actually changes, rather than being fooled
/// by two structurally-equal-looking messages in a row.
struct BannerMessage: Identifiable, Equatable {
    let id = UUID()
    let kind: BannerKind
    let text: String

    /// How long this message stays up before auto-dismissing if the user
    /// doesn't tap the explicit dismiss (X) button first. Errors stay up
    /// noticeably longer than routine info toasts - mirrors the Kotlin
    /// reference's `SnackbarDuration.Long` (errors) vs default (info).
    var autoDismissDuration: TimeInterval {
        switch kind {
        case .info:
            return 4
        case .error:
            return 8
        }
    }

    static func == (lhs: BannerMessage, rhs: BannerMessage) -> Bool {
        lhs.id == rhs.id
    }
}

/// Reports the currently-visible bottom tab bar's height so a
/// `MessageBannerView` overlay can float above it instead of covering it -
/// mirrors the Kotlin sample app's `onGloballyPositioned` measurement (PR
/// #106). Zero whenever no tab bar is part of the current screen (every
/// screen except `MainTabView`'s Credentials/Settings tabs).
///
/// Unlike Compose's `DisposableEffect`, which needs an explicit reset
/// callback when the reporting composable leaves the tree, SwiftUI
/// recomputes a preference's aggregate value from whichever descendants are
/// actually present in each render pass - once `MainTabView`'s bottom bar is
/// no longer part of the hierarchy, `reduce` simply has no value to fold in
/// and `defaultValue` (0) applies again on its own.
struct BottomBarHeightKey: PreferenceKey {
    static var defaultValue: CGFloat = 0

    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) {
        value = max(value, nextValue())
    }
}

/// Non-blocking toast/banner view for a single `BannerMessage`. Floats above
/// the rest of the UI (via the caller's `.overlay(alignment: .bottom)`)
/// rather than presenting modally, so the screen underneath stays fully
/// interactive while it's visible - the entire point of replacing the old
/// blocking `.alert()`.
struct MessageBannerView: View {
    let message: BannerMessage
    let onDismiss: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: message.kind == .error ? "exclamationmark.triangle.fill" : "info.circle.fill")
                .foregroundColor(SirosTheme.onPrimary)
                .padding(.top, 1)

            Text(message.text)
                .font(.subheadline)
                .foregroundColor(SirosTheme.onPrimary)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)

            // Explicit dismiss - always available even before the
            // auto-dismiss timer below fires, and never required (the
            // banner clears itself either way).
            Button(action: onDismiss) {
                Image(systemName: "xmark")
                    .font(.caption.weight(.semibold))
                    .foregroundColor(SirosTheme.onPrimary.opacity(0.85))
                    .padding(6)
            }
            .accessibilityLabel(L10n.string("common.dismiss"))
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .background(
            RoundedRectangle(cornerRadius: 14)
                .fill(message.kind == .error ? SirosTheme.error : SirosTheme.brand)
        )
        .shadow(color: .black.opacity(0.25), radius: 10, y: 4)
        // Re-keyed on `message.id` so a new message (even one with identical
        // text/kind) restarts the countdown, and so SwiftUI cancels the
        // previous countdown automatically when the message changes or this
        // view is removed (banner dismissed) - no manual cancellation needed.
        .task(id: message.id) {
            let nanoseconds = UInt64(max(message.autoDismissDuration, 0) * 1_000_000_000)
            try? await Task.sleep(nanoseconds: nanoseconds)
            guard !Task.isCancelled else { return }
            onDismiss()
        }
    }
}

/// Overlays an optional `BannerMessage` above the receiver, floating just
/// above `bottomInset` (the measured bottom tab bar height, or 0 on screens
/// without one) rather than blocking any part of the underlying UI.
struct MessageBannerModifier: ViewModifier {
    let message: BannerMessage?
    let bottomInset: CGFloat
    let onDismiss: () -> Void

    func body(content: Content) -> some View {
        content
            .overlay(alignment: .bottom) {
                if let message {
                    MessageBannerView(message: message, onDismiss: onDismiss)
                        .padding(.horizontal, 16)
                        .padding(.bottom, bottomInset + 8)
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                }
            }
            .animation(.easeInOut(duration: 0.2), value: message)
    }
}

extension View {
    /// See `MessageBannerModifier`.
    func messageBanner(_ message: BannerMessage?, bottomInset: CGFloat = 0, onDismiss: @escaping () -> Void) -> some View {
        modifier(MessageBannerModifier(message: message, bottomInset: bottomInset, onDismiss: onDismiss))
    }
}

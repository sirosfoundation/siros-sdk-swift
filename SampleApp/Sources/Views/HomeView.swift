// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosCredentials

/// The wallet's landing screen: a brand-blue hero greeting the user, a banner
/// when credentials need attention, and the two things a wallet is for -
/// manage what you hold, and share it with someone in front of you. Scanning
/// a QR code is the centre button of the bottom bar on every screen, so it
/// has no tile here.
///
/// The banner counts the credentials that cannot currently be used (see
/// `CredentialWithInstances.needsAttention`) and opens Manage credentials on
/// that filter. A dismissible card leads to Add Credentials. A second card
/// offers the Photo ID scan directly when `viewModel.showPhotoIdOnboarding`
/// is on (a sample-app setting - see `WalletViewModel+PhotoIdOnboarding.swift`)
/// and the wallet doesn't already hold that credential.
struct HomeView: View {
    @EnvironmentObject var viewModel: WalletViewModel

    private var attentionCount: Int {
        CredentialUtils.groupForDisplay(
            credentials: viewModel.credentials,
            presentationHistory: viewModel.currentPresentationHistory
        )
        .filter { $0.needsAttention(statuses: viewModel.credentialStatuses) }
        .count
    }

    private var greeting: String {
        if let name = viewModel.displayName, !name.isEmpty {
            return L10n.string("home.welcomeBackName", name)
        }
        return L10n.string("home.welcomeBack")
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 0) {
                hero
                tiles
                prompts
            }
        }
        .background(SirosTheme.screenBackground)
    }

    private var hero: some View {
        let count = attentionCount
        return VStack(alignment: .leading, spacing: 28) {
            Text(greeting)
                .font(.title.weight(.medium))
                .foregroundColor(.white)
                .frame(maxWidth: .infinity, alignment: .leading)
            if count > 0 {
                Button(action: { viewModel.openManageCredentials(needsAttentionOnly: true) }) {
                    HStack(spacing: 12) {
                        Image(systemName: "exclamationmark.triangle")
                            .font(.system(size: 30))
                            .foregroundColor(SirosTheme.attention)
                        Text(count == 1 ? L10n.string("home.attentionOne") : L10n.string("home.attentionOther", count))
                            .font(.body.weight(.semibold))
                            .foregroundColor(SirosTheme.brandOnPage)
                            .multilineTextAlignment(.leading)
                        Spacer(minLength: 8)
                        Image(systemName: "chevron.right")
                            .font(.title3)
                            .foregroundColor(SirosTheme.brandOnPage)
                    }
                    .walletCard(padding: 14)
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("home-attention")
            }
        }
        .padding(.horizontal, SirosTheme.screenMargin)
        .padding(.vertical, 28)
        .background(SirosTheme.brand)
    }

    /// The hero ends halfway down the two tiles, which straddle its edge.
    private var tiles: some View {
        HStack(spacing: 32) {
            // "nav-tab-credentials" is the hook the credential-stack UI tests
            // use to reach the credential list from Home.
            tile("wallet.pass", L10n.string("home.manageCredentials"), "nav-tab-credentials") {
                viewModel.openManageCredentials(needsAttentionOnly: false)
            }
            tile("person.2", L10n.string("home.shareInPerson"), "home-share-in-person") {
                viewModel.go(.share)
            }
        }
        .padding(.horizontal, SirosTheme.screenMargin)
        .background(
            VStack(spacing: 0) {
                SirosTheme.brand
                Color.clear
            }
        )
    }

    private func tile(_ systemImage: String, _ label: String, _ identifier: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            VStack(spacing: 16) {
                Image(systemName: systemImage)
                    .font(.system(size: 52))
                    .foregroundColor(SirosTheme.brandOnPage)
                Text(label)
                    .font(.body.weight(.medium))
                    .foregroundColor(SirosTheme.ink)
                    .multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity, minHeight: 148)
            .walletCard()
        }
        .buttonStyle(.plain)
        .accessibilityIdentifier(identifier)
    }

    private var prompts: some View {
        VStack(spacing: 16) {
            if viewModel.showPhotoIdOnboarding && !viewModel.hasPhotoIdCredential() {
                HomePromptCard(
                    systemImage: "person.text.rectangle",
                    title: L10n.string("home.photoIdOnboardingTitle"),
                    text: L10n.string("home.photoIdOnboardingDescription"),
                    actionLabel: L10n.string("home.promptBegin"),
                    action: { viewModel.openIDVPreparation() },
                    onDismiss: nil
                )
            }
            if !viewModel.addCredentialsPromptDismissed {
                HomePromptCard(
                    systemImage: "plus.circle",
                    title: L10n.string("credentials.addTitle"),
                    text: L10n.string("home.addCredentialsText"),
                    actionLabel: L10n.string("home.promptGetStarted"),
                    action: { viewModel.openAddCredential() },
                    onDismiss: { viewModel.addCredentialsPromptDismissed = true }
                )
            }
        }
        .padding(.horizontal, SirosTheme.screenMargin)
        .padding(.vertical, 32)
    }
}

/// A prompt card: grey icon tile, a title, a sentence and an underlined
/// action; `onDismiss` adds the close cross.
private struct HomePromptCard: View {
    let systemImage: String
    let title: String
    let text: String
    let actionLabel: String
    let action: () -> Void
    let onDismiss: (() -> Void)?

    var body: some View {
        HStack(alignment: .top, spacing: 16) {
            Button(action: action) {
                HStack(alignment: .center, spacing: 16) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 4).fill(SirosTheme.promptTile)
                        Image(systemName: systemImage)
                            .font(.system(size: 30))
                            .foregroundColor(SirosTheme.brandOnPage)
                    }
                    .frame(width: 56, height: 56)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(title)
                            .font(.body.weight(.semibold))
                        Text(text)
                            .font(.subheadline)
                            .multilineTextAlignment(.leading)
                        Text(actionLabel)
                            .font(.subheadline.weight(.medium))
                            .underline()
                    }
                    .foregroundColor(SirosTheme.ink)
                    Spacer(minLength: 0)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            if let onDismiss {
                Button(action: onDismiss) {
                    Image(systemName: "xmark")
                        .font(.body.weight(.semibold))
                        .foregroundColor(SirosTheme.ink)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(L10n.string("common.dismiss"))
            }
        }
        .walletCard(padding: 12)
    }
}

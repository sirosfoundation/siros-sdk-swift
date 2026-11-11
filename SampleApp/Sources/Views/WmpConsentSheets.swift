// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosWallet

/// The WMP consent ask: the YES/NO on a matched presentation (the Kotlin
/// sample's `PresentationConsentDialog` twin). The verifier's resolved label
/// is the sentence's subject; the per-credential selections render grouped,
/// each credential's own claims under its title; the raw client_id rides the
/// details disclosure (never the title).
struct WmpConsentSheet: View {
    @EnvironmentObject var viewModel: WalletViewModel
    let ask: WalletViewModel.PendingConsentAsk
    @State private var showDetails = false

    var body: some View {
        VStack(spacing: 16) {
            Text("\(ask.verifierName ?? "The verifier") is asking you to share:")
                .font(.headline)
                .multilineTextAlignment(.center)

            if let verifierId = ask.verifierId, !verifierId.isEmpty {
                Button(showDetails ? "Hide details" : "Verifier details") {
                    showDetails.toggle()
                }
                .font(.caption)
                if showDetails {
                    Text(verifierId)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            }

            if ask.selections.isEmpty {
                // No match record: the flat claim list, de-duplicated.
                List {
                    ForEach(Array(Set(ask.requestedClaims)).sorted(), id: \.self) { claim in
                        Text(claim)
                    }
                }
            } else {
                List {
                    ForEach(ask.selections, id: \.credentialId) { selection in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(selection.credentialName ?? "Credential \(selection.credentialId)")
                                .font(.subheadline.weight(.semibold))
                            if let claims = selection.claims, !claims.isEmpty {
                                Text(claims.joined(separator: ", "))
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }

            HStack(spacing: 12) {
                Button("Decline") {
                    viewModel.answerConsentAsk(ask, agreed: false)
                }
                .buttonStyle(.bordered)
                Button("Share") {
                    viewModel.answerConsentAsk(ask, agreed: true)
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding()
        .interactiveDismissDisabled()
    }
}

/// A WMP credential-match ambiguity (issue #277): more than one credential
/// matched; the user picks (pre-selected: the wallet's first match) or
/// cancels - which REFUSES the presentation outright.
struct AmbiguitySheet: View {
    @EnvironmentObject var viewModel: WalletViewModel
    let ask: WalletViewModel.PendingAmbiguityAsk
    @State private var picked: WmpConsentSelection?

    var body: some View {
        VStack(spacing: 16) {
            Text("More than one credential matches")
                .font(.headline)
            Text("This request matches several of your credentials. Choose which to share.")
                .font(.subheadline)
                .multilineTextAlignment(.center)

            List {
                ForEach(ask.matches, id: \.credentialId) { match in
                    Button {
                        picked = match
                    } label: {
                        HStack {
                            Image(systemName: picked?.credentialId == match.credentialId ? "checkmark.circle.fill" : "circle")
                                .foregroundStyle(Color.accentColor)
                            // The credential's title alone: the matched claim
                            // is machine text that belongs in the consent
                            // sheet that follows, worded.
                            Text(match.credentialName ?? "Credential \(match.credentialId)")
                                .font(.body)
                            Spacer()
                        }
                    }
                }
            }

            HStack(spacing: 12) {
                Button("Cancel") {
                    viewModel.chooseAmbiguityMatch(ask, pick: nil)
                }
                .buttonStyle(.bordered)
                Button("Choose") {
                    viewModel.chooseAmbiguityMatch(ask, pick: picked)
                }
                .buttonStyle(.borderedProminent)
                .disabled(picked == nil)
            }
        }
        .padding()
        .interactiveDismissDisabled()
        .onAppear {
            // Pre-selected: the wallet's first match (its default answer).
            picked = ask.matches.first
        }
    }
}
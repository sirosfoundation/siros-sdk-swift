// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosWallet
import SirosCredentials

/// Presentation consent screen — shows the verifier's request and
/// lets the user approve or decline sharing credentials.
struct PresentationConsentView: View {
    @EnvironmentObject var viewModel: WalletViewModel

    var body: some View {
        guard let request = viewModel.pendingPresentation else {
            return AnyView(EmptyView())
        }

        return AnyView(
            VStack(spacing: 16) {
                // Header
                HStack(spacing: 12) {
                    Image(systemName: "checkmark.shield.fill")
                        .font(.system(size: 32))
                        .foregroundStyle(.accent)
                    VStack(alignment: .leading) {
                        Text("Credential Request")
                            .font(.title2.bold())
                        if let verifier = request.verifierName {
                            Text(verifier)
                                .font(.subheadline)
                                .foregroundStyle(.secondary)
                        }
                    }
                    Spacer()
                }
                .padding(.horizontal)

                Text(requestDescription(request))
                    .font(.body)
                    .padding(.horizontal)

                // Credential cards
                ScrollView {
                    VStack(spacing: 8) {
                        ForEach(request.candidates, id: \.id) { credential in
                            HStack(spacing: 12) {
                                let bgColor = credential.metadata?.backgroundColor
                                    .flatMap { Color(hex: $0) } ?? .accentColor
                                Circle()
                                    .fill(bgColor)
                                    .frame(width: 36, height: 36)
                                    .overlay(
                                        Text((credential.metadata?.name ?? "?").prefix(1).uppercased())
                                            .font(.caption.bold())
                                            .foregroundStyle(.white)
                                    )
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(credential.metadata?.name ?? credential.format)
                                        .font(.body.weight(.medium))
                                    if let issuer = credential.metadata?.issuer?.name {
                                        Text(issuer)
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                    }
                                }
                                Spacer()
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundStyle(.green)
                            }
                            .padding(12)
                            .background(
                                RoundedRectangle(cornerRadius: 12)
                                    .fill(.regularMaterial)
                            )
                        }
                    }
                    .padding(.horizontal)
                }

                // Requested claims
                if !request.requestedClaims.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Requested information:")
                            .font(.caption.bold())
                            .foregroundStyle(.secondary)
                        ForEach(request.requestedClaims.flatMap { $0 }, id: \.self) { claim in
                            Label(claim, systemImage: "info.circle")
                                .font(.caption)
                        }
                    }
                    .padding(.horizontal)
                }

                Spacer()

                // Action buttons
                VStack(spacing: 8) {
                    Button(action: {
                        let ids = request.candidates.map(\.id)
                        viewModel.acceptPresentation(ids)
                    }) {
                        Text("Share")
                            .frame(maxWidth: .infinity)
                            .frame(height: 44)
                    }
                    .buttonStyle(.borderedProminent)

                    Button(action: { viewModel.declinePresentation() }) {
                        Text("Decline")
                            .frame(maxWidth: .infinity)
                            .frame(height: 44)
                    }
                    .buttonStyle(.bordered)
                    .tint(.red)
                }
                .padding(.horizontal)
                .padding(.bottom)
            }
            .padding(.top, 24)
        )
    }

    private func requestDescription(_ request: PresentationRequest) -> String {
        if let verifier = request.verifierName {
            return "\(verifier) is requesting the following credentials:"
        }
        return "A verifier is requesting the following credentials:"
    }
}

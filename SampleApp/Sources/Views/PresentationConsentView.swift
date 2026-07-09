// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosWallet
import SirosCredentials

/// Multi-step presentation consent screen with selective disclosure.
///
/// Steps:
/// 1. Preview: verifier info and overview of what's requested
/// 2. Per-credential: select which claims to disclose
/// 3. Summary: confirm final selection before sharing
struct PresentationConsentView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @State private var currentStep = 0
    @State private var claimSelections: [String: Bool] = [:]

    var body: some View {
        guard let request = viewModel.pendingPresentation else {
            return AnyView(EmptyView())
        }

        let totalSteps = request.candidates.count + 2 // preview + per-cred + summary

        return AnyView(
            VStack(spacing: 16) {
                // Step progress bar
                StepProgressBar(currentStep: currentStep, totalSteps: totalSteps)
                    .padding(.horizontal)

                // Content
                Group {
                    if currentStep == 0 {
                        previewStep(request)
                    } else if currentStep <= request.candidates.count {
                        let cred = request.candidates[currentStep - 1]
                        claimSelectionStep(credential: cred, requestedClaims: request.requestedClaims)
                    } else {
                        summaryStep(request)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)

                // Navigation buttons
                HStack(spacing: 12) {
                    if currentStep == 0 {
                        Button(action: { viewModel.declinePresentation() }) {
                            HStack {
                                Image(systemName: "xmark")
                                Text("Decline")
                            }
                            .frame(maxWidth: .infinity)
                            .frame(height: 48)
                        }
                        .buttonStyle(.bordered)
                        .tint(.red)
                    } else {
                        Button(action: { currentStep -= 1 }) {
                            Text("Back")
                                .frame(maxWidth: .infinity)
                                .frame(height: 48)
                        }
                        .buttonStyle(.bordered)
                    }

                    if currentStep < totalSteps - 1 {
                        Button(action: { currentStep += 1 }) {
                            Text("Next")
                                .frame(maxWidth: .infinity)
                                .frame(height: 48)
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(SirosTheme.brand)
                    } else {
                        Button(action: {
                            let ids = request.candidates.map(\.id)
                            viewModel.acceptPresentation(ids)
                        }) {
                            HStack {
                                Image(systemName: "checkmark")
                                Text("Share")
                            }
                            .frame(maxWidth: .infinity)
                            .frame(height: 48)
                        }
                        .buttonStyle(.borderedProminent)
                        .tint(SirosTheme.brand)
                    }
                }
                .padding(.horizontal)
                .padding(.bottom)
            }
            .padding(.top, 16)
            .onAppear { initializeSelections(request) }
        )
    }

    // MARK: - Step 1: Preview

    @ViewBuilder
    private func previewStep(_ request: PresentationRequest) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 12) {
                    Image(systemName: "info.circle.fill")
                        .font(.system(size: 28))
                        .foregroundColor(SirosTheme.brand)
                    VStack(alignment: .leading) {
                        Text("Credential Request")
                            .font(.title2.bold())
                        if let verifier = request.verifierName {
                            Text(verifier)
                                .font(.subheadline)
                                .foregroundColor(SirosTheme.onSurfaceVariant)
                        }
                    }
                }

                let verifier = request.verifierName ?? "A verifier"
                Text("\(verifier) is requesting the following credentials:")
                    .font(.body)

                ForEach(request.candidates, id: \.id) { cred in
                    credentialCard(cred, claimCount: request.requestedClaims.flatMap { $0 }.count)
                }
            }
            .padding(.horizontal)
        }
    }

    // MARK: - Step 2: Per-Credential Claim Selection

    @ViewBuilder
    private func claimSelectionStep(credential: StoredCredential, requestedClaims: [[String]]) -> some View {
        let claimMetaMap = Dictionary(
            uniqueKeysWithValues: (credential.metadata?.claims ?? []).map { ($0.path.joined(separator: "."), $0) }
        )
        let claims = requestedClaims.flatMap { $0 }.uniqued()

        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                credentialRow(credential)

                Spacer().frame(height: 8)

                Text("Select which data to share:")
                    .font(.subheadline)
                    .fontWeight(.semibold)

                ForEach(claims, id: \.self) { claim in
                    let meta = claimMetaMap[claim]
                    let isRequired = meta?.mandatory == true || meta?.sd == "always"
                    let key = "\(credential.id):\(claim)"
                    let isOn = claimSelections[key] ?? true

                    HStack(spacing: 8) {
                        Toggle("", isOn: Binding(
                            get: { isOn },
                            set: { newValue in
                                if !isRequired {
                                    claimSelections[key] = newValue
                                }
                            }
                        ))
                        .toggleStyle(.switch)
                        .labelsHidden()
                        .disabled(isRequired)

                        VStack(alignment: .leading, spacing: 1) {
                            Text(meta?.label ?? formatClaimName(claim))
                                .font(.body)
                                .fontWeight(.medium)
                            if isRequired {
                                Text("Required")
                                    .font(.caption)
                                    .foregroundColor(SirosTheme.onSurfaceVariant)
                            } else if let desc = meta?.description {
                                Text(desc)
                                    .font(.caption)
                                    .foregroundColor(SirosTheme.onSurfaceVariant)
                            }
                        }

                        Spacer()
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(
                        RoundedRectangle(cornerRadius: 8)
                            .fill(isOn ? SirosTheme.surfaceVariant : SirosTheme.surface)
                    )
                }
            }
            .padding(.horizontal)
        }
    }

    // MARK: - Step 3: Summary

    @ViewBuilder
    private func summaryStep(_ request: PresentationRequest) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Image(systemName: "checkmark.circle.fill")
                    .font(.system(size: 28))
                    .foregroundColor(SirosTheme.brand)

                Text("Ready to share")
                    .font(.title2.bold())

                let verifier = request.verifierName ?? "the verifier"
                Text("You will share the following with \(verifier):")
                    .font(.body)
                    .foregroundColor(SirosTheme.onSurfaceVariant)

                ForEach(request.candidates, id: \.id) { cred in
                    let claimMetaMap = Dictionary(
                        uniqueKeysWithValues: (cred.metadata?.claims ?? []).map { ($0.path.joined(separator: "."), $0) }
                    )
                    let disclosedClaims = request.requestedClaims.flatMap { $0 }.uniqued()
                        .filter { claimSelections["\(cred.id):\($0)"] ?? true }

                    VStack(alignment: .leading, spacing: 4) {
                        credentialRow(cred)
                        Divider().padding(.vertical, 4)
                        ForEach(disclosedClaims, id: \.self) { claim in
                            let meta = claimMetaMap[claim]
                            Text("✓ \(meta?.label ?? formatClaimName(claim))")
                                .font(.caption)
                                .foregroundColor(SirosTheme.onSurfaceVariant)
                        }
                    }
                    .padding(12)
                    .background(
                        RoundedRectangle(cornerRadius: 12)
                            .fill(SirosTheme.surfaceVariant)
                    )
                }
            }
            .padding(.horizontal)
        }
    }

    // MARK: - Helpers

    private func initializeSelections(_ request: PresentationRequest) {
        for cred in request.candidates {
            let claimMetaMap = Dictionary(
                uniqueKeysWithValues: (cred.metadata?.claims ?? []).map { ($0.path.joined(separator: "."), $0) }
            )
            for claim in request.requestedClaims.flatMap({ $0 }) {
                let meta = claimMetaMap[claim]
                let key = "\(cred.id):\(claim)"
                let isRequired = meta?.mandatory == true || meta?.sd == "always"
                claimSelections[key] = isRequired || meta?.sd != "never"
            }
        }
    }

    @ViewBuilder
    private func credentialCard(_ cred: StoredCredential, claimCount: Int) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            credentialRow(cred)
            Text("\(claimCount) data fields requested")
                .font(.caption)
                .foregroundColor(SirosTheme.onSurfaceVariant)
                .padding(.top, 4)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(SirosTheme.surfaceVariant)
        )
    }

    @ViewBuilder
    private func credentialRow(_ credential: StoredCredential) -> some View {
        HStack(spacing: 12) {
            Circle()
                .fill(SirosTheme.brand)
                .frame(width: 36, height: 36)
                .overlay(
                    Text((credential.metadata?.name ?? "?").prefix(1).uppercased())
                        .font(.caption.bold())
                        .foregroundColor(.white)
                )
            VStack(alignment: .leading, spacing: 2) {
                Text(credential.metadata?.name ?? credential.format)
                    .font(.body.weight(.medium))
                if let issuer = credential.metadata?.issuer?.name {
                    Text(issuer)
                        .font(.caption)
                        .foregroundColor(SirosTheme.onSurfaceVariant)
                }
            }
        }
    }

    private func formatClaimName(_ claim: String) -> String {
        claim.split(separator: ".").flatMap { $0.split(separator: "_") }
            .map { $0.prefix(1).uppercased() + $0.dropFirst() }
            .joined(separator: " ")
    }
}

// MARK: - Step Progress Bar

struct StepProgressBar: View {
    let currentStep: Int
    let totalSteps: Int

    var body: some View {
        HStack(spacing: 4) {
            ForEach(0..<totalSteps, id: \.self) { step in
                RoundedRectangle(cornerRadius: 2)
                    .fill(step <= currentStep ? SirosTheme.brand : SirosTheme.border)
                    .frame(height: 4)
            }
        }
    }
}

// MARK: - Array extension for unique elements

private extension Array where Element: Hashable {
    func uniqued() -> [Element] {
        var seen = Set<Element>()
        return filter { seen.insert($0).inserted }
    }
}

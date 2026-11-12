//
//  WalletViewModel+PresentationFlow.swift
//  SirosIDWalletSample
//
//  The WMP consent ask and the presentation flow it answers - split out of
//  WalletViewModel.swift (which the consent surface had grown past
//  SwiftLint's file_length limit). The ask state itself (@Published) stays
//  in the view model; everything that DRIVES it lives here: the details
//  bridge, the sheet's answers, the accept/decline paths, the history, and
//  the WalletEventListener callbacks that raise the asks.
//
import CryptoKit
import Foundation
import SwiftUI
import SirosWallet
import SirosTransport
import SirosCredentials
import SirosAuth
import SirosKeystore

extension WalletViewModel {
    struct ConsentAskDetail {
        let verifierName: String?
        let verifierId: String?
        let selections: [WmpConsentSelection]
    }

    /// "Show me details" on the minimal WMP consent sheet: swap it for the
    /// pre-rework full in-wallet consent view (PresentationConsentView),
    /// landing on the claim-selection step; its Share/Cancel answer the
    /// same gate ask the sheet would have.
    func showConsentDetails(_ ask: PendingConsentAsk) {
        consentAskBridge = .consent(ask)
        pendingConsentAsk = nil
        pendingPresentation = presentationRequest(from: consentAskDetail, or: nil)
    }

    /// "Show me details" on the ambiguity sheet: the same full view at the
    /// selection step - the choice of credential IS the point. Share answers
    /// the AMBIGUITY ask with the picked credential; Cancel refuses.
    func showAmbiguityDetails(_ ask: PendingAmbiguityAsk) {
        consentAskBridge = .ambiguity(ask)
        pendingAmbiguity = nil
        pendingPresentation = presentationRequest(from: consentAskDetail, or: ask.matches)
    }

    /// Back from the full consent view to the sheet it bridged from.
    func hideConsentDetails() {
        guard let bridge = consentAskBridge else { return }
        consentAskBridge = nil
        pendingPresentation = nil
        switch bridge {
        case .consent(let ask): pendingConsentAsk = ask
        case .ambiguity(let ask): pendingAmbiguity = ask
        }
    }

    /// Where the full consent view lands when bridged (the selection step).
    var consentViewStartStep: Int { consentAskBridge == nil ? 0 : 1 }

    /// The wallet-level PresentationRequest for the bridged ask's selections.
    private func presentationRequest(from detail: ConsentAskDetail?, or matches: [WmpConsentSelection]?) -> PresentationRequest {
        let selections = (detail?.selections.isEmpty == false ? detail!.selections : matches) ?? []
        var creds: [StoredCredential] = []
        if case .ready(_, _, let ready, _) = walletState { creds = ready }
        return PresentationRequest(
            verifierName: detail?.verifierName ?? detail?.verifierId,
            candidates: selections.compactMap { sel in creds.first { $0.id == sel.credentialId } },
            requestedClaims: selections.map { $0.claims ?? [] }
        )
    }

    /// A WMP consent ask awaiting the user's YES/NO. Identity-carrying for
    /// `.sheet(item:)`.
    struct PendingConsentAsk: Identifiable {
        let id = UUID()
        /// The trust evaluation's label (client_name → domain → client_id).
        let verifierName: String?
        /// The raw client_id (the details view's subject).
        let verifierId: String?
        /// The per-credential selections this ask covers.
        let selections: [WmpConsentSelection]
        /// The claim names, flat (the fallback rendering).
        let requestedClaims: [String]
        /// The answer channel.
        let answer: CheckedContinuation<Bool, Never>
    }

    /// A credential-match ambiguity awaiting the user's ruling.
    struct PendingAmbiguityAsk: Identifiable {
        let id = UUID()
        /// The matched credentials to pick among.
        let matches: [WmpConsentSelection]
        /// The answer channel.
        let answer: CheckedContinuation<WmpCredentialAmbiguity, Never>
    }

    // MARK: - Presentation

    func acceptPresentation(_ selectedIds: [Int64]) {
        // The full consent view bridged from a WMP ask: its Share answers
        // THAT ask (consent: agree; ambiguity: the picked credential as
        // UserChoice).
        if let bridge = consentAskBridge {
            consentAskBridge = nil
            pendingPresentation = nil
            switch bridge {
            case .consent(let ask): ask.answer.resume(returning: true)
            case .ambiguity(let ask):
                ask.answer.resume(returning: .userChoice(ask.matches.filter { selectedIds.contains($0.credentialId) }))
            }
            return
        }
        pendingPresentation = nil
        presentationContinuation?.resume(returning: selectedIds)
        presentationContinuation = nil
    }

    func declinePresentation() {
        // The bridge counterpart: decline the consent ask, or refuse the
        // presentation outright (ambiguity).
        if let bridge = consentAskBridge {
            consentAskBridge = nil
            pendingPresentation = nil
            switch bridge {
            case .consent(let ask): ask.answer.resume(returning: false)
            case .ambiguity(let ask): ask.answer.resume(returning: .declined)
            }
            return
        }
        pendingPresentation = nil
        presentationContinuation?.resume(returning: [])
        presentationContinuation = nil
    }

    // MARK: - WMP consent & ambiguity

    /// The user's YES on a WMP consent ask.
    func answerConsentAsk(_ ask: PendingConsentAsk, agreed: Bool) {
        guard pendingConsentAsk?.id == ask.id else { return }
        pendingConsentAsk = nil
        ask.answer.resume(returning: agreed)
    }

    /// The user's ruling on a credential-match ambiguity: these picks.
    func chooseAmbiguityMatch(_ ask: PendingAmbiguityAsk, pick: WmpConsentSelection?) {
        guard pendingAmbiguity?.id == ask.id else { return }
        pendingAmbiguity = nil
        ask.answer.resume(returning: pick.map { .userChoice([$0]) } ?? .declined)
    }

    // MARK: - History

    func openHistory() {
        showHistory = true
        presentationHistory = wallet?.presentationHistory ?? []
    }

    func closeHistory() {
        showHistory = false
    }
}

extension WalletViewModel {
    /// The WMP consent ask: the YES/NO on a matched presentation. Routed
    /// through `pendingConsentAsk` (`WmpConsentSheet`), the verifier's
    /// resolved label as the subject and the per-credential selections
    /// grouped. The SDK's default DECLINES (fail closed) - without this
    /// override every WMP presentation in enforce mode is auto-declined
    /// (the Kotlin #395 twin, found in the 2026-11-11 audit round).
    nonisolated func onConsentRequested(
        flowId: String,
        purpose: String?,
        requestedClaims: [String],
        verifierName: String?,
        verifierId: String?,
        selections: [WmpConsentSelection]
    ) async -> Bool {
        await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
            Task { @MainActor in
                if self.pendingConsentAsk != nil {
                    // A second ask while one is up: the first is cancelled
                    // (its flow ended) - answer it declined, take this one.
                    self.pendingConsentAsk?.answer.resume(returning: false)
                }
                self.pendingConsentAsk = PendingConsentAsk(
                    verifierName: verifierName ?? purpose,
                    verifierId: verifierId,
                    selections: selections,
                    requestedClaims: requestedClaims,
                    answer: continuation
                )
                self.consentAskDetail = ConsentAskDetail(
                    verifierName: verifierName ?? purpose,
                    verifierId: verifierId,
                    selections: selections
                )
            }
        }
    }

    /// The multi-match ruling (issue #277): Choose the picked match, or
    /// Cancel - which REFUSES the presentation outright, never a silent
    /// fallback to the wallet's first pick.
    nonisolated func onCredentialAmbiguity(flowId: String, matches: [WmpConsentSelection]) -> WmpCredentialAmbiguity {
        await withCheckedContinuation { (continuation: CheckedContinuation<WmpCredentialAmbiguity, Never>) in
            Task { @MainActor in
                if self.pendingAmbiguity != nil {
                    self.pendingAmbiguity?.answer.resume(returning: .declined)
                }
                self.pendingAmbiguity = PendingAmbiguityAsk(matches: matches, answer: continuation)
            }
        }
    }

    nonisolated func onFlowComplete(flowId: String, redirectUri: String?, matchedNothing: Bool) {
        Task { @MainActor in
            // Any pending ask belonged to a flow that just ended: decline it.
            self.pendingConsentAsk?.answer.resume(returning: false)
            self.pendingConsentAsk = nil
            self.pendingAmbiguity?.answer.resume(returning: .declined)
            self.pendingAmbiguity = nil
            if matchedNothing {
                // The engine's no-match refusal: the verifier sees "wallet
                // declined the request"; the wallet says what happened (and
                // the redirect link below, when the error answer built one).
                self.infoMessage = L10n.string("flow.noMatchingCredential")
                self.showInfo = true
            } else if self.receivedCredentialCount > 0 {
                self.infoMessage = L10n.string("flow.credentialsReceived", self.receivedCredentialCount)
                self.showInfo = true
                self.receivedCredentialCount = 0
            } else if self.lastFlowType == "presentation" {
                // Presentation has no analogous per-item count, so a plain
                // confirmation is the equivalent "something happened" signal
                // for a flow whose whole point is watching this screen after
                // a QR scan.
                self.infoMessage = L10n.string("flow.presentationSent")
                self.showInfo = true
            }

            // Some verifiers (e.g. verifier.multipaz.org) return a
            // redirect_uri with their direct_post.jwt response so the
            // user's browser can be sent back to the verifier's own result
            // page. Without this, the flow just silently ends on the
            // wallet side with no way back to the verifier.
            self.openVerifierRedirect(redirectUri)
        }
    }
}

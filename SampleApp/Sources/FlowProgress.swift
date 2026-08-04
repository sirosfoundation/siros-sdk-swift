// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Localized display support for go-wallet-backend's FlowStep token
/// vocabulary (see internal/engine/messages.go) - shared by both the legacy
/// engine protocol and the newer WMP/JSON-RPC protocol.
///
/// Ordinal position lists below drive the flow progress bar's fraction. They
/// declare each step's canonical position, not its guaranteed real-world
/// order - a step can be skipped (e.g. no tx_code required) or, rarely,
/// arrive out of order relative to this list. Callers should combine the
/// fraction from `flowStepProgress` with a monotonic max guard so the bar
/// never visibly jumps backward.

private let issuanceSteps = [
    "parsing_offer",
    "offer_parsed",
    "fetching_metadata",
    "metadata_fetched",
    "evaluating_trust",
    "trust_evaluated",
    "awaiting_selection",
    "authorization_required",
    "exchanging_token",
    "token_obtained",
    "requesting_credential",
    "deferred",
]

private let presentationSteps = [
    "parsing_request",
    "request_parsed",
    "evaluating_verifier_trust",
    "match_credentials",
    "awaiting_consent",
    "credential_selection",
    "submitting_response",
]

private let stepLabelKeys: [String: String] = [
    "parsing_offer": "flow.steps.parsingOffer",
    "offer_parsed": "flow.steps.offerParsed",
    "fetching_metadata": "flow.steps.fetchingMetadata",
    "metadata_fetched": "flow.steps.metadataFetched",
    "evaluating_trust": "flow.steps.evaluatingTrust",
    "trust_evaluated": "flow.steps.trustEvaluated",
    "awaiting_selection": "flow.steps.awaitingSelection",
    "authorization_required": "flow.steps.authorizationRequired",
    "exchanging_token": "flow.steps.exchangingToken",
    "token_obtained": "flow.steps.tokenObtained",
    "requesting_credential": "flow.steps.requestingCredential",
    "deferred": "flow.steps.deferred",
    "parsing_request": "flow.steps.parsingRequest",
    "request_parsed": "flow.steps.requestParsed",
    "evaluating_verifier_trust": "flow.steps.evaluatingVerifierTrust",
    "match_credentials": "flow.steps.matchCredentials",
    "awaiting_consent": "flow.steps.awaitingConsent",
    "credential_selection": "flow.steps.credentialSelection",
    "submitting_response": "flow.steps.submittingResponse",
]

/// Localized label for a raw FlowStep token, falling back to a generic
/// "Processing…" for unrecognized tokens.
func flowStepLabel(_ step: String) -> String {
    L10n.string(stepLabelKeys[step] ?? "flow.steps.unknown")
}

/// Progress fraction (0...1) for a step within a flow type, or nil if the
/// flow type or step isn't recognized (caller should fall back to an
/// indeterminate indicator in that case).
func flowStepProgress(flowType: String, step: String) -> Double? {
    let steps: [String]
    switch flowType {
    case "issuance": steps = issuanceSteps
    case "presentation": steps = presentationSteps
    default: return nil
    }
    guard let index = steps.firstIndex(of: step) else { return nil }
    // +1 so the first step already shows some progress rather than an empty bar.
    return Double(index + 1) / Double(steps.count)
}

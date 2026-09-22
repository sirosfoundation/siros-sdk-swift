// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosCredentials

/// Fraction of a `CredentialCardView`'s own height left visible above the
/// card placed after it in `CredentialStack`. Card `i` sits at
/// `y = i * peek`, so every card but the frontmost is covered from that
/// point down by the one in front of it - a smaller fraction shows more of
/// the stack at once but less of each individual card's face. Mirrors the
/// Kotlin sample app's `CREDENTIAL_PEEK_FRACTION` (`CredentialCard.kt`)
/// exactly - 0.32 is enough to read a flat (no-template) card's name/issuer
/// row, which sits near the top of `CredentialCardView`'s layout, without
/// needing its SVG template rendered at all.
let credentialPeekFraction: CGFloat = 0.32

/// How far (as a fraction of a card's own height) a drag has to travel
/// before `CredentialStack` treats it as "pull this card out" rather than a
/// gesture that snaps back to where the card already was. Mirrors the
/// Kotlin sample app's `CREDENTIAL_PULL_THRESHOLD_FRACTION` - deliberately
/// smaller than the peek itself, so a short, easy drag is enough to bring a
/// buried card forward.
let credentialPullThresholdFraction: CGFloat = 0.18

/// How long a touch must be held, with negligible movement, before it
/// resolves to a long-press rather than a tap - matches
/// `UILongPressGestureRecognizer`'s platform default (0.5s), which the
/// system `.contextMenu` this replaces was already implicitly using, and is
/// close to Android's `ViewConfiguration.getLongPressTimeout()` (500ms) that
/// the Kotlin implementation this ports reads via
/// `viewConfiguration.longPressTimeoutMillis`.
let credentialLongPressDuration: TimeInterval = 0.5

/// Movement (in points), accumulated from touch-down, past which a touch is
/// read as a drag rather than a tap/long-press candidate. SwiftUI has no
/// public equivalent to Compose's `ViewConfiguration.touchSlop`; this picks
/// a comparable value (iOS's own gesture recognizers commonly use ~10pt).
let credentialTouchSlop: CGFloat = 10

/// The accessibility identifier of a stacked card, keyed on its batch id -
/// lets both the manual on-device verification and
/// `CredentialStackInteractionUITests` address one card in `CredentialStack`
/// without depending on its current position, which is the whole point of a
/// deck the user can reorder. Mirrors the Kotlin sample app's
/// `credentialStackCardTestTag`.
func credentialStackCardTestTag(_ batchId: Int64) -> String {
    "credential-stack-card-\(batchId)"
}

/// A deck of `CredentialCardView`s, each overlapping the one placed before
/// it rather than laid out full-height one after another - a wallet's whole
/// point is holding more credentials than fit on a screen shown one at a
/// time, and a plain scrolling list of full cards asks for exactly that much
/// scrolling to see what else is there. Port of the Kotlin sample app's
/// `CredentialStack` (`CredentialCard.kt`) - see its doc comment for the
/// full design rationale.
///
/// The stack is a real deck, not a static illustration of one: tapping a
/// card that isn't already at the front brings it forward (repeated taps
/// cycle through the whole stack), and dragging a card any real distance
/// pulls it the rest of the way out and drops it at the front, or lets go
/// and it settles back where it was if the drag didn't go far enough to
/// mean it. Full detail only opens for the card that's *already* frontmost.
///
/// Order is kept as this view's own state, keyed on each credential's
/// `batchId` so a card's position survives a recomposition triggered by
/// something unrelated changing (e.g. SVG hydration finishing) - a
/// credential added or removed while the stack is on screen reconciles the
/// deck (survivors keep their position, a new one joins at the front)
/// without resetting anyone else's position in it.
///
/// ONE gesture recognizer, attached to the whole deck (not one per card) -
/// see `handleChanged`/`hitTestCard`'s doc comments for why. `CredentialCardView`
/// is given `onClick: nil` here since every touch is resolved by this single
/// recognizer instead.
struct CredentialStack: View {
    let entries: [CredentialWithInstances]
    let onCredentialClick: (StoredCredential) -> Void
    let onCredentialLongClick: (StoredCredential) -> Void
    let onRenewCredential: (StoredCredential) -> Void

    private enum GesturePhase {
        case idle
        /// Down, not yet moved past slop or held past the long-press
        /// deadline - could still resolve to any of the three.
        case pending
        case dragging
        /// Fired; nothing further happens for the rest of this touch (in
        /// particular, the eventual release must not also read as a tap).
        case longPressed
    }

    /// Front-to-back order of batch ids; the LAST id is frontmost (fully
    /// visible, nothing placed after it to cover it).
    @State private var order: [Int64] = []
    /// Which card (if any) the CURRENT single gesture concerns - resolved
    /// once, via `hitTestCard`, at touch-down, and unchanged for the rest of
    /// that gesture even if the finger later drifts over where another card
    /// happens to be drawn (matches ordinary touch tracking: once a
    /// recognizer claims a touch, subsequent moves stay owned by it).
    @State private var activeId: Int64?
    /// Live drag translation for `activeId`'s card. Reset to 0 instantly
    /// (not animated) on release - that card's resting slot is a pure
    /// function of its index in `order`, so removing the live offset alone
    /// already reveals it sitting at rest; an actual reorder's spring comes
    /// from `bringToFront`'s `withAnimation`, not from animating this back
    /// to zero.
    @State private var dragOffset: CGFloat = 0
    @State private var isDragging = false
    @State private var gesturePhase: GesturePhase = .idle
    @State private var longPressTask: Task<Void, Never>?

    private var byId: [Int64: CredentialWithInstances] {
        Dictionary(uniqueKeysWithValues: entries.map { ($0.credential.batchId, $0) })
    }

    var body: some View {
        // A `GeometryReader` (rather than measuring width via a
        // `.background`/`PreferenceKey` pair) both supplies the width each
        // card's fixed 1.6:1 aspect ratio is derived from AND, given an
        // EXPLICIT `.frame(width:)` on the `ZStack` below, forces that same
        // width down through the `ScrollView`/`ZStack` chain - a plain
        // `.frame(maxWidth: .infinity)` on each card (what `CredentialCardView`
        // uses) only expands to fill a width some ancestor actually
        // proposes, and a `ScrollView`'s content is not guaranteed to be
        // proposed one; confirmed necessary after a first version (measuring
        // width via a background `GeometryReader` + `PreferenceKey` only, with
        // no explicit width passed back down) rendered every stacked card
        // collapsed to its own intrinsic (text-sized) width instead of the
        // full available width.
        GeometryReader { proxy in
            let cardHeight = proxy.size.width / 1.6
            let peek = cardHeight * credentialPeekFraction
            let pullThreshold = cardHeight * credentialPullThresholdFraction
            let totalHeight = cardHeight + peek * CGFloat(max(order.count - 1, 0))

            ScrollView(.vertical, showsIndicators: true) {
                ZStack(alignment: .topLeading) {
                    ForEach(order, id: \.self) { id in
                        if let entry = byId[id], let index = order.firstIndex(of: id) {
                            let y = CGFloat(index) * peek + (id == activeId ? dragOffset : 0)
                            let isActiveDragging = id == activeId && isDragging
                            CredentialCardView(
                                credential: entry.credential,
                                instances: entry.instances,
                                onClick: nil,
                                onRenewClick: { onRenewCredential(entry.credential) }
                            )
                            .frame(width: proxy.size.width, height: cardHeight)
                            // Collapses every leaf accessibility element inside
                            // CredentialCardView (issuer badge, name/format text,
                            // ribbons, ...) into ONE combined element before
                            // tagging it - without this, `.accessibilityIdentifier`
                            // below tags EVERY one of those leaves independently
                            // (confirmed via an XCUITest diagnostic dump: 5
                            // separate elements all matching the same identifier,
                            // each with a tiny frame the size of one text label),
                            // so `.matching(identifier:).firstMatch` resolves to
                            // whichever leaf happens to come first - a few points
                            // wide, not the whole card.
                            .accessibilityElement(children: .combine)
                            .accessibilityIdentifier(credentialStackCardTestTag(id))
                            .scaleEffect(isActiveDragging ? 1.04 : 1.0)
                            .animation(.easeOut(duration: 0.15), value: isActiveDragging)
                            .position(x: proxy.size.width / 2, y: y + cardHeight / 2)
                            .zIndex(isActiveDragging ? 1_000 : Double(index))
                        }
                    }
                }
                .frame(width: proxy.size.width, height: totalHeight, alignment: .top)
                .contentShape(Rectangle())
                .gesture(
                    DragGesture(minimumDistance: 0)
                        .onChanged { value in
                            handleChanged(value, peek: peek, cardHeight: cardHeight)
                        }
                        .onEnded { value in
                            handleEnded(value, pullThreshold: pullThreshold)
                        }
                )
            }
            .scrollDisabled(isDragging)
        }
        .frame(maxHeight: entries.isEmpty ? 0 : .infinity)
        .onAppear { reconcileOrder() }
        .onChange(of: entries.map(\.credential.batchId)) { _ in reconcileOrder() }
    }

    /// Which card (if any) a touch at deck-local `y` lands on - front (last
    /// in `order`, topmost) to back, since the frontmost card is drawn over
    /// everything behind it within its own bounds. This is the crux of why
    /// `CredentialStack` uses ONE gesture recognizer for the whole deck
    /// instead of one per card (`CredentialStackCard` in an earlier version
    /// of this file, since removed): confirmed via repeated on-device/
    /// simulator diagnostics that SwiftUI does NOT reliably arbitrate
    /// independent `.gesture()` recognizers across OVERLAPPING ZStack
    /// siblings by touch point the way Compose does for Kotlin's per-card
    /// `pointerInput` - only the single sibling with the highest `zIndex`
    /// ever received ANY touch, anywhere in the deck's bounds, including
    /// deep inside a buried card's own clearly-visible, uncovered peek
    /// strip, where nothing else was even drawn. That's the same "two
    /// recognizers starve each other" trap this whole feature is built
    /// around, wearing a sibling-level disguise instead of a same-view one:
    /// the fix is the same in spirit - exactly ONE recognizer, so there is
    /// nothing left for it to lose an arbitration race against - just
    /// applied to the whole stack rather than to one card, with this
    /// function doing the hit-testing SwiftUI itself won't do correctly
    /// here.
    private func hitTestCard(atY y: CGFloat, peek: CGFloat, cardHeight: CGFloat) -> Int64? {
        for (index, id) in order.enumerated().reversed() {
            let top = CGFloat(index) * peek
            if y >= top && y <= top + cardHeight {
                return id
            }
        }
        return nil
    }

    private func handleChanged(_ value: DragGesture.Value, peek: CGFloat, cardHeight: CGFloat) {
        switch gesturePhase {
        case .idle:
            guard let id = hitTestCard(atY: value.startLocation.y, peek: peek, cardHeight: cardHeight) else { return }
            activeId = id
            gesturePhase = .pending
            startLongPressTimer(for: id)
        case .pending:
            if abs(value.translation.height) > credentialTouchSlop {
                gesturePhase = .dragging
                longPressTask?.cancel()
                isDragging = true
                dragOffset = value.translation.height
            }
        case .dragging:
            dragOffset = value.translation.height
        case .longPressed:
            break
        }
    }

    private func handleEnded(_ value: DragGesture.Value, pullThreshold: CGFloat) {
        longPressTask?.cancel()
        longPressTask = nil
        defer {
            gesturePhase = .idle
            activeId = nil
        }
        guard let id = activeId, let entry = byId[id] else { return }
        let isFrontmost = order.last == id

        switch gesturePhase {
        case .dragging:
            isDragging = false
            let pulledFarEnough = abs(dragOffset) > pullThreshold
            dragOffset = 0
            if pulledFarEnough && !isFrontmost {
                bringToFront(id)
            }
        case .pending:
            if isFrontmost {
                onCredentialClick(entry.credential)
            } else {
                bringToFront(id)
            }
        case .longPressed, .idle:
            break
        }
    }

    /// Counts down in real time, independently of whether another touch
    /// event ever arrives - a finger held perfectly still delivers no
    /// further `DragGesture.onChanged` calls at all between touch-down and
    /// release, so a long-press timeout checked only inside `onChanged`
    /// (as an earlier version of this function did) never fires for a
    /// still hold: the eventual release reads as a plain tap regardless of
    /// how long the touch was held. Racing the wait itself against the
    /// gesture's own event stream, instead of reacting to events after the
    /// fact, is what makes a held-still press actually resolve to
    /// long-press - confirmed on-device by holding a card motionless in the
    /// simulator for longer than `credentialLongPressDuration` and checking
    /// the long-press action actually fires. Mirrors the Kotlin sample
    /// app's `detectCredentialStackGestures`, which hit the exact same bug
    /// in its first version for the exact same reason.
    private func startLongPressTimer(for id: Int64) {
        longPressTask = Task {
            try? await Task.sleep(nanoseconds: UInt64(credentialLongPressDuration * 1_000_000_000))
            guard !Task.isCancelled else { return }
            await MainActor.run {
                guard gesturePhase == .pending, activeId == id, let entry = byId[id] else { return }
                gesturePhase = .longPressed
                onCredentialLongClick(entry.credential)
            }
        }
    }

    private func bringToFront(_ id: Int64) {
        guard let idx = order.firstIndex(of: id) else { return }
        var newOrder = order
        newOrder.remove(at: idx)
        newOrder.append(id)
        withAnimation(.spring(response: 0.42, dampingFraction: 1.0)) {
            order = newOrder
        }
    }

    /// Reconciled - not replaced - whenever the actual set of credentials
    /// changes: survivors keep their relative order (and so keep whatever
    /// position the user put them in), a newly-added credential joins at
    /// the front.
    private func reconcileOrder() {
        let currentIds = entries.map(\.credential.batchId)
        let currentSet = Set(currentIds)
        let kept = order.filter { currentSet.contains($0) }
        let added = currentIds.filter { !kept.contains($0) }
        if kept != order || !added.isEmpty {
            order = kept + added
        }
    }
}

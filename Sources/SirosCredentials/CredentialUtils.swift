// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
@preconcurrency import SwiftCBOR
#if canImport(os)
import os
private let logger = Logger(subsystem: "org.siros.sdk", category: "CredentialUtils")
#endif

/// A user-facing claim extracted from a credential payload.
public struct DisplayClaim: Sendable, Equatable {
    public let key: String
    public let label: String
    public let value: String
    public let description: String?
    public let mandatory: Bool
    /// VCTM SVG template placeholder ID this claim fills, if any.
    public let svgId: String?

    public init(
        key: String,
        label: String,
        value: String,
        description: String? = nil,
        mandatory: Bool = false,
        svgId: String? = nil
    ) {
        self.key = key
        self.label = label
        self.value = value
        self.description = description
        self.mandatory = mandatory
        self.svgId = svgId
    }
}

/// One claim whose value changed between two versions of the same credential.
public struct AttributeChange: Sendable, Equatable {
    public let key: String
    public let label: String
    public let oldValue: String
    public let newValue: String

    public init(key: String, label: String, oldValue: String, newValue: String) {
        self.key = key
        self.label = label
        self.oldValue = oldValue
        self.newValue = newValue
    }
}

/// The result of ``CredentialUtils/computeAttributeDiff(before:after:)``.
/// `hasChanges` is false (the fully-silent-renewal case per plan §4.4) only
/// when all three lists are empty.
public struct CredentialAttributeDiff: Sendable, Equatable {
    public let changed: [AttributeChange]
    public let added: [DisplayClaim]
    public let removed: [DisplayClaim]

    public init(changed: [AttributeChange], added: [DisplayClaim], removed: [DisplayClaim]) {
        self.changed = changed
        self.added = added
        self.removed = removed
    }

    public var hasChanges: Bool { !changed.isEmpty || !added.isEmpty || !removed.isEmpty }
}

/// The individually-decoded parts of a raw SD-JWT VC string, for display.
///
/// Each field is the decoded JSON text (not yet pretty-printed - callers
/// typically feed these straight into ``CredentialUtils/prettyPrintJson(_:)``
/// or an equivalent renderer).
public struct SdJwtParts: Sendable, Equatable {
    public let header: String?
    public let payload: String?
    /// Each disclosure is a JSON array (`[salt, name, value]` or `[salt, value]`)
    /// per the SD-JWT spec - one raw JSON string per disclosure, not one opaque blob.
    public let disclosures: [String]

    public init(header: String?, payload: String?, disclosures: [String]) {
        self.header = header
        self.payload = payload
        self.disclosures = disclosures
    }
}

public enum CredentialUtils {

    private static let jwtSkipKeys: Set<String> = [
        "iss", "sub", "aud", "exp", "nbf", "iat", "jti",
        "_sd", "_sd_alg", "cnf", "vct", "status", "client_status", "type",
    ]

    /// Parse the payload of a JWT (or the JWT part of an SD-JWT).
    public static func parseJwtPayload(_ raw: String) -> [String: Any]? {
        let jwtPart = raw.split(separator: "~", maxSplits: 1).first.map(String.init) ?? raw
        let parts = jwtPart.split(separator: ".")
        guard parts.count >= 2 else { return nil }

        guard let data = base64UrlDecode(String(parts[1])) else {
            #if canImport(os)
            logger.warning("Failed to base64url-decode JWT payload")
            #endif
            return nil
        }

        do {
            guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                return nil
            }
            return json
        } catch {
            #if canImport(os)
            logger.warning("Failed to parse JWT payload: \(error.localizedDescription)")
            #endif
            return nil
        }
    }

    /// Split a raw SD-JWT VC (`<jwt>~<disclosure>~<disclosure>~...`) into its
    /// individually-decoded parts, for display purposes (e.g. a "Raw" debug
    /// tab) - each disclosure is a separate JSON array per the SD-JWT spec, not
    /// part of one opaque blob.
    public static func parseSdJwtParts(_ raw: String) -> SdJwtParts {
        let segments = raw.split(separator: "~", omittingEmptySubsequences: false).map(String.init)
        let jwtSegments = segments.first?.split(separator: ".").map(String.init) ?? []
        let header = jwtSegments.first.flatMap { decodeJsonSegmentText($0) }
        let payload = jwtSegments.count > 1 ? decodeJsonSegmentText(jwtSegments[1]) : nil
        let disclosures = segments.dropFirst()
            .filter { !$0.isEmpty }
            .compactMap { decodeJsonSegmentText($0) }
        return SdJwtParts(header: header, payload: payload, disclosures: disclosures)
    }

    /// Pretty-print a JSON string with 2-space indentation. Returns the input
    /// unchanged if it doesn't parse as JSON - callers can feed arbitrary
    /// claim values through this safely.
    public static func prettyPrintJson(_ text: String) -> String {
        guard let data = text.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data),
              let pretty = try? JSONSerialization.data(
                withJSONObject: obj,
                options: [.prettyPrinted, .sortedKeys]
              ),
              let prettyString = String(data: pretty, encoding: .utf8) else {
            return text
        }
        return prettyString
    }

    /// Pretty-print an XML/SVG document with simple per-element indentation.
    ///
    /// This is not a validating parser - it's a light tokenizer good enough to
    /// make a VCTM SVG rendering template (or any other XML blob) readable in
    /// a "Raw"/debug view, mirroring what ``prettyPrintJson(_:)`` does for
    /// JSON. Self-closing tags (`<foo/>`), the XML declaration, and comments
    /// are handled; malformed input degrades to returning the original text
    /// unchanged rather than throwing.
    public static func prettyPrintXml(_ xml: String) -> String {
        var result = ""
        var depth = 0
        var index = xml.startIndex
        while index < xml.endIndex {
            guard let tagStart = xml[index...].firstIndex(of: "<") else {
                let remainder = xml[index...].trimmingCharacters(in: .whitespacesAndNewlines)
                if !remainder.isEmpty { result += remainder }
                break
            }
            let text = xml[index..<tagStart].trimmingCharacters(in: .whitespacesAndNewlines)
            guard let tagEnd = xml[tagStart...].firstIndex(of: ">") else {
                return xml
            }
            let tag = xml[tagStart...tagEnd]
            if !text.isEmpty {
                result += String(repeating: "  ", count: depth) + text + "\n"
            }
            let isClosing = tag.hasPrefix("</")
            let isSelfClosing = tag.hasSuffix("/>") || tag.hasPrefix("<?") || tag.hasPrefix("<!--")
            if isClosing { depth = max(0, depth - 1) }
            result += String(repeating: "  ", count: depth) + tag + "\n"
            if !isClosing && !isSelfClosing { depth += 1 }
            index = xml.index(after: tagEnd)
        }
        return result.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Extract user-facing claims from a stored credential.
    ///
    /// VCTM claim paths can be arbitrarily nested (e.g. a diploma's ELM schema
    /// nests everything under `credentialSubject`) - each claim is resolved by
    /// walking its own full path, not just matched by its first segment
    /// against a top-level key.
    public static func extractClaims(_ credential: StoredCredential) -> [DisplayClaim] {
        if credential.format == "mso_mdoc" { return extractMdocClaims(credential) }
        guard let payload = parseJwtPayload(credential.raw) else { return [] }
        let vctmClaims = credential.metadata?.claims ?? []

        let vctmResolved: [DisplayClaim] = vctmClaims.compactMap { claim in
            guard !claim.path.isEmpty, let value = resolveClaimPath(payload, claim.path) else { return nil }
            return DisplayClaim(
                key: claim.path.joined(separator: "."),
                label: claim.label ?? formatClaimKey(claim.path.last ?? ""),
                value: formatClaimValue(value),
                description: claim.description,
                mandatory: claim.mandatory,
                svgId: claim.svgId
            )
        }

        // Top-level keys already resolved (as an ancestor) via a VCTM path
        // shouldn't ALSO be dumped raw - e.g. once "credentialSubject.foo" is
        // resolved, don't separately dump the whole "credentialSubject" blob.
        let coveredTopLevelKeys = Set(vctmClaims.compactMap { $0.path.first })
        let uncovered = payload.keys.sorted().compactMap { key -> DisplayClaim? in
            guard !jwtSkipKeys.contains(key), !coveredTopLevelKeys.contains(key) else { return nil }
            return DisplayClaim(
                key: key,
                label: formatClaimKey(key),
                value: formatClaimValue(payload[key])
            )
        }

        return vctmResolved + uncovered
    }

    /// Walk a VCTM claim path (e.g. `["credentialSubject", "hasClaim", "awardedBy"]`)
    /// through nested JSON to the leaf value it selects. Returns nil if any
    /// segment is missing - the claim just isn't present in this credential.
    private static func resolveClaimPath(_ root: [String: Any], _ path: [String]) -> Any? {
        var current: Any = root
        for segment in path {
            guard let dict = current as? [String: Any], let next = dict[segment] else { return nil }
            current = next
        }
        return current
    }

    /// mdoc analogue of ``extractClaims(_:)``: parse a stored mdoc credential's
    /// REAL disclosed namespace/element values (via `MdocCbor`, not
    /// `parseJwtPayload` which assumes a JWT-shaped `raw`) into `DisplayClaim`s,
    /// using MDDL claim metadata (`credential.metadata.claims`, populated by
    /// ``buildMdocMetadata(offer:mddlSchema:)``) for labels/descriptions when available.
    ///
    /// Claim keys/paths use the `["namespace", "elementIdentifier"]` shape,
    /// consistent with how ``buildMdocMetadata(offer:mddlSchema:)`` populates `ClaimMeta.path`.
    /// Decode and parse a stored mdoc credential's raw base64url CBOR into its
    /// `DocumentMdoc` shape (unwrapping the `DeviceResponse`-style envelope
    /// per wallet-frontend#191). Returns nil if the raw string isn't
    /// valid base64url or doesn't parse as an mdoc document.
    public static func parseMdocDocument(_ rawCredential: String) -> DocumentMdoc? {
        guard let bytes = base64UrlDecode(rawCredential) else { return nil }
        do {
            return try MdocCbor.parseStoredCredential([UInt8](bytes))
        } catch {
            #if canImport(os)
            logger.warning("Failed to parse mdoc credential: \(error.localizedDescription)")
            #endif
            return nil
        }
    }

    public static func extractMdocClaims(_ credential: StoredCredential) -> [DisplayClaim] {
        guard let document = parseMdocDocument(credential.raw) else { return [] }

        var claimMetaByPath: [String: ClaimMeta] = [:]
        for claim in credential.metadata?.claims ?? [] {
            claimMetaByPath[claim.path.joined(separator: "/")] = claim
        }

        return document.issuerSigned.nameSpaces.flatMap { namespace, items in
            items.map { entry -> DisplayClaim in
                let elementId = entry.item.elementIdentifier
                let meta = claimMetaByPath["\(namespace)/\(elementId)"]
                return DisplayClaim(
                    key: "\(namespace).\(elementId)",
                    label: meta?.label ?? formatClaimKey(elementId),
                    value: formatCborValue(entry.item.elementValue),
                    description: meta?.description,
                    mandatory: meta?.mandatory ?? false
                )
            }
        }
    }

    /// Build `CredentialMetadata` for an mdoc credential from its MDDL schema -
    /// the mdoc analogue of ``buildMetadata(offer:vctm:rawCredential:)``.
    /// Populates `CredentialMetadata.doctype` (unused for SD-JWT credentials)
    /// instead of `CredentialMetadata.vct`.
    public static func buildMdocMetadata(offer: CredentialOffer, mddlSchema: MddlSchema? = nil) -> CredentialMetadata {
        let locale = Locale.current.identifier.replacingOccurrences(of: "_", with: "-")
        let display = mddlSchema?.display.flatMap { displays in
            displays.first(where: { $0.locale == locale })
                ?? displays.first(where: { $0.locale.hasPrefix(String(locale.prefix(2))) })
                ?? displays.first
        }

        let claims: [ClaimMeta]? = mddlSchema?.claims?.flatMap { namespace, elements in
            elements.map { elementId, meta -> ClaimMeta in
                let claimDisplay = meta.display.flatMap { displays in
                    displays.first(where: { $0.locale == locale })
                        ?? displays.first(where: { $0.locale.hasPrefix(String(locale.prefix(2))) })
                        ?? displays.first
                }
                return ClaimMeta(
                    path: [namespace, elementId],
                    label: claimDisplay?.name,
                    mandatory: meta.mandatory
                )
            }
        }

        return CredentialMetadata(
            name: display?.name ?? offer.credentialName,
            description: display?.description ?? offer.credentialDescription,
            issuer: IssuerInfo(name: offer.issuerName, url: offer.credentialIssuerIdentifier),
            doctype: mddlSchema?.doctype,
            backgroundColor: display?.backgroundColor ?? offer.backgroundColor,
            textColor: display?.textColor ?? offer.textColor,
            logo: display?.logo.map { LogoInfo(uri: $0.uri, altText: $0.altText) }
                ?? offer.logoUri.map { LogoInfo(uri: $0) },
            claims: claims
        )
    }

    /// Format a decoded CBOR element value for display.
    private static func formatCborValue(_ value: CBOR) -> String {
        switch value {
        case .utf8String(let s): return s
        case .byteString(let b): return "<\(b.count) bytes>"
        case .unsignedInt(let n): return String(n)
        case .negativeInt(let n): return String(-1 - Int64(n))
        case .boolean(let b): return b ? "true" : "false"
        case .double(let d): return String(d)
        case .float(let f): return String(f)
        default: return String(describing: value)
        }
    }

    /// Build credential metadata from an offer, optional VCTM, and raw credential.
    public static func buildMetadata(
        offer: CredentialOffer,
        vctm: Vctm? = nil,
        rawCredential: String? = nil
    ) -> CredentialMetadata {
        let locale = Locale.current.identifier.replacingOccurrences(of: "_", with: "-")
        let vctmDisplay = vctm?.display.flatMap { displays in
            displays.first(where: { $0.locale == locale })
                ?? displays.first(where: { $0.locale.hasPrefix(String(locale.prefix(2))) })
                ?? displays.first
        }

        let simple = vctmDisplay?.rendering?.simple

        let payload = rawCredential.flatMap { parseJwtPayload($0) }
        let vct = payload?["vct"] as? String

        let claims: [ClaimMeta]? = vctm?.claims?.map { claim in
            let claimDisplay = claim.display.flatMap { displays in
                displays.first(where: { $0.locale == locale })
                    ?? displays.first(where: { $0.locale.hasPrefix(String(locale.prefix(2))) })
                    ?? displays.first
            }
            return ClaimMeta(
                path: claim.path.compactMap { $0 },
                label: claimDisplay?.label,
                description: claimDisplay?.description,
                sd: claim.sd,
                mandatory: claim.mandatory ?? false,
                svgId: claim.svgId
            )
        }

        let svgTemplates: [SvgTemplateInfo]? = vctmDisplay?.rendering?.svgTemplates?.map { template in
            SvgTemplateInfo(
                uri: template.uri,
                colorScheme: template.properties?.colorScheme,
                contrast: template.properties?.contrast,
                orientation: template.properties?.orientation
            )
        }

        return CredentialMetadata(
            name: vctmDisplay?.name ?? offer.credentialName,
            description: vctmDisplay?.description ?? offer.credentialDescription,
            issuer: IssuerInfo(
                name: offer.issuerName,
                url: offer.credentialIssuerIdentifier
            ),
            vct: vct,
            backgroundColor: simple?.backgroundColor ?? offer.backgroundColor,
            textColor: simple?.textColor ?? offer.textColor,
            logo: simple?.logo.map { LogoInfo(uri: $0.uri, altText: $0.altText) }
                ?? offer.logoUri.map { LogoInfo(uri: $0) },
            claims: claims,
            svgTemplates: svgTemplates
        )
    }

    /// Format a snake_case or kebab-case key as a human-readable label.
    public static func formatClaimKey(_ key: String) -> String {
        key.split(omittingEmptySubsequences: true, whereSeparator: { $0 == "_" || $0 == "-" })
            .map { $0.prefix(1).uppercased() + $0.dropFirst() }
            .joined(separator: " ")
    }

    // MARK: - Private

    private static func decodeJsonSegmentText(_ base64url: String) -> String? {
        guard let data = base64UrlDecode(base64url),
              let obj = try? JSONSerialization.jsonObject(with: data),
              let reencoded = try? JSONSerialization.data(withJSONObject: obj),
              let text = String(data: reencoded, encoding: .utf8) else {
            return nil
        }
        return text
    }

    private static func formatClaimValue(_ value: Any?) -> String {
        switch value {
        case let s as String: return s
        case let n as NSNumber: return n.stringValue
        case let b as Bool: return b ? "true" : "false"
        default: return String(describing: value ?? "")
        }
    }

    /// Decode a base64url (no padding) string, restoring the `=` padding
    /// `Data(base64Encoded:)` requires - a bare `-`/`_` substitution without
    /// restoring padding silently returns nil for any input whose length
    /// isn't already a multiple of 4.
    public static func base64UrlDecode(_ string: String) -> Data? {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder != 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        return Data(base64Encoded: base64)
    }

    /// Group stored credentials into display-ready families, mirroring
    /// wallet-frontend's `CredentialsContextProvider.fetchVcData`: only the
    /// `instanceId == 0` credential of a batch (see `StoredCredential.batchId`)
    /// is returned as a visible entry, with every sibling copy's usage count
    /// attached as `CredentialWithInstances.instances` - the UI derives its
    /// "remaining copies" badge from `instances.count { $0.sigCount == 0 }`.
    ///
    /// Every issuance response - batch of one or of many - shares one
    /// `batchId`, so grouping is uniform: no separate "standalone" case,
    /// matching wallet-frontend exactly.
    public static func groupForDisplay(
        credentials: [StoredCredential],
        presentationHistory: [PresentationRecord]
    ) -> [CredentialWithInstances] {
        func sigCount(for credentialId: Int64) -> Int {
            presentationHistory.filter { $0.credentialIds.contains(credentialId) }.count
        }

        var byBatch: [Int64: [StoredCredential]] = [:]
        for credential in credentials {
            byBatch[credential.batchId, default: []].append(credential)
        }

        let results: [CredentialWithInstances] = byBatch.values.compactMap { members in
            guard let visible = members.first(where: { $0.instanceId == 0 }) else { return nil }
            let instances = members
                .sorted(by: { $0.instanceId < $1.instanceId })
                .map { CredentialInstance(instanceId: $0.instanceId, sigCount: sigCount(for: $0.id)) }
            return CredentialWithInstances(credential: visible, instances: instances)
        }

        return results.sorted(by: { ($0.credential.issuedAt ?? 0) > ($1.credential.issuedAt ?? 0) })
    }

    /// Every credential format this SDK currently supports discloses via
    /// salted-hash element digests (mdoc's MSO, SD-JWT's `_sd` array) - none
    /// is a real ZKP predicate proof - so ``CredentialConsumptionPolicy/consumeNonZkp``
    /// is indistinguishable from ``CredentialConsumptionPolicy/consumeAll``
    /// today. Kept as a real, separate policy value (not collapsed into one)
    /// since it's the right shape for once a ZKP-based format exists; this
    /// function is the single place that would need updating then.
    private static func isZkpFormat(_ format: String) -> Bool { false }

    /// Instances from `instances` (all copies of one batch - see
    /// `StoredCredential.batchId`) that are still allowed to be used for a
    /// NEW presentation under `policy`, given what `presentationHistory`
    /// shows has already been presented. Mirrors ``groupForDisplay(credentials:presentationHistory:)``'s
    /// own `sigCount` usage-counting exactly, so "eligible" and the
    /// "remaining copies" ribbon never disagree.
    ///
    /// ``CredentialConsumptionPolicy/neverConsume`` (the default - today's
    /// actual behavior) returns every instance unconditionally. Otherwise, an
    /// instance is eligible only if it hasn't already been presented
    /// (`sigCount == 0`) - each instance is bound to its own device key
    /// specifically so a verifier can't correlate repeated presentations by a
    /// reused key/signature; reusing an already-presented instance would
    /// throw that guarantee away.
    public static func eligibleInstances(
        instances: [StoredCredential],
        policy: CredentialConsumptionPolicy,
        presentationHistory: [PresentationRecord]
    ) -> [StoredCredential] {
        guard policy != .neverConsume else { return instances }
        // A single pass building this set, rather than rescanning all of
        // presentationHistory per instance (O(instances x history) before),
        // matters once either grows - this can run on every UI update.
        var usedCredentialIds: Set<Int64> = []
        for record in presentationHistory {
            usedCredentialIds.formUnion(record.credentialIds)
        }
        return instances.filter { instance in
            let consumes = policy == .consumeAll || !isZkpFormat(instance.format)
            return !consumes || !usedCredentialIds.contains(instance.id)
        }
    }

    /// Below this many eligible (unused) instances remaining, the UI should
    /// offer to renew/re-issue the credential rather than let it silently run
    /// out. Not user-configurable in this pass - just the stated default.
    public static let renewThreshold = 0

    /// True when `instances`' eligible (unused) count under `policy`/
    /// `presentationHistory` has dropped to or below `threshold` - the
    /// proactive-renewal trigger (plan §4.3). Note `CredentialConsumptionPolicy.neverConsume`
    /// makes `eligibleInstances` always return every instance, so this only
    /// ever fires under a consuming policy.
    public static func isBelowRenewThreshold(
        instances: [StoredCredential],
        policy: CredentialConsumptionPolicy,
        presentationHistory: [PresentationRecord],
        threshold: Int = renewThreshold
    ) -> Bool {
        eligibleInstances(instances: instances, policy: policy, presentationHistory: presentationHistory).count <= threshold
    }

    /// Compares two versions of the same credential's claims (by `key`, not
    /// list position - VCTM claim ordering isn't guaranteed stable across a
    /// renewal) and reports what changed, matching Kotlin's
    /// `CredentialUtils.computeAttributeDiff` exactly.
    public static func computeAttributeDiff(before: [DisplayClaim], after: [DisplayClaim]) -> CredentialAttributeDiff {
        let beforeByKey = Dictionary(uniqueKeysWithValues: before.map { ($0.key, $0) })
        let afterByKey = Dictionary(uniqueKeysWithValues: after.map { ($0.key, $0) })
        let changed: [AttributeChange] = afterByKey.keys.filter { beforeByKey[$0] != nil }.compactMap { key in
            guard let old = beforeByKey[key], let new = afterByKey[key], old.value != new.value else { return nil }
            return AttributeChange(key: key, label: new.label, oldValue: old.value, newValue: new.value)
        }
        let added = afterByKey.keys.filter { beforeByKey[$0] == nil }.map { afterByKey[$0]! }
        let removed = beforeByKey.keys.filter { afterByKey[$0] == nil }.map { beforeByKey[$0]! }
        return CredentialAttributeDiff(changed: changed, added: added, removed: removed)
    }

    /// Group stored credentials into one ``CredentialFamily`` per
    /// `StoredCredential.batchId`, for callers (mdoc proximity consent) that
    /// need every instance's full `StoredCredential` - not just its usage
    /// count, as ``groupForDisplay(credentials:presentationHistory:)``'s
    /// `CredentialInstance` carries - because a proximity session signs with
    /// whichever approved instance it picks.
    ///
    /// Uses the same convention as `groupForDisplay`: a batch is only
    /// representable if it has an `instanceId == 0` member; a batch missing
    /// one is skipped rather than falling back to an arbitrary member, so
    /// the two grouping functions never disagree about which batches are
    /// representable.
    public static func groupIntoFamilies(_ credentials: [StoredCredential]) -> [CredentialFamily] {
        var byBatch: [Int64: [StoredCredential]] = [:]
        for credential in credentials {
            byBatch[credential.batchId, default: []].append(credential)
        }
        return byBatch.values.compactMap { members in
            guard let representative = members.first(where: { $0.instanceId == 0 }) else { return nil }
            return CredentialFamily(representative: representative, instances: members)
        }
    }
}

/// Governs whether a successful presentation exhausts the specific credential
/// instance it used, so that instance can never be presented again.
///
/// Defaults to ``neverConsume`` - today's actual behavior - so introducing
/// this setting doesn't silently change existing wallets' behavior.
public enum CredentialConsumptionPolicy: String, Sendable, CaseIterable {
    /// Every successful presentation exhausts the instance it used, regardless of format.
    case consumeAll

    /// Same as ``consumeAll`` until a real ZKP presentation format exists (see
    /// `CredentialUtils.isZkpFormat`).
    case consumeNonZkp

    /// Instances are never exhausted - a presentation may reuse any matching instance.
    case neverConsume
}

/// One member of a batch-issued credential family, alongside its usage count.
public struct CredentialInstance: Sendable, Equatable {
    public let instanceId: Int
    public let sigCount: Int

    public init(instanceId: Int, sigCount: Int) {
        self.instanceId = instanceId
        self.sigCount = sigCount
    }
}

/// A visible credential card plus every instance in its batch (see `CredentialUtils.groupForDisplay`).
public struct CredentialWithInstances: Sendable, Equatable {
    public let credential: StoredCredential
    public let instances: [CredentialInstance]

    public init(credential: StoredCredential, instances: [CredentialInstance]) {
        self.credential = credential
        self.instances = instances
    }
}

/// One credential "type" as the user should see it: every `StoredCredential`
/// instance sharing a `StoredCredential.batchId` is the SAME credential from
/// a batch issuance (see `CredentialUtils.groupForDisplay`'s doc comment for
/// why - each instance is bound to its own device key purely for
/// unlinkability, not a distinct credential the user chose to hold multiple
/// of). A proximity consent prompt must offer one choice per family, never
/// one per raw instance, or a 5-instance batch reads as "you have 5 driver's
/// licenses." See `CredentialUtils.groupIntoFamilies`.
public struct CredentialFamily: Sendable, Equatable {
    /// The instance shown to the user for display (matches
    /// `CredentialUtils.groupForDisplay`'s convention of the `instanceId == 0` member).
    public let representative: StoredCredential
    /// Every instance in this batch - the proximity session picks one of these to actually sign with once the family is approved.
    public let instances: [StoredCredential]

    public init(representative: StoredCredential, instances: [StoredCredential]) {
        self.representative = representative
        self.instances = instances
    }
}

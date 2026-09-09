// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// What a host app has to declare for the SDK's features to work on iOS.
///
/// Android lets a library merge its own manifest into the host app, so the
/// Kotlin SDK ships its platform components declared and a host app adds
/// nothing. iOS has no equivalent: `Info.plist` usage descriptions, URL
/// schemes and entitlements can only be declared by the app bundle itself,
/// and a missing one fails at runtime - a camera that never prompts, a deep
/// link that opens Safari instead, an NFC session that throws - long after
/// the integration looked finished. This type is the SDK's side of that
/// contract: the requirements, stated once, per feature, and an `audit` that
/// reads the host's bundle and says which are missing. Call it on startup in
/// debug builds; the sample app does.
///
/// Requirements are grouped by feature because an app that never scans QR
/// codes owes no camera prompt, and one that never does proximity
/// presentation owes no Bluetooth one. `Feature.allCases` is the union.
public enum HostAppRequirements {

    /// An SDK capability with its own host-side declarations.
    public enum Feature: String, CaseIterable, Sendable {
        /// Passkey login and registration (`ASAuthorization`): the
        /// `webcredentials:` associated domain for the wallet backend's
        /// relying-party id.
        case passkeys
        /// Same-device flows started by URL: OpenID4VCI offers, OpenID4VP /
        /// HAIP requests, and the OAuth authorization callback.
        case deepLinks
        /// QR-code scanning of offers and presentation requests.
        case qrScanning
        /// ISO 18013-5 proximity presentation over BLE.
        case bleProximity
        /// FIDO2 security keys over NFC (CTAP2), and NFC device engagement.
        case nfc
        /// Biometric gating of key use (`LAContext`).
        case biometrics
        /// Identity verification via the IDV module's liveness capture.
        case identityVerification
    }

    /// One thing the host bundle must declare.
    public struct Requirement: Equatable, Sendable {
        public enum Kind: Equatable, Sendable {
            /// An `Info.plist` key that must be present (any non-empty value).
            case infoPlistKey(String)
            /// A URL scheme that must appear in some `CFBundleURLTypes` entry.
            case urlScheme(String)
            /// A code-signing entitlement. Entitlements are not readable from
            /// inside the process, so these are reported for documentation
            /// and never flagged as missing by `audit`.
            case entitlement(String)
        }
        public let feature: Feature
        public let kind: Kind
        /// Why the SDK needs it - suitable for a checklist or a log line.
        public let reason: String
    }

    /// The requirements for `features` (default: every feature).
    public static func requirements(for features: Set<Feature> = Set(Feature.allCases)) -> [Requirement] {
        var out: [Requirement] = []
        func add(_ feature: Feature, _ kind: Requirement.Kind, _ reason: String) {
            if features.contains(feature) { out.append(Requirement(feature: feature, kind: kind, reason: reason)) }
        }
        add(.passkeys, .entitlement("com.apple.developer.associated-domains"),
            "webcredentials:<backend host> lets ASAuthorization create and use passkeys for the wallet backend's relying-party id")
        for scheme in DeepLinkClassifier.handledSchemes {
            add(.deepLinks, .urlScheme(scheme),
                "the SDK classifies \(scheme):// links into issuance or presentation flows (DeepLinkClassifier)")
        }
        add(.qrScanning, .infoPlistKey("NSCameraUsageDescription"),
            "the camera prompt shown before the first QR scan; without it the OS terminates the app on access")
        add(.bleProximity, .infoPlistKey("NSBluetoothAlwaysUsageDescription"),
            "CoreBluetooth advertising and connecting to an mdoc reader")
        add(.nfc, .infoPlistKey("NFCReaderUsageDescription"),
            "CoreNFC sessions for CTAP2 security keys and NFC engagement")
        add(.nfc, .entitlement("com.apple.developer.nfc.readersession.formats"),
            "TAG format, so NFCTagReaderSession can talk ISO 7816 to a security key")
        add(.biometrics, .infoPlistKey("NSFaceIDUsageDescription"),
            "LAContext evaluation gating keystore operations on Face ID devices")
        add(.identityVerification, .infoPlistKey("NSCameraUsageDescription"),
            "the IDV module's liveness capture uses the camera")
        return out
    }

    /// A requirement `audit` found unmet.
    public struct Finding: Equatable, Sendable, CustomStringConvertible {
        public let requirement: Requirement
        public var description: String {
            let what: String
            switch requirement.kind {
            case .infoPlistKey(let key): what = "Info.plist key \(key)"
            case .urlScheme(let scheme): what = "CFBundleURLTypes scheme \(scheme)"
            case .entitlement(let e): what = "entitlement \(e)"
            }
            return "[\(requirement.feature.rawValue)] missing \(what): \(requirement.reason)"
        }
    }

    /// Checks `bundle`'s `Info.plist` against the requirements for
    /// `features`, plus the host's own authorization-callback scheme if
    /// given. Entitlements cannot be inspected at runtime and are skipped.
    /// Returns an empty array when everything the SDK can check is declared.
    public static func audit(
        bundle: Bundle = .main,
        features: Set<Feature> = Set(Feature.allCases),
        callbackScheme: String? = nil
    ) -> [Finding] {
        audit(infoDictionary: bundle.infoDictionary ?? [:], features: features, callbackScheme: callbackScheme)
    }

    /// `audit(bundle:)` on an already-loaded `Info.plist` dictionary.
    public static func audit(
        infoDictionary info: [String: Any],
        features: Set<Feature> = Set(Feature.allCases),
        callbackScheme: String? = nil
    ) -> [Finding] {
        let declaredSchemes: Set<String> = Set(
            ((info["CFBundleURLTypes"] as? [[String: Any]]) ?? [])
                .flatMap { ($0["CFBundleURLSchemes"] as? [String]) ?? [] }
                .map { $0.lowercased() }
        )
        var findings: [Finding] = []
        for requirement in requirements(for: features) {
            switch requirement.kind {
            case .infoPlistKey(let key):
                let value = info[key] as? String
                if value == nil || value?.isEmpty == true { findings.append(Finding(requirement: requirement)) }
            case .urlScheme(let scheme):
                if !declaredSchemes.contains(scheme.lowercased()) { findings.append(Finding(requirement: requirement)) }
            case .entitlement:
                continue
            }
        }
        if let callbackScheme, !declaredSchemes.contains(callbackScheme.lowercased()) {
            findings.append(Finding(requirement: Requirement(
                feature: .deepLinks,
                kind: .urlScheme(callbackScheme),
                reason: "the authorization redirect the wallet backend sends the browser back to after login"
            )))
        }
        return findings
    }
}

// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI

/// Which appearance the app uses: the device's, or one the user picked. The
/// raw value is what is stored (`ThemeMode.storageKey`, read with
/// `@AppStorage` at the root of the app so the login screen follows it too).
enum ThemeMode: String, CaseIterable, Identifiable {
    case system
    case light
    case dark

    static let storageKey = "siros.sample.themeMode"

    var id: String { rawValue }

    /// The mode stored as `value`; `.system` when nothing, or nothing
    /// recognisable, is stored.
    static func fromStored(_ value: String?) -> ThemeMode {
        value.flatMap(ThemeMode.init(rawValue:)) ?? .system
    }

    /// What to hand `preferredColorScheme`: nil follows the device.
    var colorScheme: ColorScheme? {
        switch self {
        case .system: return nil
        case .light: return .light
        case .dark: return .dark
        }
    }

    var label: String {
        switch self {
        case .system: return L10n.string("settings.appearanceSystem")
        case .light: return L10n.string("settings.appearanceLight")
        case .dark: return L10n.string("settings.appearanceDark")
        }
    }
}

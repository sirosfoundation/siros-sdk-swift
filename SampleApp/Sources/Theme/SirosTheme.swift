// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI

/// SIROS brand theme colors — adaptive for light and dark mode.
/// Light mode values match wallet-frontend branding/default/theme.json.
/// Dark mode values are derived from the same palette with inverted surfaces.
enum SirosTheme {
    // Brand palette (same in both modes)
    static let brand = Color(red: 0.106, green: 0.271, blue: 0.529)           // #1B4587
    static let brandLight = Color(red: 0.239, green: 0.400, blue: 0.655)      // #3D66A7
    static let brandLighter = Color(red: 0.490, green: 0.573, blue: 0.706)    // #7D92B4
    static let brandDark = Color(red: 0.243, green: 0.376, blue: 0.596)       // #3E6098

    // Adaptive Surface/Background
    static let background = Color("SirosBackground", bundle: nil)
    static let surface = Color("SirosSurface", bundle: nil)
    static let surfaceVariant = Color("SirosSurfaceVariant", bundle: nil)

    // Adaptive On colors
    static let onSurface = Color("SirosOnSurface", bundle: nil)
    static let onSurfaceVariant = Color("SirosOnSurfaceVariant", bundle: nil)
    static let onPrimary = Color.white

    // Semantic
    static let error = Color(red: 0.933, green: 0.267, blue: 0.267)           // #EE4444
    static let border = Color("SirosBorder", bundle: nil)
}

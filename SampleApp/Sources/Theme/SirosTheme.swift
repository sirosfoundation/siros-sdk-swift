// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI

/// SIROS brand theme colors — matches wallet-frontend branding/default/theme.json.
enum SirosTheme {
    // Brand palette
    static let brand = Color(red: 0.106, green: 0.271, blue: 0.529)           // #1B4587
    static let brandLight = Color(red: 0.239, green: 0.400, blue: 0.655)      // #3D66A7
    static let brandLighter = Color(red: 0.490, green: 0.573, blue: 0.706)    // #7D92B4
    static let brandDark = Color(red: 0.243, green: 0.376, blue: 0.596)       // #3E6098

    // Surface/Background
    static let background = Color(red: 0.976, green: 0.980, blue: 0.984)      // #F9FAFB
    static let surface = Color.white
    static let surfaceVariant = Color(red: 0.953, green: 0.957, blue: 0.965)  // #F3F4F6

    // On colors
    static let onSurface = Color(red: 0.067, green: 0.086, blue: 0.129)       // #111621
    static let onSurfaceVariant = Color(red: 0.294, green: 0.333, blue: 0.388) // #4B5563
    static let onPrimary = Color.white

    // Semantic
    static let error = Color(red: 0.933, green: 0.267, blue: 0.267)           // #EE4444
    static let border = Color(red: 0.898, green: 0.906, blue: 0.922)          // #E5E7EB
}


// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import UIKit

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
    // For outcomes that may resolve on their own - a suspended credential can
    // be reinstated, one that is not yet valid simply becomes valid - which
    // should not read as the same finality as `error`.
    static let warning = Color(red: 0.918, green: 0.588, blue: 0.129)         // #EA9621
    static let success = Color(red: 0.133, green: 0.694, blue: 0.298)         // #22B14C
    static let border = Color("SirosBorder", bundle: nil)

    // MARK: - Wallet design ("Mobile Landing & Navigation")
    //
    // Colours of the wallet's own screens: the header, the bottom bar, Home,
    // the menu and the screens they lead to. A credential card is drawn from
    // its registry design and reads none of these; every colour above this
    // mark is as it was.

    /// Page background of the designed screens.
    static let screenBackground = adaptive(light: 0xFFFFFF, dark: 0x131B29)
    /// Primary text (#0C0E11).
    static let ink = adaptive(light: 0x0C0E11, dark: 0xEEF0F3)
    /// Secondary text and unselected bar items: #69707D, a step darker than
    /// the design's #6E7582 so it reads at 4.7:1 on the alternate surface
    /// (the design's value reaches 4.4:1 there).
    static let secondaryText = adaptive(light: 0x69707D, dark: 0xB3BBC6)
    /// The alternate, faintly grey surface (#F8F9F9).
    static let altSurface = adaptive(light: 0xF8F9F9, dark: 0x1C2433)
    /// Card borders and rules (#E0E1E4).
    static let hairline = adaptive(light: 0xE0E1E4, dark: 0x333A48)
    /// Pale-blue icon tile and its icon (#E5EEFD / brand).
    static let iconTile = adaptive(light: 0xE5EEFD, dark: 0x24365A)
    static let iconTileContent = adaptive(light: 0x1B4587, dark: 0xC9D8F5)
    /// Grey icon tile of a Home prompt card (#EDEDEF).
    static let promptTile = adaptive(light: 0xEDEDEF, dark: 0x2A3244)
    /// Highlight of the current row in the menu (#E0E1E4).
    static let menuHighlight = adaptive(light: 0xE0E1E4, dark: 0x2A3244)
    /// Brand-coloured text and icons on a page background.
    static let brandOnPage = adaptive(light: 0x1B4587, dark: 0x7D92B4)
    /// The attention amber of Home's banner (#F9A917).
    static let attention = Color(red: 0.976, green: 0.663, blue: 0.090)
    /// The Scan QR button at the centre of the bottom bar: black with a white
    /// mark, inverted in the dark theme.
    static let scanButton = adaptive(light: 0x000000, dark: 0xEEF0F3)
    static let onScanButton = adaptive(light: 0xFFFFFF, dark: 0x0C0E11)

    /// Horizontal page margin and corner radius shared by the designed screens.
    static let screenMargin: CGFloat = 24
    static let cardCorner: CGFloat = 8

    private static func adaptive(light: UInt32, dark: UInt32) -> Color {
        Color(uiColor: UIColor { traits in
            let rgb = traits.userInterfaceStyle == .dark ? dark : light
            return UIColor(
                red: CGFloat((rgb >> 16) & 0xFF) / 255,
                green: CGFloat((rgb >> 8) & 0xFF) / 255,
                blue: CGFloat(rgb & 0xFF) / 255,
                alpha: 1
            )
        })
    }
}

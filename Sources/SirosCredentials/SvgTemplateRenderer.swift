// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Substitutes VCTM claim values into an SVG rendering template.
///
/// VCTM's `rendering.svg_templates` (section 6) points at an SVG image; claims
/// with a `svg_id` are meant to fill placeholders inside it. In practice (e.g.
/// the dc4eu/vc image set used by real EUDI-style issuers) this is plain
/// Mustache-style text substitution - `{{claimSvgId}}` tokens inside `<text>`
/// elements - not DOM/id-attribute editing, so this is pure string
/// replacement, platform-agnostic and unit-testable without any UI framework.
public enum SvgTemplateRenderer {

    private static let unmatchedToken = try! NSRegularExpression(pattern: "\\{\\{[^}]*\\}\\}")

    /// Replace every `{{claim.svgId}}` token in `svgTemplate` with that claim's
    /// resolved, XML-escaped value. Any token left over (a claim the VCTM
    /// defines but that isn't present in this particular credential) is
    /// blanked rather than shown to the user literally.
    public static func substitute(_ svgTemplate: String, claims: [DisplayClaim]) -> String {
        var result = svgTemplate
        for claim in claims {
            guard let id = claim.svgId else { continue }
            result = result.replacingOccurrences(of: "{{\(id)}}", with: escapeXml(claim.value))
        }
        let range = NSRange(result.startIndex..., in: result)
        result = unmatchedToken.stringByReplacingMatches(in: result, range: range, withTemplate: "")
        return result
    }

    /// Escape characters that are special in XML text content/attributes.
    public static func escapeXml(_ value: String) -> String {
        value
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&apos;")
    }
}

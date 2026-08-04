// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import CoreImage
import CoreImage.CIFilterBuiltins
#if canImport(UIKit)
import UIKit
#endif

/// Renders a string (e.g. an `mdoc:` device engagement URI) as a QR code
/// image, for display to an mdoc reader per ISO 18013-5 §8.2.2.3.
///
/// Ported from the Kotlin sample app's `QrCodeGenerator.kt`, which used
/// zxing - Apple platforms need no third-party dependency for this, since
/// `CoreImage`'s built-in `CIQRCodeGenerator` filter does the same job.
enum QrCodeGenerator {

    /// Generate a QR code image for `content`, scaled up to roughly
    /// `sizePx` on each side (the filter's native output is a small, exact
    /// module-count bitmap - nearest-neighbor scaling keeps QR modules crisp
    /// rather than blurring them).
    static func generate(_ content: String, sizePx: CGFloat = 800) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(content.utf8)
        // "M" (15% error correction) - matches the Kotlin sample app's
        // choice, a reasonable balance between density and scan
        // reliability for a device-engagement URI.
        filter.correctionLevel = "M"

        guard let ciImage = filter.outputImage else { return nil }
        let scale = sizePx / ciImage.extent.width
        let scaled = ciImage.transformed(by: CGAffineTransform(scaleX: scale, y: scale))

        let context = CIContext()
        guard let cgImage = context.createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cgImage)
    }
}

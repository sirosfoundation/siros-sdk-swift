// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI

/// The wallet's two engagement screens behind one entry point: scanning a QR
/// code (`QRScannerContent`) and showing the wallet's ISO 18013-5 device
/// engagement as a QR code (`ProximityEngagementContent`). Both are
/// chrome-free; `ContentView` frames them with the wallet header and a Back
/// button, which always means "leave Activate entirely".
struct ActivateView: View {
    @EnvironmentObject var viewModel: WalletViewModel

    var body: some View {
        switch viewModel.activateMode {
        case .qr:
            QRScannerContent()
        case .proximity:
            ProximityEngagementContent()
        }
    }
}

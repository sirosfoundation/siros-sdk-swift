// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI

@main
struct SirosSampleApp: App {
    @StateObject private var viewModel = WalletViewModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(viewModel)
                .onOpenURL { url in
                    viewModel.handleDeepLink(url)
                }
                .tint(SirosTheme.brand)
        }
    }
}

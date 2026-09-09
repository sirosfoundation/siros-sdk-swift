// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosWallet

@main
struct SirosSampleApp: App {
    @StateObject private var viewModel = WalletViewModel()

    init() {
        #if DEBUG
        // iOS cannot merge an SDK's Info.plist needs into the host app the
        // way Android merges manifests, so the SDK states them and this
        // checks the bundle against that list. Anything reported here is a
        // feature that will fail at runtime, not at build time.
        for finding in HostAppRequirements.audit(callbackScheme: "siros-sample") {
            print("HostAppRequirements: \(finding)")
        }
        #endif
    }

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

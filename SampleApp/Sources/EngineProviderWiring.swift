// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosWallet
import SirosTransport

extension WalletViewModel {

    /// The prioritized engine providers (the SDK's `engineProviders`) - the
    /// user-configured list the wallet connects in order (retries each)
    /// until one answers; the connected session is pinned to its provider.
    /// An empty enabled set keeps the single-mode shape (`wmpEngineMode`,
    /// the picker). Broken out as separately-typed statements like the
    /// config's other closures (the same type-checker limit makeWallet
    /// warns about).
    func engineProviderList(backendUrl: String) -> [WmpEngineProvider] {
        let localProviderFactory: (@Sendable (WmpEngineAskContext) throws -> any TransportProtocol)?
        if engineLocalEnabled {
            localProviderFactory = { [backendUrl] (ctx: WmpEngineAskContext) in
                try makeLocalEngineTransport(
                    asks: ctx.asks,
                    backendUrl: backendUrl,
                    bearer: ctx.bearerProvider
                )
            }
        } else {
            localProviderFactory = nil
        }
        var engineProviders: [WmpEngineProvider] = []
        if let localProviderFactory {
            engineProviders.append(.local(localProviderFactory))
        }
        let trimmedSendUrl = wmpSendUrl.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedSseUrl = wmpSseUrl.trimmingCharacters(in: .whitespacesAndNewlines)
        if engineRemoteEnabled && !trimmedSendUrl.isEmpty && !trimmedSseUrl.isEmpty {
            engineProviders.append(
                .remoteHttpSse(
                    sendUrl: trimmedSendUrl,
                    sseUrl: trimmedSseUrl,
                    // The bearer KIND must match the deployment's
                    // ENGINE_PRINCIPAL_MODE: the tenant kind (the AS's
                    // pseudonymous engine token) for the tenant-mode engines
                    // this sample targets, the user's own backend token for a
                    // user-mode engine.
                    tenantTokens: engineTenantTokens
                )
            )
        }
        return engineProviders
    }
}

/// app's ports (URLSession for the engine's outgoing fetches, the WALLET's
/// own ask handlers over the SDK's handler seam). The trust stack is the
/// backend proxy's PDP routes (`ProxyPdp`) when the provider-list path
/// supplies the backend URL and the wallet's own backend bearer (the SDK's
/// ask context - only the provider-list path has it); the single-mode
/// shape passes neither and the local engine then fails closed at the trust
/// step. A free function, so the `@Sendable` closures capture nothing but
/// their explicit arguments.
///
/// The XCFramework gates it: a build without the engine core
/// (`engine_adapter_sdkFFI` - Vendor/'s framework) refuses the local mode
/// with a clear error at the factory, exactly as the SDK's own
/// `WmpEngineMode.local` check does when no factory was configured.
func makeLocalEngineTransport(
    asks: WmpEngineAskHandler,
    backendUrl: String? = nil,
    bearer: (@Sendable () async throws -> String?)? = nil
) throws -> any TransportProtocol {
    #if canImport(EngineAdapterSdk)
    // The types are the SDK's own (SirosTransport's) and the app target's;
    // the engine bindings ride inside them - nothing to import here.
    let pdp: ProxyPdp?
    if let backendUrl, let bearer {
        pdp = ProxyPdp(baseUrl: backendUrl, bearerProvider: bearer)
    } else {
        pdp = nil
    }
    return WmpUniFFITransport(
        http: URLSessionEngineHttp(),
        host: UniFfiEngineAskHost(handler: asks),
        pdp: pdp
    )
    #else
    throw NSError(
        domain: "org.siros.sdk.sample",
        code: 1,
        userInfo: [NSLocalizedDescriptionKey: "The local engine mode needs the engine XCFramework (engine_adapter_sdkFFI), which this build does not link"]
    )
    #endif
}

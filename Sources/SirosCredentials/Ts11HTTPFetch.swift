// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(os)
import os
#endif

/// Shared plain HTTP GET used by both `Ts11RegistryClient` and
/// `Ts11CredentialDiscovery` to fetch registry/schema/document bodies: 10s
/// timeout, `Accept: application/json`, 200-only success. Each caller keeps
/// its own log category/wording (via `logCategory`/`logPrefix`) so log
/// filtering by category is unaffected by sharing this implementation.
func ts11FetchWithUrlSession(
    _ urlString: String,
    logCategory: String,
    logPrefix: String
) async -> String? {
    guard let url = URL(string: urlString) else { return nil }
    var request = URLRequest(url: url)
    request.httpMethod = "GET"
    request.timeoutInterval = 10
    request.setValue("application/json", forHTTPHeaderField: "Accept")

    do {
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
            #if canImport(os)
            let statusCode = (response as? HTTPURLResponse)?.statusCode ?? -1
            Logger(subsystem: "org.siros.sdk", category: logCategory)
                .warning("\(logPrefix) failed: \(statusCode) from \(urlString)")
            #endif
            return nil
        }
        return String(data: data, encoding: .utf8)
    } catch {
        #if canImport(os)
        Logger(subsystem: "org.siros.sdk", category: logCategory)
            .warning("\(logPrefix) error from \(urlString): \(error.localizedDescription)")
        #endif
        return nil
    }
}

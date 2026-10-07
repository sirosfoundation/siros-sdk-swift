// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(Glibc)
import Glibc
#endif

/// Which hosts a document referenced by attacker-influenced metadata may be
/// fetched from: public, routable addresses only. Refuses loopback, private,
/// link-local, shared-address, documentation, multicast and reserved ranges,
/// IP literals in those ranges, and names that cannot be public (single-label,
/// `localhost`, `.local`, `.internal`, ...), for the name itself and for
/// every address it resolves to.
///
/// Limits: the check happens before the connection, so a name that resolves
/// differently a moment later (DNS rebinding) is not caught here; redirects are
/// refused outright by the fetcher so a redirect cannot be used to reach a
/// private address either.
public enum PublicHostPolicy {
    /// Resolves a host name to its addresses (textual), empty when it does not resolve.
    public typealias Resolver = @Sendable (String) async -> [String]

    static let blockedSuffixes = [".localhost", ".local", ".internal", ".home.arpa", ".lan", ".corp", ".intranet"]

    /// Whether `host` (a URL host component) is acceptable, resolving names with `resolver`.
    public static func isAllowed(host rawHost: String, resolver: Resolver = systemResolver) async -> Bool {
        var host = rawHost.lowercased()
        if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        guard !host.isEmpty else { return false }
        if let literal = parseAddress(host) { return isPublic(literal) }
        // A name: must look public, and everything it resolves to must be public.
        guard host.contains("."), !host.hasSuffix("."), host != "localhost",
              !blockedSuffixes.contains(where: { host.hasSuffix($0) }) else { return false }
        let addresses = await resolver(host)
        guard !addresses.isEmpty else { return false }
        for text in addresses {
            guard let address = parseAddress(text), isPublic(address) else { return false }
        }
        return true
    }

    // MARK: Addresses

    enum Address: Equatable {
        case v4([UInt8])    // 4 bytes
        case v6([UInt8])    // 16 bytes
    }

    static func parseAddress(_ text: String) -> Address? {
        var v4 = in_addr()
        if inet_pton(AF_INET, text, &v4) == 1 {
            return .v4(withUnsafeBytes(of: &v4) { Array($0) })
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, text, &v6) == 1 {
            return .v6(withUnsafeBytes(of: &v6) { Array($0) })
        }
        return nil
    }

    static func isPublic(_ address: Address) -> Bool {
        switch address {
        case .v4(let b): return isPublicV4(b)
        case .v6(let b): return isPublicV6(b)
        }
    }

    private static func isPublicV4(_ b: [UInt8]) -> Bool {
        let (a, c) = (b[0], b[1])
        switch a {
        case 0, 10, 127: return false
        case 100 where (64...127).contains(c): return false
        case 169 where c == 254: return false
        case 172 where (16...31).contains(c): return false
        case 192 where c == 168: return false
        case 192 where c == 0 && (b[2] == 0 || b[2] == 2): return false
        case 192 where c == 88 && b[2] == 99: return false
        case 198 where c == 18 || c == 19: return false
        case 198 where c == 51 && b[2] == 100: return false
        case 203 where c == 0 && b[2] == 113: return false
        case 224...255: return false
        default: return true
        }
    }

    private static func isPublicV6(_ b: [UInt8]) -> Bool {
        if b.allSatisfy({ $0 == 0 }) { return false }                              // ::
        if b[0..<15].allSatisfy({ $0 == 0 }) && b[15] == 1 { return false }        // ::1
        if b[0..<10].allSatisfy({ $0 == 0 }) && b[10] == 0xff && b[11] == 0xff {   // ::ffff:a.b.c.d
            return isPublicV4(Array(b[12..<16]))
        }
        if b[0..<12].allSatisfy({ $0 == 0 }) { return false }                      // deprecated IPv4-compatible
        if b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b {          // 64:ff9b::/96 NAT64
            return isPublicV4(Array(b[12..<16]))
        }
        if (b[0] & 0xfe) == 0xfc { return false }                                  // fc00::/7
        if b[0] == 0xfe && (b[1] & 0xc0) == 0x80 { return false }                  // fe80::/10
        if b[0] == 0xfe && (b[1] & 0xc0) == 0xc0 { return false }                  // fec0::/10 (site-local)
        if b[0] == 0xff { return false }                                           // multicast
        if b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8 { return false } // documentation
        if b[0] == 0x20 && b[1] == 0x02 { return isPublicV4(Array(b[2..<6])) }     // 6to4
        if b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x00 && b[3] == 0x00 { return isPublicV4(Array(b[12..<16].map { $0 ^ 0xff })) } // Teredo
        return true
    }

    // MARK: System resolution

    /// Resolves with `getaddrinfo` off the calling task's thread.
    public static let systemResolver: Resolver = { host in
        await withCheckedContinuation { (continuation: CheckedContinuation<[String], Never>) in
            DispatchQueue.global().async {
                var hints = addrinfo()
                hints.ai_family = AF_UNSPEC
                hints.ai_socktype = Int32(SOCK_STREAM.rawValue)
                var result: UnsafeMutablePointer<addrinfo>?
                guard getaddrinfo(host, nil, &hints, &result) == 0, let first = result else {
                    continuation.resume(returning: [])
                    return
                }
                defer { freeaddrinfo(result) }
                var found: [String] = []
                var cursor: UnsafeMutablePointer<addrinfo>? = first
                while let info = cursor {
                    var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    if getnameinfo(info.pointee.ai_addr, info.pointee.ai_addrlen, &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0 {
                        found.append(String(cString: buffer))
                    }
                    cursor = info.pointee.ai_next
                }
                continuation.resume(returning: found)
            }
        }
    }
}

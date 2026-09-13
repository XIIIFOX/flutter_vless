import Foundation
import Darwin
import dnssd
import flutter_vless_macos_privacy

/// Used only for VPN transport endpoints, before virtual DNS is installed.
/// mDNSResponder can be blocked while includeAllNetworks is starting on macOS.
/// Bound and cancel that lookup, then use the tunnel's DNS upstream over HTTPS
/// from the provider process. Never turn off protection to bootstrap a tunnel.
enum TunnelEndpointResolver {
    static func resolveIPv4(_ host: String,
                            event: (NativeDiagnosticMessage) -> Void = { _ in }) async throws -> String? {
        try await resolveIPv4(host, system: {
            try await SystemEndpointLookup.resolve($0, timeout: 2)
        }, fallback: { try await encryptedLookup($0) }, event: event)
    }

    static func resolveIPv4(_ host: String,
                            system: (String) async throws -> String?,
                            fallback: (String) async throws -> String?,
                            event: (NativeDiagnosticMessage) -> Void = { _ in }) async throws -> String? {
        try Task.checkCancellation()
        if let address = try await system(host) { return address }
        try Task.checkCancellation()
        // Never disclose local/single-label names to a public bootstrap resolver.
        guard isPublicHostname(host) else { return nil }
        event("System endpoint DNS unavailable; trying encrypted endpoint bootstrap")
        do {
            let address = try await fallback(host)
            try Task.checkCancellation()
            if address != nil { event("Encrypted endpoint bootstrap completed") }
            return address
        } catch {
            try Task.checkCancellation()
            if error is CancellationError { throw error }
            event("Encrypted endpoint bootstrap unavailable")
            return nil
        }
    }

    static func encryptedLookup(_ host: String) async throws -> String? {
        guard isPublicHostname(host) else { return nil }
        // An IP URL avoids recursively asking the unavailable system resolver.
        // Use normal platform certificate validation, no trust overrides.
        var url = URLComponents(string: "https://1.1.1.1/dns-query")!
        url.queryItems = [URLQueryItem(name: "name", value: host), URLQueryItem(name: "type", value: "A")]
        var request = URLRequest(url: url.url!, timeoutInterval: 5)
        request.setValue("application/dns-json", forHTTPHeaderField: "Accept")
        request.cachePolicy = .reloadIgnoringLocalCacheData
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 5
        configuration.timeoutIntervalForResource = 5
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.connectionProxyDictionary = [:]
        let session = URLSession(configuration: configuration, delegate: NoRedirects(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        let (bytes, response) = try await session.bytes(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200,
              http.mimeType == "application/dns-json" else { return nil }
        var data = Data()
        for try await byte in bytes {
            guard data.count < 65_536 else { return nil }
            data.append(byte)
        }
        return address(in: data, for: host)
    }

    static func address(in data: Data, for host: String) -> String? {
        guard data.count <= 65_536,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              json["Status"] as? Int == 0,
              json["TC"] as? Bool != true,
              let questions = json["Question"] as? [[String: Any]], questions.count == 1,
              questions[0]["type"] as? Int == 1,
              canonical(questions[0]["name"] as? String ?? "") == canonical(host),
              let answers = json["Answer"] as? [[String: Any]] else { return nil }
        var name = canonical(host)
        var seen = Set<String>()
        for _ in 0..<16 {
            guard seen.insert(name).inserted else { return nil }
            let matching = answers.filter { canonical($0["name"] as? String ?? "") == name }
            if let cname = matching.first(where: { $0["type"] as? Int == 5 })?["data"] as? String {
                name = canonical(cname)
                continue
            }
            for answer in matching where answer["type"] as? Int == 1 {
                guard let value = answer["data"] as? String else { continue }
                var address = in_addr()
                if value.withCString({ inet_pton(AF_INET, $0, &address) }) == 1 { return value }
            }
            return nil
        }
        return nil
    }

    private static func canonical(_ host: String) -> String {
        (host.hasSuffix(".") ? String(host.dropLast()) : host).lowercased()
    }

    static func isPublicHostname(_ host: String) -> Bool {
        let name = canonical(host)
        guard name.utf8.count <= 253, name.contains("."),
              name.utf8.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 46 }),
              name.split(separator: ".", omittingEmptySubsequences: false).allSatisfy({
                  !$0.isEmpty && $0.utf8.count <= 63 && !$0.hasPrefix("-") && !$0.hasSuffix("-")
              }) else { return false }
        return !["local", "localhost", "internal", "home.arpa", "test", "invalid", "example"].contains {
            name == $0 || name.hasSuffix("." + $0)
        }
    }

    private final class NoRedirects: NSObject, URLSessionTaskDelegate {
        func urlSession(_ session: URLSession, task: URLSessionTask,
                        willPerformHTTPRedirection response: HTTPURLResponse,
                        newRequest request: URLRequest,
                        completionHandler: @escaping (URLRequest?) -> Void) {
            completionHandler(nil)
        }
    }
}

/// DNSServiceRef has an explicit cancellation API; getaddrinfo does not.
/// All reference access/deallocation stays on its registered serial queue.
final class SystemEndpointLookup: @unchecked Sendable {
    private let queue = DispatchQueue(label: "dev.tfox.flutter-vless.endpoint-dns")
    private var service: DNSServiceRef?
    private var continuation: CheckedContinuation<String?, Error>?
    private var timer: DispatchWorkItem?
    private var cancelled = false

    static func resolve(_ host: String, timeout: TimeInterval) async throws -> String? {
        let lookup = SystemEndpointLookup()
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
                lookup.queue.async { lookup.start(host, timeout: timeout, continuation: continuation) }
            }
        } onCancel: {
            lookup.queue.async {
                lookup.cancelled = true
                lookup.finish(.failure(CancellationError()))
            }
        }
    }

    private func start(_ host: String, timeout: TimeInterval,
                       continuation: CheckedContinuation<String?, Error>) {
        self.continuation = continuation
        guard !cancelled else { finish(.failure(CancellationError())); return }
        let status = DNSServiceGetAddrInfo(&service, DNSServiceFlags(kDNSServiceFlagsTimeout), 0,
            DNSServiceProtocol(kDNSServiceProtocol_IPv4), host, { _, flags, _, error, _, address, _, context in
                guard let context else { return }
                let lookup = Unmanaged<SystemEndpointLookup>.fromOpaque(context).takeUnretainedValue()
                guard error == kDNSServiceErr_NoError else { lookup.finish(.success(nil)); return }
                guard flags & DNSServiceFlags(kDNSServiceFlagsAdd) != 0,
                      let address, address.pointee.sa_family == sa_family_t(AF_INET) else { return }
                var ip = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
                var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                guard inet_ntop(AF_INET, &ip, &buffer, socklen_t(buffer.count)) != nil else { return }
                lookup.finish(.success(String(cString: buffer)))
            }, Unmanaged.passUnretained(self).toOpaque())
        guard status == kDNSServiceErr_NoError, let service,
              DNSServiceSetDispatchQueue(service, queue) == kDNSServiceErr_NoError else {
            finish(.success(nil)); return
        }
        let timeoutWork = DispatchWorkItem { [self] in finish(.success(nil)) }
        timer = timeoutWork
        queue.asyncAfter(deadline: .now() + max(0, timeout), execute: timeoutWork)
    }

    private func finish(_ result: Result<String?, Error>) {
        guard let continuation else { return }
        self.continuation = nil
        timer?.cancel()
        timer = nil
        if let service { DNSServiceRefDeallocate(service); self.service = nil }
        continuation.resume(with: result)
    }
}

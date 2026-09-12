import Foundation
import Security
import Darwin

/// Uses an explicitly authenticated socket: CFNetwork's SOCKS dictionary offers
/// noauth even with credentials. There is no origin connection or auth fallback.
public enum LocalProxyDelayClient {
    public static func measure(url: URL, port: Int, credentials: LocalProxyCredentials?,
                               proxyProtocol: String = "socks", completion: @escaping (Int64) -> Void) {
        DispatchQueue.global(qos: .utility).async {
            completion(measureResponse(url: url, port: port, credentials: credentials, proxyProtocol: proxyProtocol))
        }
    }

    private static func measureResponse(url: URL, port: Int, credentials: LocalProxyCredentials?, proxyProtocol: String) -> Int64 {
        guard let scheme = url.scheme?.lowercased(), ["http", "https"].contains(scheme),
              let rawHost = url.host, !rawHost.isEmpty, url.user == nil, url.password == nil,
              (1...65535).contains(port), ["socks", "http"].contains(proxyProtocol),
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return -1 }
        let host = rawHost.hasPrefix("[") && rawHost.hasSuffix("]") ? String(rawHost.dropFirst().dropLast()) : rawHost
        let destinationPort = url.port ?? (scheme == "https" ? 443 : 80)
        let start = DispatchTime.now().uptimeNanoseconds
        do {
            let fd: Int32
            if proxyProtocol == "http" {
                fd = try LocalHTTPProxyClient.openConnection(proxyPort: port, credentials: credentials,
                    host: host, port: destinationPort, timeout: 8)
            } else {
                fd = try LocalSOCKS5Client.openConnection(proxyPort: port, credentials: credentials,
                    host: host, port: destinationPort, timeout: 8)
            }
            defer { close(fd) }
            let connection = LocalProxyTLSConnection(fd: fd, deadline: start + 10_000_000_000)
            if scheme == "https", !connection.startTLS(host: host) { return -1 }
            let path = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
            let target = path + (components.percentEncodedQuery.map { "?" + $0 } ?? "")
            let authority = (host.contains(":") ? "[\(host)]" : host) + (url.port.map { ":\($0)" } ?? "")
            guard ![target, authority].contains(where: { $0.contains("\r") || $0.contains("\n") }) else { return -1 }
            let request = Array("GET \(target) HTTP/1.1\r\nHost: \(authority)\r\nConnection: close\r\nUser-Agent: flutter-vless-delay\r\n\r\n".utf8)
            guard connection.write(request) else { return -1 }
            // Bounded response headers suffice; no cookies, credential storage, redirects or body buffering.
            var bytes: [UInt8] = []
            while bytes.count < 16_384, let next = connection.read(maxCount: min(2048, 16_384 - bytes.count)) {
                bytes.append(contentsOf: next)
                guard let end = bytes.firstIndex(of: 10) else { continue }
                let fields = String(decoding: bytes[...end], as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines).split(separator: " ")
                guard fields.count >= 2, fields[0] == "HTTP/1.1" || fields[0] == "HTTP/1.0",
                      let status = Int(fields[1]), (200...399).contains(status) else { return -1 }
                return Int64(max(1, (DispatchTime.now().uptimeNanoseconds - start) / 1_000_000))
            }
            return -1
        } catch { return -1 }
    }
}

/// TLS wraps only the authenticated FD; trust and hostname are checked before
/// HTTP bytes. SecureTransport remains available on iOS 15 and supports TLS 1.2.
private final class LocalProxyTLSConnection {
    let fd: Int32
    let deadline: UInt64
    private var tls: SSLContext?

    init(fd: Int32, deadline: UInt64) { self.fd = fd; self.deadline = deadline }
    private var withinDeadline: Bool { DispatchTime.now().uptimeNanoseconds < deadline }

    func startTLS(host: String) -> Bool {
        guard let context = SSLCreateContext(kCFAllocatorDefault, .clientSide, .streamType) else { return false }
        tls = context
        guard SSLSetIOFuncs(context, { connection, data, size in
            return Unmanaged<LocalProxyTLSConnection>.fromOpaque(connection).takeUnretainedValue().transportRead(data, size)
        }, { connection, data, size in
            return Unmanaged<LocalProxyTLSConnection>.fromOpaque(connection).takeUnretainedValue().transportWrite(data, size)
        }) == errSecSuccess,
        SSLSetConnection(context, Unmanaged.passUnretained(self).toOpaque()) == errSecSuccess,
        SSLSetProtocolVersionMin(context, .tlsProtocol12) == errSecSuccess,
        SSLSetSessionOption(context, .breakOnServerAuth, true) == errSecSuccess,
        host.withCString({ SSLSetPeerDomainName(context, $0, host.utf8.count) }) == errSecSuccess else { return false }
        var authenticated = false
        while withinDeadline {
            let result = SSLHandshake(context)
            if result == errSSLPeerAuthCompleted {
                var trust: SecTrust?
                guard SSLCopyPeerTrust(context, &trust) == errSecSuccess, let trust,
                      SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, host as CFString)) == errSecSuccess,
                      SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess,
                      SecTrustEvaluateWithError(trust, nil) else { return false }
                authenticated = true
            } else if result == errSecSuccess { return authenticated }
            else if result != errSSLWouldBlock { return false }
        }
        return false
    }

    func write(_ bytes: [UInt8]) -> Bool {
        guard withinDeadline else { return false }
        guard let tls else { return LocalSOCKS5Client.sendAll(fd: fd, bytes: bytes) }
        var offset = 0
        while offset < bytes.count, withinDeadline {
            var count = 0
            let status = bytes.withUnsafeBytes { SSLWrite(tls, $0.baseAddress!.advanced(by: offset), bytes.count - offset, &count) }
            offset += count
            guard status == errSecSuccess || status == errSSLWouldBlock else { return false }
        }
        return offset == bytes.count
    }

    func read(maxCount: Int) -> [UInt8]? {
        while withinDeadline {
            var bytes = [UInt8](repeating: 0, count: maxCount)
            var count = 0
            if let tls {
                let status = bytes.withUnsafeMutableBytes { SSLRead(tls, $0.baseAddress!, maxCount, &count) }
                if count > 0 { return Array(bytes.prefix(count)) }
                guard status == errSecSuccess || status == errSSLWouldBlock else { return nil }
            } else {
                count = bytes.withUnsafeMutableBytes { recv(fd, $0.baseAddress, maxCount, 0) }
                if count > 0 { return Array(bytes.prefix(count)) }
                guard count < 0 && errno == EINTR else { return nil }
            }
        }
        return nil
    }

    private func transportRead(_ data: UnsafeMutableRawPointer, _ size: UnsafeMutablePointer<Int>) -> OSStatus {
        guard withinDeadline else { size.pointee = 0; return errSSLClosedAbort }
        let requested = size.pointee
        let count = recv(fd, data, requested, 0)
        size.pointee = max(0, count)
        if count > 0 { return count == requested ? errSecSuccess : errSSLWouldBlock }
        if count == 0 { return errSSLClosedGraceful }
        return errno == EINTR ? errSSLWouldBlock : errSSLClosedAbort
    }

    private func transportWrite(_ data: UnsafeRawPointer, _ size: UnsafeMutablePointer<Int>) -> OSStatus {
        guard withinDeadline else { size.pointee = 0; return errSSLClosedAbort }
        let requested = size.pointee
        let count = send(fd, data, requested, MSG_NOSIGNAL)
        size.pointee = max(0, count)
        if count > 0 { return count == requested ? errSecSuccess : errSSLWouldBlock }
        return errno == EINTR ? errSSLWouldBlock : errSSLClosedAbort
    }
}

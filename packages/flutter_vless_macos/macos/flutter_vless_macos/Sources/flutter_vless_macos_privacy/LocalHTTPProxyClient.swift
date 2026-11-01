import Foundation
import Darwin

/// CONNECT credentials are consumed by the loopback proxy before any origin
/// request is sent. The established socket is then used for HTTP or TLS.
public final class LocalHTTPProxyClient: @unchecked Sendable {
    private let port: Int
    private let credentials: LocalProxyCredentials?

    public init(port: Int, credentials: LocalProxyCredentials?) {
        self.port = port
        self.credentials = credentials
    }

    public func measure(url: URL) async throws -> Int64 {
        let delay: Int64 = await withCheckedContinuation { continuation in
            LocalProxyDelayClient.measure(url: url, port: port, credentials: credentials,
                                          proxyProtocol: "http") {
                continuation.resume(returning: $0)
            }
        }
        guard delay >= 0 else { throw URLError(.cannotConnectToHost) }
        return delay
    }

    public static func connectRequest(host: String, port: Int, credentials: LocalProxyCredentials?) throws -> [UInt8] {
        guard (1...65535).contains(port), !host.isEmpty, host.utf8.count <= 255,
              host.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7f && ![47, 64, 92].contains($0) }) else {
            throw LocalSOCKS5Client.Failure.invalidDestination
        }
        let authority = host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
        var request = "CONNECT \(authority) HTTP/1.1\r\nHost: \(authority)\r\n"
        if let credentials {
            let token = Data("\(credentials.username):\(credentials.password)".utf8).base64EncodedString()
            request += "Proxy-Authorization: Basic \(token)\r\n"
        }
        return Array((request + "\r\n").utf8)
    }

    public static func openConnection(proxyPort: Int, credentials: LocalProxyCredentials?, host: String,
                                      port: Int, timeout: TimeInterval = 8, budget: LocalProxyIOBudget? = nil) throws -> Int32 {
        let phase = (budget ?? LocalProxyIOBudget(timeout: timeout)).limited(to: timeout)
        let request = try connectRequest(host: host, port: port, credentials: credentials)
        guard (1...65535).contains(proxyPort), phase.canContinue else { throw LocalSOCKS5Client.Failure.invalidDestination }
        let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else { throw LocalSOCKS5Client.Failure.connect }
        do {
            var duration = timeval(tv_sec: Int(timeout), tv_usec: 0)
            var noSignal: Int32 = 1
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &duration, socklen_t(MemoryLayout<timeval>.size))
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &duration, socklen_t(MemoryLayout<timeval>.size))
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            address.sin_port = UInt16(proxyPort).bigEndian
            inet_pton(AF_INET, "127.0.0.1", &address.sin_addr)
            let flags = fcntl(fd, F_GETFL)
            guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { throw LocalSOCKS5Client.Failure.connect }
            let connected = withUnsafePointer(to: &address, { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            })
            if connected != 0 {
                guard [EINPROGRESS, EALREADY, EINTR].contains(errno), waitForConnect(fd: fd, budget: phase) else {
                    throw LocalSOCKS5Client.Failure.connect
                }
            }
            guard phase.canContinue, fcntl(fd, F_SETFL, flags) == 0,
                  LocalSOCKS5Client.sendAll(fd: fd, bytes: request, budget: phase) else { throw LocalSOCKS5Client.Failure.request }
            var header: [UInt8] = []
            while header.count < 8192 && !header.suffix(4).elementsEqual([13, 10, 13, 10]) {
                guard let byte = LocalSOCKS5Client.receiveExactly(fd: fd, count: 1, budget: phase) else {
                    throw LocalSOCKS5Client.Failure.request
                }
                header += byte
            }
            guard header.suffix(4).elementsEqual([13, 10, 13, 10]),
                  let line = String(bytes: header, encoding: .ascii)?.components(separatedBy: "\r\n").first,
                  line.hasPrefix("HTTP/1.1 200 ") || line.hasPrefix("HTTP/1.0 200 ") else {
                throw LocalSOCKS5Client.Failure.authentication
            }
            return fd
        } catch {
            close(fd)
            throw error
        }
    }

    private static func waitForConnect(fd: Int32, budget: LocalProxyIOBudget) -> Bool {
        while budget.canContinue {
            let milliseconds = budget.waitMilliseconds()
            guard milliseconds > 0 else { return false }
            var descriptor = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            let result = Darwin.poll(&descriptor, 1, milliseconds)
            guard budget.canContinue else { return false }
            if result > 0 {
                var error: Int32 = 0, size = socklen_t(MemoryLayout<Int32>.size)
                return descriptor.revents & Int16(POLLNVAL) == 0
                    && getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0 && error == 0
            }
            if result < 0 && errno != EINTR { return false }
        }
        return false
    }
}

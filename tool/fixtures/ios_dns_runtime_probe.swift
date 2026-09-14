// Controlled DNS upstream through the actual bundled iOS Xray. All listeners
// bind to localhost; no NetworkExtension or host routes/DNS are configured.
private func dnsProbeSocket(_ port: Int, type: Int32 = SOCK_STREAM) -> Int32 {
    let fd = socket(AF_INET, type, 0)
    precondition(fd >= 0)
    var yes: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, socklen_t(MemoryLayout<Int32>.size))
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = UInt16(port).bigEndian
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr)
    precondition(withUnsafePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
    } == 0)
    if type == SOCK_STREAM { precondition(listen(fd, 16) == 0) }
    return fd
}

private func dnsProbeTimeout(_ fd: Int32, seconds: Int = 3) {
    var timeout = timeval(tv_sec: seconds, tv_usec: 0)
    var yes: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, socklen_t(MemoryLayout<Int32>.size))
}

private final class DNSDirectFallbackTrap: @unchecked Sendable {
    private let tcp: Int32
    private let udp: Int32
    private let lock = NSLock()
    private var hits = 0
    init(port: Int) {
        tcp = dnsProbeSocket(port)
        udp = dnsProbeSocket(port, type: SOCK_DGRAM)
        DispatchQueue.global().async { [self] in
            while true {
                let client = accept(tcp, nil, nil)
                guard client >= 0 else { return }
                lock.lock(); hits += 1; lock.unlock()
                close(client)
            }
        }
        DispatchQueue.global().async { [self] in
            var bytes = [UInt8](repeating: 0, count: 4096)
            while recv(udp, &bytes, bytes.count, 0) > 0 {
                lock.lock(); hits += 1; lock.unlock()
            }
        }
    }
    func stop() { for fd in [tcp, udp] { shutdown(fd, SHUT_RDWR); close(fd) } }
    func count() -> Int { lock.lock(); defer { lock.unlock() }; return hits }
}

private final class DNSControlledProxy: @unchecked Sendable {
    enum Response { case answer, servfail, refuseConnection }
    private let fd: Int32
    private let proto: String
    private let lock = NSLock()
    private var response: Response = .answer
    private var queries = 0
    private var failure: String?

    init(port: Int, proto: String) {
        fd = dnsProbeSocket(port)
        self.proto = proto
        DispatchQueue.global().async { [self] in
            while true {
                let client = accept(fd, nil, nil)
                guard client >= 0 else { return }
                DispatchQueue.global().async { [self] in serve(client) }
            }
        }
    }
    func stop() { shutdown(fd, SHUT_RDWR); close(fd) }
    func mode(_ next: Response) { lock.lock(); response = next; lock.unlock() }
    func state() -> (Int, String?) { lock.lock(); defer { lock.unlock() }; return (queries, failure) }
    private func fail(_ message: String) { lock.lock(); failure = message; lock.unlock() }

    private func serve(_ client: Int32) {
        defer { close(client) }
        dnsProbeTimeout(client)
        lock.lock(); let mode = response; lock.unlock()
        if proto == "http" {
            var request: [UInt8] = []
            while request.count < 8192 && !request.suffix(4).elementsEqual([13, 10, 13, 10]) {
                guard let byte = LocalSOCKS5Client.receiveExactly(fd: client, count: 1) else { return fail("HTTP header missing") }
                request += byte
            }
            let text = String(decoding: request, as: UTF8.self)
            let token = Data("remote-dns-user:remote-dns-password".utf8).base64EncodedString()
            guard text.hasPrefix("CONNECT 1.1.1.1:53 HTTP/1.1"), text.contains("Proxy-Authorization: Basic \(token)") else {
                return fail("HTTP upstream destination/auth mismatch")
            }
            let reply = mode == .refuseConnection ? "HTTP/1.1 502 Bad Gateway\r\n\r\n" : "HTTP/1.1 200 Connection Established\r\n\r\n"
            _ = LocalSOCKS5Client.sendAll(fd: client, bytes: Array(reply.utf8))
            if mode == .refuseConnection { return }
        } else {
            guard let greeting = LocalSOCKS5Client.receiveExactly(fd: client, count: 2), greeting[0] == 5,
                  let methods = LocalSOCKS5Client.receiveExactly(fd: client, count: Int(greeting[1])), methods.contains(2) else {
                return fail("SOCKS upstream greeting mismatch")
            }
            _ = LocalSOCKS5Client.sendAll(fd: client, bytes: [5, 2])
            guard let auth = LocalSOCKS5Client.receiveExactly(fd: client, count: 2), auth[0] == 1,
                  let user = LocalSOCKS5Client.receiveExactly(fd: client, count: Int(auth[1])),
                  let passLength = LocalSOCKS5Client.receiveExactly(fd: client, count: 1),
                  let pass = LocalSOCKS5Client.receiveExactly(fd: client, count: Int(passLength[0])),
                  String(decoding: user, as: UTF8.self) == "remote-dns-user",
                  String(decoding: pass, as: UTF8.self) == "remote-dns-password" else { return fail("Remote credentials changed") }
            _ = LocalSOCKS5Client.sendAll(fd: client, bytes: [1, 0])
            guard LocalSOCKS5Client.receiveExactly(fd: client, count: 10) == [5, 1, 0, 1, 1, 1, 1, 1, 0, 53] else {
                return fail("DNS was not TCP CONNECT to upstream resolver")
            }
            _ = LocalSOCKS5Client.sendAll(fd: client, bytes: [5, mode == .refuseConnection ? 5 : 0, 0, 1, 127, 0, 0, 1, 0, 53])
            if mode == .refuseConnection { return }
        }
        guard let length = LocalSOCKS5Client.receiveExactly(fd: client, count: 2) else { return fail("Missing TCP DNS frame") }
        let size = Int(length[0]) * 256 + Int(length[1])
        guard (12...4096).contains(size), var query = LocalSOCKS5Client.receiveExactly(fd: client, count: size) else {
            return fail("Invalid TCP DNS query")
        }
        lock.lock(); queries += 1; lock.unlock()
        query[2] = 0x81
        query[3] = mode == .servfail ? 0x82 : 0x80
        query[6] = 0; query[7] = mode == .servfail ? 0 : 1
        query[8] = 0; query[9] = 0; query[10] = 0; query[11] = 0
        if mode == .answer {
            let type = Array(query.suffix(4).prefix(2))
            let data: [UInt8] = type == [0, 28]
                ? [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 73]
                : [198, 51, 100, 73]
            query += [0xc0, 0x0c] + type + [0, 1, 0, 0, 0, 60, 0, UInt8(data.count)] + data
        }
        _ = LocalSOCKS5Client.sendAll(fd: client, bytes: [UInt8(query.count >> 8), UInt8(query.count & 255)] + query)
    }
}

private func dnsProbeQuery(id: UInt16, type: UInt16 = 1) -> [UInt8] {
    var bytes: [UInt8] = [UInt8(id >> 8), UInt8(id & 255), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]
    for label in ["dns-proof", "invalid"] { bytes += [UInt8(label.utf8.count)] + Array(label.utf8) }
    return bytes + [0, UInt8(type >> 8), UInt8(type & 255), 0, 1]
}

private func queryVirtualDNS(credentials: LocalProxyCredentials, udp: Bool, id: UInt16, type: UInt16 = 1) throws -> [UInt8]? {
    let query = dnsProbeQuery(id: id, type: type)
    if !udp {
        let fd = try LocalSOCKS5Client.openConnection(proxyPort: 18098, credentials: credentials, host: TunnelDNSPolicy.virtualServer, port: 53, timeout: 3)
        defer { close(fd) }
        _ = LocalSOCKS5Client.sendAll(fd: fd, bytes: [0, UInt8(query.count)] + query)
        guard let size = LocalSOCKS5Client.receiveExactly(fd: fd, count: 2) else { return nil }
        return LocalSOCKS5Client.receiveExactly(fd: fd, count: Int(size[0]) * 256 + Int(size[1]))
    }
    let control = openLoopback(18098)
    defer { close(control) }
    precondition(LocalSOCKS5Client.authenticate(fd: control, credentials: credentials))
    _ = LocalSOCKS5Client.sendAll(fd: control, bytes: [5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
    guard let relay = LocalSOCKS5Client.receiveExactly(fd: control, count: 10), relay.prefix(4).elementsEqual([5, 0, 0, 1]) else {
        preconditionFailure("Authenticated UDP ASSOCIATE failed")
    }
    let fd = socket(AF_INET, SOCK_DGRAM, 0)
    defer { close(fd) }
    dnsProbeTimeout(fd, seconds: 2)
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = (UInt16(relay[8]) * 256 + UInt16(relay[9])).bigEndian
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr)
    let bytes: [UInt8] = [0, 0, 0, 1, 198, 18, 0, 2, 0, 53] + query
    let sent = bytes.withUnsafeBytes { buffer in
        withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            sendto(fd, buffer.baseAddress, bytes.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        } }
    }
    precondition(sent == bytes.count)
    var response = [UInt8](repeating: 0, count: 4096)
    let received = recv(fd, &response, response.count, 0)
    guard received >= 22 else { return nil }
    precondition(response.prefix(4).elementsEqual([0, 0, 0, 1]))
    return Array(response[10..<received])
}

func runDNSRuntimeChecks() throws {
    let credentials = try LocalProxyCredentials(username: "dns-session-user", password: "dns-session-password")
    let trap = DNSDirectFallbackTrap(port: 18104)
    defer { trap.stop() }
    for proto in ["http", "socks"] {
        let upstream = DNSControlledProxy(port: 18103, proto: proto)
        defer { upstream.stop() }
        let raw: [String: Any] = [
            "inbounds": [["tag": "in_proxy", "protocol": "socks", "listen": "127.0.0.1", "port": 18098]],
            "outbounds": [
                ["tag": "direct", "protocol": "freedom", "settings": ["redirect": "127.0.0.1:18104"]],
                ["tag": "proxy", "protocol": proto, "settings": ["servers": [["address": "127.0.0.1", "port": 18103,
                    "users": [["user": "remote-dns-user", "pass": "remote-dns-password"]]]]]],
                ["tag": "block", "protocol": "blackhole"]],
            "routing": ["rules": [["type": "field", "network": "udp", "outboundTag": "direct"]]]]
        guard let prepared = TunnelXrayConfigPreparer.prepare(jsonData: try JSONSerialization.data(withJSONObject: raw), credentials: credentials) else {
            preconditionFailure("DNS fixture preparation failed")
        }
        for generation in 0..<2 {
            upstream.mode(.answer)
            var error: NSError?
            precondition(XRayStartPrivate(prepared.data, ProbeLogger(), &error))
            defer { XRayStop() }
            for udp in [false, true] {
                let id = UInt16(0x4300 + generation * 2 + (udp ? 1 : 0))
                guard let answer = try queryVirtualDNS(credentials: credentials, udp: udp, id: id) else {
                    print("DNS_QUERY_FAILED proto=\(proto) udp=\(udp) fixture=\(upstream.state().1 ?? "none")")
                    preconditionFailure("Virtual DNS did not return controlled answer")
                }
                precondition(answer.prefix(2).elementsEqual([UInt8(id >> 8), UInt8(id & 255)]))
                precondition(answer.suffix(4).elementsEqual([198, 51, 100, 73]))
                precondition(trap.count() == 0)
                // The OS-facing resolver must not advertise IPv6 destinations
                // that the packet tunnel deliberately cannot forward. Use
                // NODATA, not a timeout/NXDOMAIN that could also break A lookup.
                let queriesBeforeAAAA = upstream.state().0
                let ipv6ID = id + 0x100
                let ipv6 = try queryVirtualDNS(credentials: credentials, udp: udp, id: ipv6ID, type: 28)
                if ipv6 != dnsNoDataResponse(id: ipv6ID) {
                    print("DNS_IPV4_ONLY_FAILED=\(proto);UDP=\(udp);answerCount=\(ipv6.map { Int($0[6]) * 256 + Int($0[7]) } ?? -1)")
                    fflush(stdout)
                }
                precondition(ipv6 == dnsNoDataResponse(id: ipv6ID), "IPv4-only DNS must answer AAAA with NOERROR/NODATA")
                precondition(upstream.state().0 == queriesBeforeAAAA, "AAAA must not reach the upstream resolver")
            }
            XRayStop()
            print("DNS_RUNTIME_PASS=\(proto);GENERATION=\(generation)")
            print("DNS_IPV4_ONLY_PASS=\(proto);GENERATION=\(generation)")
        }
        var error: NSError?
        precondition(XRayStartPrivate(prepared.data, ProbeLogger(), &error))
        upstream.mode(.servfail)
        for udp in [false, true] {
            let answer = try queryVirtualDNS(credentials: credentials, udp: udp, id: udp ? 0x4501 : 0x4500)
            precondition(answer != nil && answer![3] & 15 == 2, "DNS SERVFAIL must not switch to another resolver")
        }
        upstream.mode(.refuseConnection)
        for udp in [false, true] {
            let answer = try? queryVirtualDNS(credentials: credentials, udp: udp, id: udp ? 0x4601 : 0x4600)
            precondition(answer == nil, "Proxy refusal must not fall back to a direct resolver")
        }
        XRayStop()
        let (count, failure) = upstream.state()
        precondition(count == 6 && failure == nil && trap.count() == 0)
        print("DNS_REFUSAL_NO_FALLBACK_PASS=\(proto)")
    }
}

private func dnsNoDataResponse(id: UInt16) -> [UInt8] {
    var response = dnsProbeQuery(id: id, type: 28)
    response[2] = 0x85 // response, authoritative, recursion desired
    response[3] = 0x80 // recursion available, NOERROR
    return response
}

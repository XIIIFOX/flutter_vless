// CI-only bundled SDK proof. The outer harness owns admission/deadline. This
// exercises authenticated SOCKS, not HEV or a NetworkExtension packet tunnel.
private let appleFakeDNSName = "apple-fakedns.invalid"
private func appleFakeDNSPayload(_ generation: Int, udp: Bool) -> [UInt8] {
    [0, 0xff, UInt8(generation), udp ? 0x75 : 0x74] + Array("opaque-sdk-proof".utf8)
}

private final class AppleFakeDNSUpstream: @unchecked Sendable {
    let port: Int
    private let tcp: Int32, udp: Int32
    private let state = NSCondition(), worker = DispatchGroup()
    private var stopped = false, closed = false, failed = false
    private var current: Int32 = -1, control: Int32 = -1
    private var generation = 0, tcpCount = 0, udpCount = 0, associations = 0

    init() {
        let listener = dnsProbeSocket(0)
        var address = sockaddr_in(), length = socklen_t(MemoryLayout<sockaddr_in>.size)
        precondition(withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(listener, $0, &length) }
        } == 0)
        tcp = listener
        port = Int(UInt16(bigEndian: address.sin_port))
        udp = dnsProbeSocket(port, type: SOCK_DGRAM)
        for fd in [tcp, udp] { precondition(fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) == 0) }
        worker.enter()
        DispatchQueue.global().async { [self] in defer { worker.leave() }; serve() }
    }
    private func fail() { state.lock(); failed = true; state.broadcast(); state.unlock() }
    private func release(_ fd: Int32) {
        state.lock()
        if current == fd { current = -1 }
        if control == fd { control = -1 }
        close(fd); state.broadcast(); state.unlock()
    }
    private func acceptOne() {
        let fd = accept(tcp, nil, nil)
        guard fd >= 0 else { if errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR { fail() }; return }
        state.lock()
        if stopped { close(fd); state.unlock(); return }
        current = fd; let activeGeneration = generation; state.unlock()
        var retained = false
        defer { if !retained { release(fd) } }
        // BSD accept may inherit O_NONBLOCK; existing exact reads are blocking.
        guard fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK) == 0 else { return fail() }
        dnsProbeTimeout(fd)
        guard LocalSOCKS5Client.receiveExactly(fd: fd, count: 3) == [5, 1, 0],
              LocalSOCKS5Client.sendAll(fd: fd, bytes: [5, 0]),
              let request = LocalSOCKS5Client.receiveExactly(fd: fd, count: 4),
              request[0] == 5, request[2] == 0 else { return fail() }
        if request[1] == 3 {
            guard request[3] == 1, LocalSOCKS5Client.receiveExactly(fd: fd, count: 6) == [0, 0, 0, 0, 0, 0] else { return fail() }
            state.lock()
            guard control == -1, !stopped else { state.unlock(); return fail() }
            control = fd; current = -1; associations += 1; retained = true; state.broadcast(); state.unlock()
            guard LocalSOCKS5Client.sendAll(fd: fd, bytes: [5, 0, 0, 1, 127, 0, 0, 1, UInt8(port >> 8), UInt8(port & 255)]) else { return fail() }
        } else {
            let name = Array(appleFakeDNSName.utf8)
            let expected = appleFakeDNSPayload(activeGeneration, udp: false)
            guard request[1] == 1, request[3] == 3,
                  LocalSOCKS5Client.receiveExactly(fd: fd, count: 1) == [UInt8(name.count)],
                  LocalSOCKS5Client.receiveExactly(fd: fd, count: name.count + 2) == name + [UInt8(18081 >> 8), UInt8(18081 & 255)],
                  LocalSOCKS5Client.sendAll(fd: fd, bytes: [5, 0, 0, 1, 127, 0, 0, 1, 0, 0]),
                  LocalSOCKS5Client.receiveExactly(fd: fd, count: expected.count) == expected,
                  LocalSOCKS5Client.sendAll(fd: fd, bytes: expected) else { return fail() }
            state.lock(); tcpCount += 1; state.unlock()
        }
    }
    private func datagram() {
        var peer = sockaddr_in(), length = socklen_t(MemoryLayout<sockaddr_in>.size)
        var bytes = [UInt8](repeating: 0, count: 4096)
        let count = withUnsafeMutablePointer(to: &peer) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(udp, &bytes, bytes.count, 0, $0, &length) }
        }
        if count < 0 { if errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR { fail() }; return }
        state.lock(); let live = control >= 0; let activeGeneration = generation; state.unlock()
        let name = Array(appleFakeDNSName.utf8)
        let expected: [UInt8] = [0, 0, 0, 3, UInt8(name.count)] + name + [UInt8(18082 >> 8), UInt8(18082 & 255)] + appleFakeDNSPayload(activeGeneration, udp: true)
        guard live, Array(bytes.prefix(count)) == expected else { return fail() }
        let sent = expected.withUnsafeBytes { buffer in
            withUnsafePointer(to: &peer) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                sendto(udp, buffer.baseAddress, expected.count, 0, $0, length)
            } }
        }
        guard sent == expected.count else { return fail() }
        state.lock(); udpCount += 1; state.unlock()
    }
    private func serve() {
        while true {
            state.lock(); let done = stopped; let association = control; state.unlock()
            if done { break }
            var descriptors = [pollfd(fd: tcp, events: Int16(POLLIN), revents: 0),
                               pollfd(fd: udp, events: Int16(POLLIN), revents: 0),
                               pollfd(fd: association, events: Int16(POLLIN), revents: 0)]
            let ready = poll(&descriptors, nfds_t(descriptors.count), 100)
            if ready < 0 { if errno == EINTR { continue }; fail(); break }
            if descriptors[2].revents != 0 && association >= 0 {
                var byte: UInt8 = 0
                let received = recv(association, &byte, 1, MSG_DONTWAIT)
                if received == 0 || (received < 0 && (errno == ECONNRESET || errno == EPIPE)) { release(association) }
                else if received > 0 || (received < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { fail() }
            }
            if descriptors[0].revents & Int16(POLLIN) != 0 { acceptOne() }
            if descriptors[1].revents & Int16(POLLIN) != 0 { datagram() }
            if descriptors[0...1].contains(where: { $0.revents & Int16(POLLERR | POLLNVAL) != 0 }) { fail(); break }
        }
        state.lock(); let remaining = control; state.unlock()
        if remaining >= 0 { release(remaining) }
    }
    func begin(_ next: Int) {
        state.lock(); defer { state.unlock() }
        precondition(!failed && current == -1 && control == -1 && tcpCount == next && udpCount == next && associations == next)
        generation = next
    }
    func requireIdle() {
        state.lock(); defer { state.unlock() }
        let deadline = Date(timeIntervalSinceNow: 3)
        while current >= 0 || control >= 0 {
            guard state.wait(until: deadline) else { preconditionFailure("FakeDNS upstream did not drain") }
        }
        precondition(!failed)
    }
    func stop() {
        state.lock()
        if closed { state.unlock(); return }
        stopped = true
        for fd in [current, control] where fd >= 0 { shutdown(fd, SHUT_RDWR) }
        state.unlock()
        precondition(worker.wait(timeout: .now() + 5) == .success, "FakeDNS worker did not stop")
        state.lock(); close(tcp); close(udp); closed = true; state.unlock()
    }
    func requireComplete() {
        state.lock(); defer { state.unlock() }
        precondition(closed && !failed && current == -1 && control == -1 && tcpCount == 2 && udpCount == 2 && associations == 2)
    }
}

func runAppleFakeDNSRuntimeChecks() throws {
    let upstream = AppleFakeDNSUpstream()
    defer { XRayStop(); upstream.stop() }
    let credentials = try LocalProxyCredentials(username: "fake-sdk-user", password: "fake-sdk-password")
    let dns: [String: Any] = ["queryStrategy": "UseIPv4", "servers": ["fakedns"]]
    let imported: [String: Any] = ["tag": "fake-caller", "protocol": "socks", "listen": "127.0.0.1", "port": 18095,
        "settings": ["auth": "noauth"], "sniffing": ["enabled": true, "routeOnly": false, "destOverride": ["tls"]]]
    let raw: [String: Any] = ["dns": dns, "inbounds": [imported],
        "outbounds": [["tag": "fake-proxy", "protocol": "socks", "settings": ["servers": [["address": "127.0.0.1", "port": upstream.port]]]],
                      ["tag": "fake-block", "protocol": "blackhole"]],
        "routing": ["rules": [["type": "field", "domain": ["full:" + appleFakeDNSName], "outboundTag": "fake-proxy"],
                              ["type": "field", "network": "tcp,udp", "outboundTag": "fake-block"]]]]
    let source = try JSONSerialization.data(withJSONObject: raw, options: [.sortedKeys])
    guard let prepared = TunnelXrayConfigPreparer.prepare(jsonData: source, credentials: credentials,
        resolveIPv4: { _ in preconditionFailure("Numeric FakeDNS proxy must not bootstrap") }) else { preconditionFailure("FakeDNS SDK preparation failed") }
    let effective = try JSONSerialization.jsonObject(with: prepared.data) as! [String: Any]
    precondition(effective["dns"] as! NSDictionary == dns as NSDictionary && effective["fakedns"] == nil)
    let inputs = effective["inbounds"] as! [[String: Any]], sniff = inputs[0]["sniffing"] as! [String: Any]
    precondition(inputs[1] as NSDictionary == imported as NSDictionary && sniff["routeOnly"] as? Bool == true)
    precondition((sniff["destOverride"] as! [String]).contains("fakedns"))
    let port = TunnelXrayConfigPreparer.parseConfig(jsonData: prepared.data)!.inboundPort
    for generation in 0..<2 {
        upstream.begin(generation)
        var error: NSError?
        precondition(XRayStartPrivate(prepared.data, ProbeLogger(), &error))
        var fake: [UInt8] = []
        for udp in [false, true] {
            let id = UInt16(0x7300 + generation * 2 + (udp ? 1 : 0))
            guard let answer = try queryVirtualDNS(proxyPort: port, credentials: credentials, udp: udp, id: id, name: appleFakeDNSName), answer.count >= 16 else { preconditionFailure("FakeDNS SDK query failed") }
            precondition(answer.prefix(2).elementsEqual([UInt8(id >> 8), UInt8(id & 255)]) && answer[3] & 15 == 0 && answer[6...7].elementsEqual([0, 1]))
            let address = Array(answer.suffix(4))
            precondition(address[0] == 198 && (address[1] == 18 || address[1] == 19))
            if fake.isEmpty { fake = address } else { precondition(fake == address) }
        }
        let host = fake.map(String.init).joined(separator: ".")
        let fd = try LocalSOCKS5Client.openConnection(proxyPort: port, credentials: credentials, host: host, port: 18081, timeout: 3)
        let payload = appleFakeDNSPayload(generation, udp: false)
        precondition(LocalSOCKS5Client.sendAll(fd: fd, bytes: payload))
        precondition(LocalSOCKS5Client.receiveExactly(fd: fd, count: payload.count) == payload)
        close(fd)
        let datagram = appleFakeDNSPayload(generation, udp: true)
        precondition(exchangeSOCKSUDP(proxyPort: port, credentials: credentials, host: host, port: 18082, payload: datagram) == datagram)
        XRayStop(); upstream.requireIdle()
    }
    upstream.stop(); upstream.requireComplete()
    let sourceAfter = try JSONSerialization.data(withJSONObject: raw, options: [.sortedKeys])
    precondition(sourceAfter == source)
    print("APPLE_FAKEDNS_SDK_PASS=2")
}

// CI-only actual optional factory proof. Existing outer harness owns the process
// deadline and admission guard; no OS tunnel, routes or preferences are changed.
func runNativeRoutingRuntimeChecks() throws {
    precondition(FLVlessCoreRoutingCapability() == 1, "Enabled routing runtime is required")
    let aliased = LocalProbeOrigin(port: 18096), fallback = LocalProbeOrigin(port: 18097)
    // The only configured upstream is TCP. A joined HTTP fixture records any
    // attempted connection without answering DNS; static hosts must avoid it.
    let trap = LocalProbeOrigin(port: 18104)
    // This owned TCP listener remains occupied across both source variants.
    guard let occupiedPort = (10808...10839).first(where: LocalProxyAccessPolicy.isTCPPortAvailable) else {
        preconditionFailure("No free port for the occupied listener fixture")
    }
    let occupied = LocalProbeOrigin(port: occupiedPort)
    defer { XRayStop(); aliased.stop(); fallback.stop(); trap.stop(); occupied.stop() }
    var assetError: NSError?
    precondition(XRaySetAssetLocation("", &assetError))
    let credentials = try LocalProxyCredentials(username: "routing-session-user", password: "routing-session-password")
    let expected = Array("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".utf8)
    for variant in 0..<2 {
        func stage(_ name: String) { print("NATIVE_ROUTING_STAGE=\(name);VARIANT=\(variant)") }
        stage("prepare")
        let sourceTag = variant == 0 ? "caller-source" : ""
        var sourceInput: [String: Any] = ["listen": "127.0.0.1", "port": 18095, "protocol": "socks", "settings": ["auth": "noauth", "udp": true]]
        if variant == 0 { sourceInput["tag"] = sourceTag }
        let dns: [String: Any] = ["queryStrategy": "UseIPv4", "hosts": ["dns-proof.invalid": "192.0.2.14", "fallback.invalid": "192.0.2.99"], "servers": ["tcp://127.0.0.1:18104"]]
        let raw: [String: Any] = ["inbounds": [sourceInput], "dns": dns,
            "outbounds": [["tag": "caller-block", "protocol": "blackhole"],
                ["tag": "alias-target", "protocol": "freedom", "settings": ["redirect": "127.0.0.1:18096"]],
                ["tag": "selected-default", "protocol": "freedom", "settings": ["redirect": "127.0.0.1:18097"]]],
            "routing": ["domainStrategy": "IPIfNonMatch", "rules": [
                ["type": "field", "inboundTag": [sourceTag], "ip": [TunnelDNSPolicy.virtualServer], "port": "53", "outboundTag": "caller-block"],
                ["type": "field", "inboundTag": [sourceTag], "domain": ["full:alias.invalid"], "outboundTag": "alias-target"]]]]
        let source = try JSONSerialization.data(withJSONObject: raw)
        let intent = try NativeRoutingIntent(sourceInboundIndex: 0, defaultOutboundTag: "selected-default")
        guard let prepared = TunnelXrayConfigPreparer.prepare(jsonData: source, credentials: credentials, routingIntent: intent,
            tcpPortAvailable: LocalProxyAccessPolicy.isTCPPortAvailable,
            resolveIPv4: { _ in preconditionFailure("Direct routing fixture must not bootstrap") }),
            let envelope = prepared.routingEnvelope else { preconditionFailure("Routing preparation failed") }
        let effective = try JSONSerialization.jsonObject(with: envelope.configurationData) as! [String: Any]
        precondition(effective["dns"] as! NSDictionary == dns as NSDictionary)
        let metadata = try JSONSerialization.jsonObject(with: envelope.metadataData) as! [String: Any]
        precondition(metadata["source_inbound_index"] as? Int == 1 && metadata["default_outbound_tag"] as? String == "selected-default")
        let port = TunnelXrayConfigPreparer.parseConfig(jsonData: prepared.data)!.inboundPort
        precondition(port != occupiedPort)
        func start() throws {
            try NativeRoutingSpec.check(envelope, capability: FLVlessCoreRoutingCapability, check: FLVlessCheckCoreRoutingPrivate)
            var error: NSError?
            precondition(FLVlessStartCoreRoutingPrivate(envelope.configurationData, envelope.metadataData, ProbeLogger(), &error), "Routing start failed")
        }
        func http(_ host: String) throws {
            let fd = try LocalSOCKS5Client.openConnection(proxyPort: port, credentials: credentials, host: host, port: 80, timeout: 3)
            defer { close(fd) }
            precondition(LocalSOCKS5Client.sendAll(fd: fd, bytes: Array("GET /native-routing HTTP/1.1\r\nHost: \(host)\r\nConnection: close\r\n\r\n".utf8)))
            precondition(LocalSOCKS5Client.receiveExactly(fd: fd, count: expected.count) == expected)
        }
        func pair() throws { try http("alias.invalid"); try http("fallback.invalid") }
        func dnsProof(_ generation: Int) throws {
            for udp in [false, true] {
                let id = UInt16(0x6800 + variant * 8 + generation * 2 + (udp ? 1 : 0))
                let answer = try queryVirtualDNS(proxyPort: port, credentials: credentials, udp: udp, id: id)
                precondition(answer != nil && answer!.prefix(2).elementsEqual([UInt8(id >> 8), UInt8(id & 255)]))
                precondition(answer![3] & 15 == 0 && answer![6] == 0 && answer![7] == 1 && answer!.suffix(4).elementsEqual([192, 0, 2, 14]))
            }
        }
        stage("start"); try start()
        stage("first-http"); try pair()
        stage("first-dns"); try dnsProof(0)
        var stale = envelope.configurationData; stale.append(0x20)
        precondition(FLVlessCheckCoreRoutingPrivate(stale, envelope.metadataData) == 17)
        var rejectedError: NSError?
        precondition(!FLVlessStartCoreRoutingPrivate(stale, envelope.metadataData, ProbeLogger(), &rejectedError))
        // Rejected final bytes must preserve the currently live owner.
        stage("after-rejection-http"); try pair()
        stage("stop"); XRayStop()
        stage("restart"); try start()
        stage("restart-http"); try pair()
        stage("restart-dns"); try dnsProof(1)
        stage("final-stop"); XRayStop()
        print("NATIVE_ROUTING_COUNTS;VARIANT=\(variant);ALIAS=\(aliased.state().0);DEFAULT=\(fallback.state().0);FALLBACK=\(trap.connections())")
        // Core never matches inboundTag:[""] against an untagged input.
        // That source therefore sends both HTTP targets to the selected default.
        precondition(aliased.state().0 == 3 && fallback.state().0 == (variant == 0 ? 3 : 9))
        precondition(trap.connections() == 0)
        print("NATIVE_ROUTING_RUNTIME_PASS=\(variant)")
    }
    print("NATIVE_ROUTING_STAGE=drain")
    aliased.stop(); fallback.stop(); trap.stop(); occupied.stop()
    print("NATIVE_ROUTING_DRAIN_COUNTS;ALIAS=\(aliased.state().0);ALIAS_CONNECTIONS=\(aliased.connections());DEFAULT=\(fallback.state().0);DEFAULT_CONNECTIONS=\(fallback.connections());FALLBACK=\(trap.connections())")
    precondition(aliased.state().0 == 3 && fallback.state().0 == 9 && aliased.connections() == 3 && fallback.connections() == 9)
    precondition(!aliased.state().1 && !fallback.state().1 && trap.connections() == 0)
    precondition(occupied.connections() == 0)
    print("NATIVE_ROUTING_RUNTIME_DRAIN_PASS")
    print("APPLE_PRIVATE_PORT_OCCUPIED_RUNTIME_PASS=2")
}

private final class ProfileRoutingPeer: @unchecked Sendable {
    private let lock = NSLock()
    private var healthy = true
    private var dnsQueries: [UInt8] = []
    let marker: UInt8
    let probeLatency: TimeInterval

    init(marker: UInt8, probeLatency: TimeInterval) {
        self.marker = marker
        self.probeLatency = probeLatency
    }

    func setHealthy(_ value: Bool) {
        lock.lock(); defer { lock.unlock() }
        healthy = value
    }

    func queries() -> [UInt8] {
        lock.lock(); defer { lock.unlock() }
        return dnsQueries
    }

    private func requestLine(_ fd: Int32) -> String? {
        var bytes: [UInt8] = []
        while bytes.count < 8192, !bytes.suffix(4).elementsEqual([13, 10, 13, 10]) {
            guard let next = LocalSOCKS5Client.receiveExactly(fd: fd, count: 1) else { return nil }
            bytes += next
        }
        return String(decoding: bytes, as: UTF8.self).components(separatedBy: "\r\n").first
    }

    func serve(_ fd: Int32, dnsPort: Int) {
        dnsProbeTimeout(fd, seconds: 2)
        guard let request = requestLine(fd), request.hasPrefix("CONNECT ") else { return }
        lock.lock(); let active = healthy; lock.unlock()
        guard active else {
            _ = LocalSOCKS5Client.sendAll(fd: fd, bytes: Array("HTTP/1.1 502 Bad Gateway\r\n\r\n".utf8))
            return
        }
        guard LocalSOCKS5Client.sendAll(fd: fd, bytes: Array("HTTP/1.1 200 Connection Established\r\n\r\n".utf8)) else { return }
        if request.hasPrefix("CONNECT 127.0.0.1:\(dnsPort) ") {
            guard let length = LocalSOCKS5Client.receiveExactly(fd: fd, count: 2) else { return }
            let size = Int(length[0]) * 256 + Int(length[1])
            guard (17...4096).contains(size), let query = LocalSOCKS5Client.receiveExactly(fd: fd, count: size) else { return }
            lock.lock(); dnsQueries.append(query[size - 3]); lock.unlock()
            dnsProbeReply(fd, query: query, marker: marker)
        } else if let tunneledRequest = requestLine(fd) {
            if tunneledRequest.hasPrefix("GET /health ") {
                Thread.sleep(forTimeInterval: probeLatency)
                _ = LocalSOCKS5Client.sendAll(fd: fd, bytes: Array("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".utf8))
            } else if tunneledRequest.hasPrefix("GET /profile ") {
                let body = String(UnicodeScalar(marker))
                _ = LocalSOCKS5Client.sendAll(fd: fd, bytes: Array("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n\(body)".utf8))
            }
        }
    }
}

// Actual Core routing through the private packet ingress and virtual DNS relay.
// Synthetic endpoints are owned loopback listeners, without an OS VPN session.
func runAppleProfileBalancerChecks() throws {
    func require(_ condition: @autoclosure () -> Bool, _ reason: String) throws {
        guard condition() else {
            throw NSError(domain: "AppleProfileBalancer", code: 1, userInfo: [NSLocalizedDescriptionKey: reason])
        }
    }
    let trap = LocalProbeOrigin(port: 0)
    let direct = LocalProbeOrigin(port: 0)
    let primary = ProfileRoutingPeer(marker: 65, probeLatency: 0.01)
    let alternate = ProfileRoutingPeer(marker: 66, probeLatency: 0.2)
    let first = LocalProbeOrigin(port: 0) { primary.serve($0, dnsPort: trap.port) }
    let second = LocalProbeOrigin(port: 0) { alternate.serve($0, dnsPort: trap.port) }
    defer { XRayStop(); first.stop(); second.stop(); trap.stop(); direct.stop() }
    let credentials = try LocalProxyCredentials.generate()
    let members = ["fv-profile-node-1!", "fv-profile-node-2!"]
    let group = "fv-profile-group-3!"
    let authoredRules: [[String: Any]] = [
        ["type": "field", "inboundTag": ["group-dns"], "ip": ["127.0.0.1/32"],
         "port": String(trap.port), "network": "tcp", "balancerTag": group],
        ["type": "field", "domain": ["full:direct.invalid"], "outboundTag": "direct"],
        ["type": "field", "network": "tcp,udp", "balancerTag": group],
    ]
    let proxyNodes: [[String: Any]] = zip(members, [first.port, second.port]).map { tag, port in
        ["tag": tag, "protocol": "http", "settings": ["servers": [["address": "127.0.0.1", "port": port]]]]
    }
    let outbounds: [[String: Any]] = [
        ["tag": "trap", "protocol": "freedom", "settings": ["redirect": "127.0.0.1:\(trap.port)"]],
        ["tag": "direct", "protocol": "freedom", "settings": ["redirect": "127.0.0.1:\(direct.port)"]],
    ] + proxyNodes + [["tag": "deny", "protocol": "blackhole"]]
    let raw: [String: Any] = [
        "inbounds": [[
            "tag": "in_proxy", "listen": "127.0.0.1", "port": 18095, "protocol": "socks",
            "settings": ["auth": "noauth", "udp": true],
        ]],
        "outbounds": outbounds,
        "dns": [
            "tag": "group-dns", "queryStrategy": "UseIP", "disableCache": true,
            "disableFallback": true, "servers": ["tcp://127.0.0.1:\(trap.port)"],
        ],
        "observatory": [
            "subjectSelector": members, "probeURL": "http://127.0.0.1:\(direct.port)/health",
            "probeInterval": "250ms", "enableConcurrency": true,
        ],
        "routing": ["rules": authoredRules, "balancers": [[
            "tag": group, "selector": members, "strategy": ["type": "leastPing"], "fallbackTag": "deny",
        ]]],
    ]
    let source = try JSONSerialization.data(withJSONObject: raw)
    guard let prepared = TunnelXrayConfigPreparer.prepare(
        jsonData: source, credentials: credentials, tcpPortAvailable: LocalProxyAccessPolicy.isTCPPortAvailable
    ), let managed = TunnelXrayConfigPreparer.parseConfig(jsonData: prepared.data) else {
          try require(false, "Profile balancer preparation failed")
          return
    }
    let effective = try JSONSerialization.jsonObject(with: prepared.data) as! [String: Any]
    let routing = effective["routing"] as! [String: Any]
    let rules = routing["rules"] as! [[String: Any]]
    let guardTag = rules.first?["outboundTag"] as? String
    try require(rules.suffix(authoredRules.count).map { $0 as NSDictionary } == authoredRules.map { $0 as NSDictionary },
                "Apple preparation changed authored routing order")
    try require(rules.first?["ip"] as? [String] == [TunnelDNSPolicy.virtualServer + "/32"], "Virtual DNS guard is not first")
    let tags = (effective["outbounds"] as! [[String: Any]]).compactMap { $0["tag"] as? String }
    let selectors = (routing["balancers"] as! [[String: Any]])[0]["selector"] as! [String]
    try require(tags.filter { tag in selectors.contains(where: { tag.hasPrefix($0) }) } == members, "Prepared group membership differs")
    try require(guardTag != nil && !members.contains(guardTag!), "Virtual DNS guard points at a group member")
    var error: NSError?
    try require(XRayStartPrivate(prepared.data, ProbeLogger(), &error), "Profile balancer startup failed")
    let port = managed.inboundPort

    func traffic(_ host: String, expected: [UInt8]) -> Bool {
        guard let fd = try? LocalSOCKS5Client.openConnection(proxyPort: port, credentials: credentials, host: host, port: 80, timeout: 1) else { return false }
        defer { close(fd) }
        let request = Array("GET /profile HTTP/1.1\r\nHost: \(host)\r\nConnection: close\r\n\r\n".utf8)
        return LocalSOCKS5Client.sendAll(fd: fd, bytes: request)
            && LocalSOCKS5Client.receiveExactly(fd: fd, count: expected.count) == expected
    }
    func waitForMember(_ marker: UInt8) -> Bool {
        let start = ProcessInfo.processInfo.systemUptime
        let response = Array("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n".utf8) + [marker]
        repeat {
            if traffic("grouped.invalid", expected: response) { return true }
            Thread.sleep(forTimeInterval: 0.06)
        } while ProcessInfo.processInfo.systemUptime - start < 5
        return false
    }
    func dns(_ peer: ProfileRoutingPeer, generation: Int) throws {
        for (index, type) in [UInt16(1), 28].enumerated() {
            let id = UInt16(0x6900 + generation * 2 + index)
            let name = "fresh-\(generation)-\(type).invalid"
            guard let answer = try queryVirtualDNS(proxyPort: port, credentials: credentials, udp: index == 1, id: id, type: type, name: name) else {
                try require(false, "Missing grouped DNS answer for QTYPE \(type) generation \(generation)")
                return
            }
            let expected: [UInt8] = type == 1
                ? [198, 51, 100, peer.marker]
                : [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, peer.marker]
            try require(answer.count >= 12 && answer[3] & 15 == 0 && answer[6...7].elementsEqual([0, 1])
                         && answer.prefix(2).elementsEqual([UInt8(id >> 8), UInt8(id & 255)])
                         && answer.suffix(expected.count).elementsEqual(expected), "Grouped DNS used wrong peer")
        }
        try require(peer.queries() == [1, 28], "Grouped resolver received unexpected queries")
    }
    let directResponse = Array("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".utf8)
    try require(waitForMember(primary.marker), "Fastest member was not selected")
    try require(traffic("direct.invalid", expected: directResponse), "Direct route did not reach its peer")
    try dns(primary, generation: 0)
    primary.setHealthy(false)
    try require(waitForMember(alternate.marker), "Group did not switch after probe failure")
    try require(traffic("direct.invalid", expected: directResponse), "Failover changed the direct route")
    try dns(alternate, generation: 1)
    XRayStop()
    // A closed TCP listener can leave TIME_WAIT connections. Probe whether
    // it still accepts instead of requiring immediate rebind of its address.
    let listenerProbe = socket(AF_INET, SOCK_STREAM, 0)
    try require(listenerProbe >= 0, "Could not create the listener cleanup probe")
    defer { close(listenerProbe) }
    dnsProbeTimeout(listenerProbe, seconds: 1)
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = UInt16(port).bigEndian
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr)
    let connected = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            connect(listenerProbe, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    try require(connected == -1 && errno == ECONNREFUSED, "Managed SOCKS did not close")
    first.stop(); second.stop(); trap.stop(); direct.stop()
    try require(primary.queries() == [1, 28] && alternate.queries() == [1, 28], "Grouped resolver leaked a query")
    try require(trap.connections() == 0 && direct.state().0 == 2, "Unexpected local fallback connection")
    print("APPLE_PROFILE_BALANCER_DNS_FAILOVER_PASS=2")
}

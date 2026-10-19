// CI-only actual optional factory proof. Existing outer harness owns the process
// deadline and admission guard; no OS tunnel, routes or preferences are changed.
func runNativeRoutingRuntimeChecks() throws {
    precondition(FLVlessCoreRoutingCapability() == 1, "Enabled routing runtime is required")
    let aliased = LocalProbeOrigin(port: 18096), fallback = LocalProbeOrigin(port: 18097)
    // The only configured upstream is TCP. A joined HTTP fixture records any
    // attempted connection without answering DNS; static hosts must avoid it.
    let trap = LocalProbeOrigin(port: 18104)
    defer { XRayStop(); aliased.stop(); fallback.stop(); trap.stop() }
    var assetError: NSError?
    precondition(XRaySetAssetLocation("", &assetError))
    let credentials = try LocalProxyCredentials(username: "routing-session-user", password: "routing-session-password")
    let expected = Array("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".utf8)
    for variant in 0..<2 {
        let sourceTag = variant == 0 ? "caller-source" : ""
        var sourceInput: [String: Any] = ["listen": "127.0.0.1", "port": 18095, "protocol": "socks", "settings": ["auth": "noauth", "udp": true]]
        if variant == 0 { sourceInput["tag"] = sourceTag }
        let dns: [String: Any] = ["queryStrategy": "UseIPv4", "hosts": ["dns-proof.invalid": "192.0.2.14", "fallback.invalid": "192.0.2.99"], "servers": ["tcp://127.0.0.1:18104"]]
        let raw: [String: Any] = ["inbounds": [sourceInput], "dns": dns,
            "outbounds": [["tag": "caller-block", "protocol": "blackhole"],
                ["tag": "alias-target", "protocol": "freedom", "settings": ["redirect": "127.0.0.1:18096"]],
                ["tag": "selected-default", "protocol": "freedom", "settings": ["redirect": "127.0.0.1:18097"]]],
            "routing": ["domainStrategy": "IPIfNonMatch", "rules": [
                ["type": "field", "inboundTag": [sourceTag], "ip": ["198.18.0.2"], "port": "53", "outboundTag": "caller-block"],
                ["type": "field", "inboundTag": [sourceTag], "domain": ["full:alias.invalid"], "outboundTag": "alias-target"]]]]
        let source = try JSONSerialization.data(withJSONObject: raw)
        let intent = try NativeRoutingIntent(sourceInboundIndex: 0, defaultOutboundTag: "selected-default")
        guard let prepared = TunnelXrayConfigPreparer.prepare(jsonData: source, credentials: credentials, routingIntent: intent,
            resolveIPv4: { _ in preconditionFailure("Direct routing fixture must not bootstrap") }),
            let envelope = prepared.routingEnvelope else { preconditionFailure("Routing preparation failed") }
        let effective = try JSONSerialization.jsonObject(with: envelope.configurationData) as! [String: Any]
        precondition(effective["dns"] as! NSDictionary == dns as NSDictionary)
        let metadata = try JSONSerialization.jsonObject(with: envelope.metadataData) as! [String: Any]
        precondition(metadata["source_inbound_index"] as? Int == 1 && metadata["default_outbound_tag"] as? String == "selected-default")
        let port = TunnelXrayConfigPreparer.parseConfig(jsonData: prepared.data)!.inboundPort
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
        try start(); try pair(); try dnsProof(0)
        var stale = envelope.configurationData; stale.append(0x20)
        precondition(FLVlessCheckCoreRoutingPrivate(stale, envelope.metadataData) == 17)
        var rejectedError: NSError?
        precondition(!FLVlessStartCoreRoutingPrivate(stale, envelope.metadataData, ProbeLogger(), &rejectedError))
        try pair() // Rejected final bytes must preserve the currently live owner.
        XRayStop()
        try start(); try pair(); try dnsProof(1); XRayStop()
        precondition(aliased.state().0 == (variant + 1) * 3 && fallback.state().0 == (variant + 1) * 3)
        precondition(trap.connections() == 0)
        print("NATIVE_ROUTING_RUNTIME_PASS=\(variant)")
    }
    aliased.stop(); fallback.stop(); trap.stop()
    precondition(aliased.state().0 == 6 && fallback.state().0 == 6 && aliased.connections() == 6 && fallback.connections() == 6)
    precondition(!aliased.state().1 && !fallback.state().1 && trap.connections() == 0)
    print("NATIVE_ROUTING_RUNTIME_DRAIN_PASS")
}

// Concatenated with the production runners and localhost fixture helpers.
func runMacCounterChecks() async throws {
    let origin = LocalProbeOrigin(port: 18096)
    defer { origin.stop() }
    let raw: [String: Any] = [
        "inbounds": [["protocol": "socks", "listen": "127.0.0.1", "port": 18095]],
        "outbounds": [["protocol": "freedom", "tag": "direct", "settings": ["redirect": "127.0.0.1:18096"]]],
        "API": ["tag": "fixture-management-api", "listen": "127.0.0.1:18081", "services": ["HandlerService", "RoutingService"]]
    ]
    let runner = ProxyOnlyRunner()
    try runner.start(configData: JSONSerialization.data(withJSONObject: raw), geoAssetsDirectory: nil)
    defer { runner.stop() }
    let fd = try LocalSOCKS5Client.openConnection(proxyPort: 18095, credentials: nil, host: "probe.invalid", port: 80)
    _ = LocalSOCKS5Client.sendAll(fd: fd, bytes: Array("GET / HTTP/1.1\r\nHost: probe.invalid\r\nConnection: close\r\n\r\n".utf8))
    precondition(String(decoding: LocalSOCKS5Client.receiveExactly(fd: fd, count: 12) ?? [], as: UTF8.self).contains("204"))
    close(fd)
    var transferred = false
    for _ in 0..<10 {
        let stats = runner.queryTrafficStats()
        if stats.upload > 0 && stats.download > 0 { transferred = true; break }
        try await Task.sleep(nanoseconds: 50_000_000)
    }
    precondition(transferred, "Default proxy-only configuration must enable real traffic counters")
    let api = openLoopback(18081)
    precondition(LocalSOCKS5Client.sendAll(fd: api, bytes: Array("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8) + [0, 0, 0, 4, 0, 0, 0, 0, 0]))
    let frame = LocalSOCKS5Client.receiveExactly(fd: api, count: 9) ?? []
    close(api)
    precondition(frame.count == 9 && frame[3] == 4 && frame.suffix(4).allSatisfy { $0 == 0 },
                 "Imported management API must remain available alongside native counters")
    print("MACOS_COUNTERS_AND_API_PASSTHROUGH_PASS")
}

// Concatenated with the production runners and localhost fixture helpers.
func runMacCounterChecks() async throws {
    let origin = LocalProbeOrigin(port: 18096)
    defer { origin.stop() }
    let raw: [String: Any] = [
        "inbounds": [["protocol": "socks", "listen": "127.0.0.1", "port": 18095]],
        "outbounds": [["protocol": "freedom", "tag": "direct", "settings": ["redirect": "127.0.0.1:18096"]]],
        "API": ["listen": "127.0.0.1:18081", "services": ["HandlerService", "RoutingService"]]
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
    let api = socket(AF_INET, SOCK_STREAM, 0)
    var address = sockaddr_in(); address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET); address.sin_port = UInt16(18081).bigEndian
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr)
    let connected = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(api, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
    close(api)
    precondition(connected != 0, "Imported management API must not open a listener")
    print("MACOS_COUNTERS_AND_API_BOUNDARY_PASS")
}

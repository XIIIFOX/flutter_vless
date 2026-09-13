// Localhost origin + the actual bundled Xray. No VPN routes or host DNS changes.
final class LocalProbeOrigin: @unchecked Sendable {
    private let fd: Int32
    private let lock = NSLock()
    private var requests = 0
    private var leakedHeader = false
    init(port: Int) {
        fd = socket(AF_INET, SOCK_STREAM, 0)
        precondition(fd >= 0)
        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = UInt16(port).bigEndian
        inet_pton(AF_INET, "127.0.0.1", &address.sin_addr)
        precondition(withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        } == 0)
        precondition(listen(fd, 16) == 0)
        DispatchQueue.global().async { [self] in
            while true {
                let client = accept(fd, nil, nil)
                if client < 0 { break }
                DispatchQueue.global().async { [self] in serve(client) }
            }
        }
    }
    func stop() { shutdown(fd, SHUT_RDWR); close(fd) }
    func state() -> (Int, Bool) {
        lock.lock(); defer { lock.unlock() }; return (requests, leakedHeader)
    }
    private func serve(_ client: Int32) {
        defer { close(client) }
        var duration = timeval(tv_sec: 5, tv_usec: 0)
        var noSignal: Int32 = 1
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &duration, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
        var bytes: [UInt8] = []
        while bytes.count < 16384, !bytes.suffix(4).elementsEqual([13, 10, 13, 10]) {
            guard let byte = LocalSOCKS5Client.receiveExactly(fd: client, count: 1) else { return }
            bytes += byte
        }
        let request = String(decoding: bytes, as: UTF8.self).lowercased()
        lock.lock()
        requests += 1
        leakedHeader = leakedHeader || request.contains("proxy-authorization:") || request.contains("local-password-canary")
        lock.unlock()
        _ = LocalSOCKS5Client.sendAll(fd: client, bytes: Array("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".utf8))
    }
}

func openLoopback(_ port: Int) -> Int32 {
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    precondition(fd >= 0)
    var timeout = timeval(tv_sec: 3, tv_usec: 0)
    var noSignal: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = UInt16(port).bigEndian
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr)
    precondition(withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
    } == 0)
    return fd
}

func runLocalAuthRuntimeChecks() async throws {
    let origin = LocalProbeOrigin(port: 18096)
    defer { origin.stop() }
    let credentials = try LocalProxyCredentials(username: "local-user-canary", password: "local-password-canary")
    let wrong = try LocalProxyCredentials(username: credentials.username, password: "wrong-password")
    // Redirect is confined to this fixture: a direct request to probe.invalid
    // cannot reach the origin. The only working path is through local Xray.
    let raw: [String: Any] = [
        "inbounds": [["tag": "in_proxy", "liſten": "127.0.0.1", "port": 18095,
                      "protocol": "socks", "ſettings": ["auth": "noauth", "udp": true,
                          "accountſ": [["uſer": "old", "paſſ": "old"]]]]],
        "outbounds": [["tag": "direct", "protocol": "freedom", "settings": ["redirect": "127.0.0.1:18096"]]]
    ]
    let source = try JSONSerialization.data(withJSONObject: raw)
    var protected = raw
    try LocalProxyAccessPolicy.applyVPN(to: &protected, credentials: credentials)
    precondition(XrayPrivacyConfig.apply(to: &protected))
    let prepared = try JSONSerialization.data(withJSONObject: protected)
    let logger = ProbeLogger()
    for generation in 0..<2 {
        var error: NSError?
        precondition(XRayStartPrivate(prepared, logger, &error))
        defer { XRayStop() }
        for secret in [nil, wrong] as [LocalProxyCredentials?] {
            let fd = openLoopback(18095)
            precondition(!LocalSOCKS5Client.authenticate(fd: fd, credentials: secret))
            close(fd)
        }
        // Xray multiplexes HTTP onto the SOCKS listener; verify that path too.
        let http = openLoopback(18095)
        _ = LocalSOCKS5Client.sendAll(fd: http, bytes: Array("GET http://probe.invalid/ HTTP/1.1\r\nHost: probe.invalid\r\n\r\n".utf8))
        let response = LocalSOCKS5Client.receiveExactly(fd: http, count: 12) ?? []
        precondition(String(decoding: response, as: UTF8.self).contains("407"))
        close(http)
        let fd = try LocalSOCKS5Client.openConnection(proxyPort: 18095, credentials: credentials, host: "probe.invalid", port: 80)
        _ = LocalSOCKS5Client.sendAll(fd: fd, bytes: Array("GET / HTTP/1.1\r\nHost: probe.invalid\r\n\r\n".utf8))
        precondition(String(decoding: LocalSOCKS5Client.receiveExactly(fd: fd, count: 12) ?? [], as: UTF8.self).contains("204"))
        close(fd)
        let delay = await withCheckedContinuation { continuation in
            LocalProxyDelayClient.measure(url: URL(string: "http://probe.invalid/")!, port: 18095, credentials: credentials) {
                continuation.resume(returning: $0)
            }
        }
        print("SOCKS_DELAY_RESULT=\(delay)")
        precondition(delay >= 0, "Authenticated SOCKS URL client did not reach controlled origin")
        let httpDelay = try await LocalHTTPProxyClient(port: 18095, credentials: credentials).measure(url: URL(string: "http://probe.invalid/")!)
        precondition(httpDelay >= 0)
        let wrongDelay = await withCheckedContinuation { continuation in
            LocalProxyDelayClient.measure(url: URL(string: "http://probe.invalid/")!, port: 18095, credentials: wrong) {
                continuation.resume(returning: $0)
            }
        }
        precondition(wrongDelay == -1)
        let wrongHTTP = try? await LocalHTTPProxyClient(port: 18095, credentials: wrong).measure(url: URL(string: "http://probe.invalid/")!)
        precondition(wrongHTTP == nil)
        XRayStop()
        print("AUTH_RUNTIME_PASS=\(generation)")
    }
    let delay = await ServerDelayRunner().measure(config: String(decoding: source, as: UTF8.self),
        url: "http://probe.invalid/", geoAssetsDirectory: nil)
    print("HTTP_DELAY_RESULT=\(delay)")
    precondition(delay >= 0, "Authenticated HTTP delay did not reach controlled origin")
    var rotated = raw
    let nextCredentials = try LocalProxyCredentials.generate()
    try LocalProxyAccessPolicy.applyVPN(to: &rotated, credentials: nextCredentials)
    precondition(XrayPrivacyConfig.apply(to: &rotated))
    var rotationError: NSError?
    let rotatedData = try JSONSerialization.data(withJSONObject: rotated)
    precondition(XRayStartPrivate(rotatedData, logger, &rotationError))
    let oldClient = openLoopback(18095)
    precondition(!LocalSOCKS5Client.authenticate(fd: oldClient, credentials: credentials))
    close(oldClient)
    let newClient = try LocalSOCKS5Client.openConnection(proxyPort: 18095, credentials: nextCredentials, host: "probe.invalid", port: 80)
    _ = LocalSOCKS5Client.sendAll(fd: newClient, bytes: Array("GET / HTTP/1.1\r\nHost: probe.invalid\r\n\r\n".utf8))
    precondition(String(decoding: LocalSOCKS5Client.receiveExactly(fd: newClient, count: 12) ?? [], as: UTF8.self).contains("204"))
    close(newClient)
    XRayStop()
    print("AUTH_ROTATION_PASS")

    var defaults = raw
    defaults.removeValue(forKey: "inbounds")
    let defaultsData = try JSONSerialization.data(withJSONObject: defaults)
    let defaultDelay = await ServerDelayRunner().measure(config: String(decoding: defaultsData, as: UTF8.self),
        url: "http://probe.invalid/", geoAssetsDirectory: nil)
    precondition(defaultDelay >= 0)
    let proxyOnly = ProxyOnlyRunner()
    try proxyOnly.start(configData: defaultsData, geoAssetsDirectory: nil)
    let defaultConnected = await proxyOnly.measureConnectedDelay(url: "http://probe.invalid/")
    precondition(defaultConnected >= 0)
    proxyOnly.stop()
    try proxyOnly.start(configData: prepared, geoAssetsDirectory: nil)
    let authorizedConnected = await proxyOnly.measureConnectedDelay(url: "http://probe.invalid/")
    precondition(authorizedConnected >= 0)
    proxyOnly.stop()
    print("RUNNER_DEFAULTS_AND_EXPLICIT_AUTH_PASS")
    let (requests, leaked) = origin.state()
    precondition(requests >= 5 && !leaked)
    print("AUTH_ORIGIN_HEADERS_PRIVATE_PASS")
}

func runDomainRoutingChecks() throws {
    let directOrigin = LocalProbeOrigin(port: 18097)
    let proxyOrigin = LocalProbeOrigin(port: 18098)
    defer { directOrigin.stop(); proxyOrigin.stop(); XRayStop() }
    let credentials = try LocalProxyCredentials.generate()
    var config: [String: Any] = [
        "inbounds": [["tag": "socks-in", "listen": "127.0.0.1", "port": 18095,
                      "protocol": "socks", "settings": ["auth": "noauth", "udp": true]]],
        "outbounds": [
            ["tag": "proxy", "protocol": "freedom", "settings": ["redirect": "127.0.0.1:18098"]],
            ["tag": "direct", "protocol": "freedom", "settings": ["redirect": "127.0.0.1:18097"]]],
        "routing": ["domainStrategy": "AsIs", "rules": [
            ["type": "field", "domain": ["full:direct-site.invalid"], "outboundTag": "direct"],
            ["type": "field", "domain": ["full:proxy-site.invalid"], "outboundTag": "proxy"]]]
    ]
    try LocalProxyAccessPolicy.applyVPN(to: &config, credentials: credentials)
    precondition(XrayPrivacyConfig.apply(to: &config))
    let data = try JSONSerialization.data(withJSONObject: config)
    let logger = ProbeLogger()
    for generation in 0..<2 {
        var error: NSError?
        precondition(XRayStartPrivate(data, logger, &error))
        for host in ["direct-site.invalid", "proxy-site.invalid"] {
            let beforeDirect = directOrigin.state().0, beforeProxy = proxyOrigin.state().0
            let fd = try LocalSOCKS5Client.openConnection(proxyPort: 18095, credentials: credentials, host: host, port: 80)
            defer { close(fd) }
            precondition(LocalSOCKS5Client.sendAll(fd: fd, bytes: Array("GET / HTTP/1.1\r\nHost: \(host)\r\n\r\n".utf8)))
            precondition(String(decoding: LocalSOCKS5Client.receiveExactly(fd: fd, count: 12) ?? [], as: UTF8.self).contains("204"))
            precondition(directOrigin.state().0 - beforeDirect == (host == "direct-site.invalid" ? 1 : 0))
            precondition(proxyOrigin.state().0 - beforeProxy == (host == "proxy-site.invalid" ? 1 : 0))
        }
        XRayStop()
        print("DOMAIN_ROUTING_PASS=\(generation)")
    }
}

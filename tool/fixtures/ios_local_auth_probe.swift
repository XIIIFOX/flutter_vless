import CryptoKit

// Localhost origin + the actual bundled Xray. No VPN routes or host DNS changes.
final class LocalProbeOrigin: @unchecked Sendable {
    private let fd: Int32
    private let lock = NSLock()
    private var requests = 0
    private var leakedHeader = false
    private var stopped = false
    private var listenerClosed = false
    private var accepted = 0
    private var clients = Set<Int32>()
    private let workers = DispatchGroup()
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
        let flags = fcntl(fd, F_GETFL, 0)
        precondition(flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0)
        workers.enter()
        DispatchQueue.global().async { [self] in
            defer { workers.leave() }
            while true {
                lock.lock(); let active = !stopped; lock.unlock()
                guard active else { break }
                let client = accept(fd, nil, nil)
                if client < 0 {
                    if errno == EINTR { continue }
                    precondition(errno == EAGAIN || errno == EWOULDBLOCK, "Owned HTTP accept failed")
                    var ready = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
                    let result = poll(&ready, 1, 100)
                    precondition(result >= 0 || errno == EINTR, "Owned HTTP listener poll failed")
                    continue
                }
                lock.lock(); accepted += 1
                guard !stopped else { close(client); lock.unlock(); break }
                // BSD accept may inherit the listener's nonblocking status.
                // Keep the existing blocking receive/timeout behavior on clients.
                let flags = fcntl(client, F_GETFL, 0)
                guard flags >= 0, fcntl(client, F_SETFL, flags & ~O_NONBLOCK) == 0 else {
                    close(client); lock.unlock(); preconditionFailure("Owned HTTP client flags failed")
                }
                clients.insert(client); workers.enter(); lock.unlock()
                DispatchQueue.global().async { [self] in
                    defer {
                        lock.lock(); clients.remove(client); close(client); lock.unlock()
                        workers.leave()
                    }
                    serve(client)
                }
            }
        }
    }
    func stop() {
        lock.lock()
        if !stopped {
            stopped = true
            // Listening TCP sockets reject shutdown with ENOTCONN on Darwin.
            // Poll is bounded; retain this descriptor until the accept loop exits.
            for client in clients { shutdown(client, SHUT_RDWR) }
        }
        lock.unlock()
        precondition(workers.wait(timeout: .now() + 6) == .success, "Owned HTTP fixture did not drain")
        lock.lock()
        if !listenerClosed { close(fd); listenerClosed = true }
        lock.unlock()
    }
    func connections() -> Int { lock.lock(); defer { lock.unlock() }; return accepted }
    func state() -> (Int, Bool) {
        lock.lock(); defer { lock.unlock() }; return (requests, leakedHeader)
    }
    private func serve(_ client: Int32) {
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
        "api": ["tag": "fixture-api", "listen": "127.0.0.1:+10808", "services": ["StatsService"]],
        "Metricſ": ["tag": "fixture-metrics", "Liſten": "127.0.0.1:+10809"],
        "stats": [String: Any](),
        "outbounds": [["tag": "direct", "protocol": "freedom", "settings": ["redirect": "127.0.0.1:18096"]],
                      ["tag": "fixture-blocked", "protocol": "blackhole"]],
        // This user's dormant rule must never capture a newly injected adapter.
        "routing": ["rules": [["type": "field", "inboundTag": ["flutter-vless-tun"], "outboundTag": "fixture-blocked"]]]
    ]
    let source = try JSONSerialization.data(withJSONObject: raw)
    var protected = raw
    let managedPort = try LocalProxyAccessPolicy.applyVPN(to: &protected, credentials: credentials)
    precondition(managedPort == 10810, "Managed adapter must reserve imported API and metrics ports")
    precondition((protected["inbounds"] as? [[String: Any]])?.first?["tag"] as? String == "flutter-vless-tun-1")
    precondition(XrayPrivacyConfig.apply(to: &protected))
    let prepared = try JSONSerialization.data(withJSONObject: protected)
    let logger = ProbeLogger()
    for generation in 0..<2 {
        var error: NSError?
        print("PROBE_PHASE=auth-core-start-begin;generation=\(generation)")
        precondition(XRayStartPrivate(prepared, logger, &error))
        print("PROBE_PHASE=auth-core-start-complete;generation=\(generation)")
        defer { XRayStop() }
        // An HTTP/2 SETTINGS frame proves that the imported API really bound
        // its original socket, rather than accidentally reaching our SOCKS input.
        let api = openLoopback(10808)
        _ = LocalSOCKS5Client.sendAll(fd: api, bytes: Array("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8) + [0, 0, 0, 4, 0, 0, 0, 0, 0])
        let frame = LocalSOCKS5Client.receiveExactly(fd: api, count: 9) ?? []
        close(api)
        precondition(frame.count == 9 && frame[3] == 4 && frame.suffix(4).allSatisfy { $0 == 0 })
        let metrics = openLoopback(10809)
        precondition(LocalSOCKS5Client.sendAll(fd: metrics, bytes: Array("GET /debug/vars HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".utf8)))
        let metricsResponse = LocalSOCKS5Client.receiveExactly(fd: metrics, count: 12) ?? []
        close(metrics)
        precondition(String(decoding: metricsResponse, as: UTF8.self).contains("200"))
        print("PROBE_PHASE=auth-management-checked;generation=\(generation)")
        for secret in [nil, wrong] as [LocalProxyCredentials?] {
            let fd = openLoopback(managedPort)
            precondition(!LocalSOCKS5Client.authenticate(fd: fd, credentials: secret))
            close(fd)
        }
        // Xray multiplexes HTTP onto the SOCKS listener; verify that path too.
        let http = openLoopback(managedPort)
        _ = LocalSOCKS5Client.sendAll(fd: http, bytes: Array("GET http://probe.invalid/ HTTP/1.1\r\nHost: probe.invalid\r\n\r\n".utf8))
        let response = LocalSOCKS5Client.receiveExactly(fd: http, count: 12) ?? []
        precondition(String(decoding: response, as: UTF8.self).contains("407"))
        close(http)
        let fd = try LocalSOCKS5Client.openConnection(proxyPort: managedPort, credentials: credentials, host: "probe.invalid", port: 80)
        _ = LocalSOCKS5Client.sendAll(fd: fd, bytes: Array("GET / HTTP/1.1\r\nHost: probe.invalid\r\n\r\n".utf8))
        precondition(String(decoding: LocalSOCKS5Client.receiveExactly(fd: fd, count: 12) ?? [], as: UTF8.self).contains("204"))
        close(fd)
        let delay = await withCheckedContinuation { continuation in
            LocalProxyDelayClient.measure(url: URL(string: "http://probe.invalid/")!, port: managedPort, credentials: credentials) {
                continuation.resume(returning: $0)
            }
        }
        print("SOCKS_DELAY_RESULT=\(delay)")
        precondition(delay >= 0, "Authenticated SOCKS URL client did not reach controlled origin")
        let httpDelay = try await LocalHTTPProxyClient(port: managedPort, credentials: credentials).measure(url: URL(string: "http://probe.invalid/")!)
        precondition(httpDelay >= 0)
        let wrongDelay = await withCheckedContinuation { continuation in
            LocalProxyDelayClient.measure(url: URL(string: "http://probe.invalid/")!, port: managedPort, credentials: wrong) {
                continuation.resume(returning: $0)
            }
        }
        precondition(wrongDelay == -1)
        let wrongHTTP = try? await LocalHTTPProxyClient(port: managedPort, credentials: wrong).measure(url: URL(string: "http://probe.invalid/")!)
        precondition(wrongHTTP == nil)
        print("PROBE_PHASE=auth-core-stop-begin;generation=\(generation)")
        XRayStop()
        print("PROBE_PHASE=auth-core-stop-complete;generation=\(generation)")
        print("AUTH_RUNTIME_PASS=\(generation)")
        print("SERVICE_TAG_RUNTIME_PASS=\(generation)")
        print("API_PORT_RESERVATION_PASS=\(generation)")
        print("METRICS_PORT_RESERVATION_PASS=\(generation)")
        print("METRICS_PASSTHROUGH_PASS=\(generation)")
    }
    // A real VPN provider holds the imported API in another process. Keep that
    // socket occupied while the isolated measurement starts its own Core.
    let occupiedAPI = socket(AF_INET, SOCK_STREAM, 0)
    precondition(occupiedAPI >= 0)
    var reuse: Int32 = 1
    setsockopt(occupiedAPI, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
    var occupiedAddress = sockaddr_in()
    occupiedAddress.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    occupiedAddress.sin_family = sa_family_t(AF_INET)
    occupiedAddress.sin_port = UInt16(10808).bigEndian
    inet_pton(AF_INET, "127.0.0.1", &occupiedAddress.sin_addr)
    precondition(withUnsafePointer(to: &occupiedAddress) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(occupiedAPI, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
    } == 0)
    precondition(listen(occupiedAPI, 1) == 0)
    let occupiedMetrics = socket(AF_INET, SOCK_STREAM, 0)
    precondition(occupiedMetrics >= 0)
    setsockopt(occupiedMetrics, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))
    occupiedAddress.sin_port = UInt16(10809).bigEndian
    precondition(withUnsafePointer(to: &occupiedAddress) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(occupiedMetrics, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
    } == 0)
    precondition(listen(occupiedMetrics, 1) == 0)
    print("PROBE_PHASE=occupied-management-delay-begin")
    let delay = await ServerDelayRunner().measure(config: String(decoding: source, as: UTF8.self),
        url: "http://probe.invalid/", geoAssetsDirectory: nil)
    close(occupiedAPI)
    close(occupiedMetrics)
    print("PROBE_PHASE=occupied-management-delay-complete")
    print("HTTP_DELAY_RESULT=\(delay)")
    precondition(delay >= 0, "Authenticated HTTP delay did not reach controlled origin")
    print("DELAY_API_ISOLATION_PASS")
    var rotated = raw
    let nextCredentials = try LocalProxyCredentials.generate()
    try LocalProxyAccessPolicy.applyVPN(to: &rotated, credentials: nextCredentials)
    precondition(XrayPrivacyConfig.apply(to: &rotated))
    var rotationError: NSError?
    let rotatedData = try JSONSerialization.data(withJSONObject: rotated)
    precondition(XRayStartPrivate(rotatedData, logger, &rotationError))
    let oldClient = openLoopback(managedPort)
    precondition(!LocalSOCKS5Client.authenticate(fd: oldClient, credentials: credentials))
    close(oldClient)
    let newClient = try LocalSOCKS5Client.openConnection(proxyPort: managedPort, credentials: nextCredentials, host: "probe.invalid", port: 80)
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
    var explicitProxy = protected
    explicitProxy["inbounds"] = [(protected["inbounds"] as! [[String: Any]])[0]]
    try proxyOnly.start(configData: JSONSerialization.data(withJSONObject: explicitProxy), geoAssetsDirectory: nil)
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
    let managedPort = try LocalProxyAccessPolicy.applyVPN(to: &config, credentials: credentials)
    precondition(XrayPrivacyConfig.apply(to: &config))
    let data = try JSONSerialization.data(withJSONObject: config)
    let logger = ProbeLogger()
    for generation in 0..<2 {
        var error: NSError?
        precondition(XRayStartPrivate(data, logger, &error))
        // Core checks of both a valid occupied-listener config and an invalid
        // candidate must preserve actual routing through the running instance.
        if FLVlessHasCorePreflight() {
            let accepted = try CorePreflightPolicy.validate(data, check: FLVlessCheckCorePrivate)
            precondition(accepted)
            let rejected = Data("{\"outbounds\":[{\"protocol\":\"privacy-canary.invalid\"}]}".utf8)
            do {
                try CorePreflightPolicy.validate(rejected, check: FLVlessCheckCorePrivate)
                preconditionFailure("Invalid candidate accepted")
            } catch let failure as CorePreflightError {
                precondition(failure.stage == "build" && failure.section == "outbounds" && failure.index == 0)
            }
            print("PREFLIGHT_RUNNING_SESSION_PASS=\(generation)")
        } else if ProcessInfo.processInfo.environment["REQUIRE_CORE_PREFLIGHT"] == "1" {
            preconditionFailure("Runtime must expose Core preflight")
        }
        for host in ["direct-site.invalid", "proxy-site.invalid"] {
            let beforeDirect = directOrigin.state().0, beforeProxy = proxyOrigin.state().0
            let fd = try LocalSOCKS5Client.openConnection(proxyPort: managedPort, credentials: credentials, host: host, port: 80)
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


// The qualifier embeds the shared, non-secret corpus rather than duplicating
// its protobuf payload in either platform's runtime fixture.
private struct LocalAssetFixture: Decodable {
    let file: String
    let code: String
    let domain: String
    let base64: String
    let sha256: String
}

func runAssetRuntimeChecks() throws {
    let encoded = "__ASSET_FIXTURE_JSON_BASE64__"
    let fixture = try JSONDecoder().decode(LocalAssetFixture.self, from: Data(base64Encoded: encoded)!)
    let payload = Data(base64Encoded: fixture.base64)!
    precondition(fixture.file == "caller-geosite.dat" && fixture.code == "CALLER" && fixture.domain == "files-fixture.invalid")
    precondition(SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined() == fixture.sha256)
    let root = FileManager.default.temporaryDirectory.appendingPathComponent("xray-custom-assets-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: root) }
    try payload.write(to: root.appendingPathComponent(fixture.file))
    let files = try FileManager.default.contentsOfDirectory(atPath: root.path)
    precondition(files == [fixture.file])
    let origin = LocalProbeOrigin(port: 18096)
    defer { origin.stop() }
    let raw: [String: Any] = [
        "inbounds": [["protocol": "socks", "listen": "127.0.0.1", "port": 18095]],
        "dns": ["hosts": [fixture.domain: "127.0.0.1"]],
        "outbounds": [["protocol": "blackhole", "tag": "default-block"],
            ["protocol": "freedom", "tag": "asset-direct", "settings": ["redirect": "127.0.0.1:18096"]]],
        "routing": ["rules": [["type": "field", "domain": ["ext:\(fixture.file):\(fixture.code)"], "outboundTag": "asset-direct"]]]
    ]
    let runner = ProxyOnlyRunner()
    defer { runner.stop() }
    try runner.start(configData: JSONSerialization.data(withJSONObject: raw), geoAssetsDirectory: root.path)
    do {
        let fd = try LocalSOCKS5Client.openConnection(proxyPort: 18095, credentials: nil, host: fixture.domain, port: 80)
        defer { close(fd) }
        precondition(LocalSOCKS5Client.sendAll(fd: fd, bytes: Array("GET /custom-assets HTTP/1.1\r\nHost: \(fixture.domain)\r\nConnection: close\r\n\r\n".utf8)))
        let expected = Array("HTTP/1.1 204 ".utf8)
        let response = LocalSOCKS5Client.receiveExactly(fd: fd, count: expected.count) ?? []
        precondition(response == expected)
    }
    precondition(origin.state().0 == 1 && !origin.state().1)
    runner.stop()
    // Root lifetime follows the stopped runtime; following nil-root sessions
    // exercise the existing default lookup and cannot retain this directory.
    try FileManager.default.removeItem(at: root)
    precondition(!FileManager.default.fileExists(atPath: root.path))
    print("ASSET_CUSTOM_ROOT_RUNTIME_PASS")
}


func runDirectOnlyRuntimeChecks() throws {
    let encoded = "__DIRECT_ONLY_FIXTURE_JSON_BASE64__"
    let originals = try JSONSerialization.jsonObject(with: Data(base64Encoded: encoded)!) as! [[String: Any]]
    precondition(originals.count == 2)
    let selectorEncoded = "__SELECTOR_TRAFFIC_FIXTURE_JSON_BASE64__"
    let selector = try JSONSerialization.jsonObject(with: Data(base64Encoded: selectorEncoded)!) as! [String: Any]
    let cases = originals.map { $0["config"] as! [String: Any] } + [selector]
    let origin = LocalProbeOrigin(port: 18096)
    let trap = DNSDirectFallbackTrap(port: 18104)
    defer { XRayStop(); origin.stop(); trap.stop() }
    let credentials = try LocalProxyCredentials.generate()
    let expected = Array("HTTP/1.1 204 ".utf8)
    for (index, item) in cases.enumerated() {
        var raw = item
        // Keep both allowed and blocked targets on the controlled origin. A
        // lost caller block must yield actual204bytes and fail this fixture.
        var dns = raw["dns"] as! [String: Any]
        var hosts = dns["hosts"] as! [String: Any]
        hosts["direct-only.invalid"] = "127.0.0.1"; hosts["blocked.invalid"] = "127.0.0.1"
        hosts["dns-proof.invalid"] = "192.0.2.14"
        dns["hosts"] = hosts; dns["servers"] = ["tcp://127.0.0.1:18104"]
        raw["dns"] = dns
        raw["api"] = ["tag": "caller-direct-api", "listen": "127.0.0.1:10808", "services": ["StatsService"]]
        raw["stats"] = [String: Any]()
        raw["policy"] = ["system": ["statsInboundUplink": false, "statsInboundDownlink": false,
            "statsOutboundUplink": false, "statsOutboundDownlink": false]]
        let sourceOutbounds = raw["outbounds"] as! [[String: Any]]
        let source = try JSONSerialization.data(withJSONObject: raw)
        guard let prepared = TunnelXrayConfigPreparer.prepare(jsonData: source, credentials: credentials, resolveIPv4: { _ in
            preconditionFailure("Direct-only runtime must not bootstrap a proxy endpoint")
        }) else { preconditionFailure("Direct-only runtime preparation failed") }
        let effective = try JSONSerialization.jsonObject(with: prepared.data) as! [String: Any]
        precondition(effective["dns"] as! NSDictionary == dns as NSDictionary)
        precondition(effective["api"] as! NSDictionary == raw["api"] as! NSDictionary)
        let callerSelectors = (raw["routing"] as? [String: Any])?["balancers"] as? NSArray
        precondition(((effective["routing"] as? [String: Any])?["balancers"] as? NSArray) == callerSelectors)
        let outbounds = effective["outbounds"] as! [[String: Any]]
        precondition(outbounds.prefix(sourceOutbounds.count).map { $0["protocol"] as! String } == sourceOutbounds.map { $0["protocol"] as! String })
        precondition(outbounds.prefix(sourceOutbounds.count).map { $0["tag"] as! String } == sourceOutbounds.map { $0["tag"] as! String })
        let port = TunnelXrayConfigPreparer.parseConfig(jsonData: prepared.data)!.inboundPort
        var error: NSError?
        precondition(XRayStartPrivate(prepared.data, ProbeLogger(), &error))
        defer { XRayStop() }
        func checkAPI() {
            let fd = openLoopback(10808); defer { close(fd) }
            precondition(LocalSOCKS5Client.sendAll(fd: fd, bytes: Array("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8) + [0, 0, 0, 4, 0, 0, 0, 0, 0]))
            let frame = LocalSOCKS5Client.receiveExactly(fd: fd, count: 9) ?? []
            precondition(frame.count == 9 && frame[3] == 4 && frame.suffix(4).allSatisfy { $0 == 0 })
        }
        checkAPI()
        func checkHTTP() throws {
            let fd = try LocalSOCKS5Client.openConnection(proxyPort: port, credentials: credentials, host: "direct-only.invalid", port: 18096)
            defer { close(fd) }
            precondition(LocalSOCKS5Client.sendAll(fd: fd, bytes: Array("GET /direct-only HTTP/1.1\r\nHost: direct-only.invalid\r\nConnection: close\r\n\r\n".utf8)))
            precondition(LocalSOCKS5Client.receiveExactly(fd: fd, count: expected.count) == expected)
        }
        try checkHTTP()
        precondition(origin.state().0 == index * 2 + 1)
        do {
            let blocked = openLoopback(port); defer { close(blocked) }
            precondition(LocalSOCKS5Client.authenticate(fd: blocked, credentials: credentials))
            // Distinguish peer closure/reset from a read timeout; a silent
            // stalled request is not evidence that caller blocking survived.
            func readOrClosed(_ count: Int) -> [UInt8]? {
                var bytes = [UInt8](repeating: 0, count: count); var offset = 0
                while offset < count {
                    let n = bytes.withUnsafeMutableBytes { recv(blocked, $0.baseAddress!.advanced(by: offset), count - offset, 0) }
                    if n == 0 || (n < 0 && errno == ECONNRESET) { return nil }
                    if n < 0 && errno == EINTR { continue }
                    precondition(n > 0, "Blocked connection timed out or failed without an explicit refusal")
                    offset += n
                }
                return bytes
            }
            let host = Array("blocked.invalid".utf8)
            precondition(LocalSOCKS5Client.sendAll(fd: blocked, bytes: [5, 1, 0, 3, UInt8(host.count)] + host + [UInt8(18096 >> 8), UInt8(18096 & 255)]))
            if let header = readOrClosed(4) {
                precondition(header[0] == 5 && header[2] == 0)
                if header[1] == 0 {
                    precondition(header[3] == 1 || header[3] == 4)
                    if readOrClosed(header[3] == 1 ? 6 : 18) != nil {
                        _ = LocalSOCKS5Client.sendAll(fd: blocked, bytes: Array("GET /blocked HTTP/1.1\r\nHost: blocked.invalid\r\nConnection: close\r\n\r\n".utf8))
                        precondition(readOrClosed(1) == nil, "Blocked connection returned payload bytes")
                    }
                }
            }
        }
        try checkHTTP()
        precondition(origin.state().0 == (index + 1) * 2, "Caller block/default order was bypassed")
        for udp in [false, true] {
            let id = UInt16(0x5800 + index * 2 + (udp ? 1 : 0))
            let answer = try queryVirtualDNS(proxyPort: port, credentials: credentials, udp: udp, id: id)
            precondition(answer != nil && answer!.prefix(2).elementsEqual([UInt8(id >> 8), UInt8(id & 255)]))
            precondition(answer![3] & 15 == 0 && answer![6] == 0 && answer![7] == 1 && answer!.suffix(4).elementsEqual([192, 0, 2, 14]))
        }
        precondition(trap.count() == 0, "Caller static hosts must not query any resolver")
        checkAPI(); XRayStop()
        print("DIRECT_ONLY_RUNTIME_PASS=\(index)")
    }
    origin.stop()
    precondition(origin.state().0 == 6 && origin.connections() == 6 && !origin.state().1)
}

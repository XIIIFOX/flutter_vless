import XCTest
@testable import flutter_vless_macos_tunnel_support

final class TunnelDNSPolicyTests: XCTestCase {
    private static let credentials = try! LocalProxyCredentials(username: "test-session", password: "test-session-password")
    func testStartupRetriesEndpointResolutionAndProducesRecoverableRuntime() async throws {
        let data = Data(#"{"inbounds":[{"protocol":"socks","port":10808}],"outbounds":[{"protocol":"http","settings":{"address":"bootstrap.invalid","port":443}}]}"#.utf8)
        var attempts = 0
        var pauses = 0
        let prepared = try await TunnelXrayConfigPreparer.prepareForStartup(jsonData: data, credentials: Self.credentials,
            resolveIPv4: { _ in attempts += 1; return attempts < 3 ? nil : "203.0.113.7" },
            retryDelay: { pauses += 1 })
        XCTAssertEqual(attempts, 3)
        XCTAssertEqual(pauses, 2)
        XCTAssertEqual(prepared.bootstrapAddresses, ["203.0.113.7"])
        XCTAssertEqual(TunnelXrayConfigPreparer.parseConfig(jsonData: prepared.data)?.inboundPort, 10809)
        do {
            _ = try await TunnelXrayConfigPreparer.prepareForStartup(jsonData: data, credentials: Self.credentials,
                resolveIPv4: { _ in nil }, attempts: 2, retryDelay: {})
            XCTFail("Unavailable endpoints must fail startup, never install a runtime-less tunnel")
        } catch { XCTAssertTrue(error is TunnelXrayConfigPreparer.StartupError) }
        do {
            _ = try await TunnelXrayConfigPreparer.prepareForStartup(jsonData: Data("{}".utf8), credentials: Self.credentials,
                resolveIPv4: { _ in XCTFail("Invalid input must not resolve"); return nil },
                retryDelay: { XCTFail("Invalid configuration must not retry") })
            XCTFail("Invalid input must fail startup")
        } catch { XCTAssertTrue(error is TunnelXrayConfigPreparer.StartupError) }
    }

    func testStartupCancellationDuringBackoffCannotPublishPreparedRuntime() async throws {
        let waiting = expectation(description: "bootstrap retry")
        let data = Data(#"{"inbounds":[{"protocol":"socks","port":10808}],"outbounds":[{"protocol":"http","settings":{"address":"bootstrap.invalid","port":443}}]}"#.utf8)
        let task = Task {
            try await TunnelXrayConfigPreparer.prepareForStartup(jsonData: data, credentials: Self.credentials,
                resolveIPv4: { _ in nil }, retryDelay: {
                    waiting.fulfill()
                    try await Task.sleep(nanoseconds: 30_000_000_000)
                })
        }
        await fulfillment(of: [waiting], timeout: 2)
        task.cancel()
        do { _ = try await task.value; XCTFail("Stopped startup must not complete") }
        catch { XCTAssertTrue(error is CancellationError) }
    }

    func testHTTPAndSocksDNSUseRootClientAndKeepApplicationRules() throws {
        for proto in ["http", "socks"] {
            let applicationRule: [String: Any] = ["inboundTag": ["socks-direct"], "outboundTag": "direct"]
            let input: [String: Any] = [
                "inbounds": [["tag": "socks-in", "listen": "127.0.0.1", "protocol": "socks", "port": 10808]],
                "outbounds": [
                    ["tag": "proxy", "protocol": proto, "settings": ["servers": [["address": "proxy.example", "port": 443]]]],
                    ["tag": "direct", "protocol": "freedom"]
                ], "routing": ["rules": [applicationRule]]
            ]
            let prepared = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: JSONSerialization.data(withJSONObject: input), credentials: Self.credentials, resolveIPv4: { _ in "203.0.113.7" }))
            let output = try XCTUnwrap(JSONSerialization.jsonObject(with: prepared.data) as? [String: Any])
            let dns = try XCTUnwrap(output["dns"] as? [String: Any])
            let server = try XCTUnwrap((dns["servers"] as? [[String: Any]])?.first)
            XCTAssertEqual(server["address"] as? String, "tcp://1.1.1.1")
            XCTAssertNil(dns["hosts"])
            let outbounds = try XCTUnwrap(output["outbounds"] as? [[String: Any]])
            XCTAssertEqual(outbounds.prefix(2).compactMap { $0["tag"] as? String }, ["proxy", "direct"])
            let relay = try XCTUnwrap(outbounds.first { ($0["protocol"] as? String) == "dns" })
            XCTAssertNil(relay["streamSettings"])
            let rules = try XCTUnwrap((output["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
            XCTAssertTrue(rules.contains { ($0["inboundTag"] as? [String]) == [server["tag"] as! String] && ($0["outboundTag"] as? String) == "proxy" && ($0["ip"] as? [String]) == ["1.1.1.1/32"] })
            let managed = try XCTUnwrap((output["inbounds"] as? [[String: Any]])?.first?["tag"] as? String)
            XCTAssertTrue(rules.contains { ($0["ip"] as? [String]) == ["198.18.0.2/32"] && ($0["inboundTag"] as? [String]) == [managed] })
            XCTAssertEqual(rules.last! as NSDictionary, applicationRule as NSDictionary)
            XCTAssertEqual(prepared.bootstrapAddresses, ["203.0.113.7"])
            if let directory = ProcessInfo.processInfo.environment["TUNNEL_DNS_FIXTURES"] {
                try prepared.data.write(to: URL(fileURLWithPath: directory).appendingPathComponent(proto + ".json"))
            }
        }
    }

    func testBootstrapFailureRejectsButTagCollisionsAllocatePrivateNames() {
        var config: [String: Any] = ["outbounds": [["protocol": "http", "settings": ["address": "unresolved.example", "port": 443]]]]
        XCTAssertNil(TunnelDNSPolicy.apply(to: &config, managedInboundTag: "fixture-tun", resolveIPv4: { _ in nil }))
        config["inbounds"] = [["tag": "flutter-vless-dns-upstream"]]
        XCTAssertNotNil(TunnelDNSPolicy.apply(to: &config, managedInboundTag: "fixture-tun", resolveIPv4: { _ in "203.0.113.7" }))
        XCTAssertEqual((((config["dns"] as? [String: Any])?["servers"] as? [[String: Any]])?.first)?["tag"] as? String, "flutter-vless-dns-upstream-1")
    }

    func testNestedXHTTPDownloadBootstrapAndCredentialsStayIntact() throws {
        var config: [String: Any] = ["outbounds": [[
            "protocol": "vless", "settings": ["vnext": [["address": "primary.example", "port": 443, "users": [["id": "test-uuid", "encryption": "preserve-exactly"]]]]],
            "streamSettings": ["network": "xhttp", "xhttpSettings": ["extra": ["downloadSettings": [
                "address": "download.example", "port": 443, "sockopt": ["tcpKeepAliveIdle": 30]
            ]]]]
        ]]]
        var resolved: [String] = []
        XCTAssertNotNil(TunnelDNSPolicy.apply(to: &config, managedInboundTag: "fixture-tun", resolveIPv4: { host in
            resolved.append(host)
            return "203.0.113.7"
        }))
        XCTAssertEqual(Set(resolved), ["primary.example", "download.example"])
        let output = String(decoding: try JSONSerialization.data(withJSONObject: config), as: UTF8.self)
        XCTAssertTrue(output.contains("preserve-exactly"))
        XCTAssertTrue(output.contains("test-uuid"))
        XCTAssertTrue(output.contains("tcpKeepAliveIdle"))
        XCTAssertEqual(output.components(separatedBy: "ForceIPv4").count - 1, 2)
        XCTAssertEqual(output.components(separatedBy: "AsIs").count - 1, 2)
    }

    func testDNSAddressCannotBeExcludedButServerAndLANBypassesRemain() {
        for subnet in ["198.18.0.2/32", "198.18.0.0/16", "0.0.0.0/0"] {
            XCTAssertFalse(TunnelDNSPolicy.allowsRouteExclusions([subnet]))
        }
        XCTAssertTrue(TunnelDNSPolicy.allowsRouteExclusions(["203.0.113.7/32", "192.168.0.0/16", "1.1.1.1/32"]))
    }

    func testWireGuardPeersPinAddressesBeforeCoreLookupWithoutChangingKeys() throws {
        let settings: [String: Any] = ["secretKey": "private-key-marker", "peers": [
            ["endpoint": "wg.example:51820", "publicKey": "public-key-marker"],
            ["endpoint": "[2001:db8::1]:51820", "publicKey": "second-key"]
        ]]
        var config: [String: Any] = ["outbounds": [["protocol": "wireguard", "settings": settings]]]
        XCTAssertEqual(TunnelDNSPolicy.apply(to: &config, managedInboundTag: "fixture-tun", resolveIPv4: { _ in "203.0.113.7" }),
                       ["2001:db8::1", "203.0.113.7"])
        let outbounds = try XCTUnwrap(config["outbounds"] as? [[String: Any]])
        var pinned = settings
        var peers = try XCTUnwrap(settings["peers"] as? [[String: Any]])
        peers[0]["endpoint"] = "203.0.113.7:51820"
        pinned["peers"] = peers
        XCTAssertEqual(outbounds[0]["settings"] as? NSDictionary, pinned as NSDictionary)
    }

    func testAbsoluteDNSNameMatchesXrayHostLookup() throws {
        var config: [String: Any] = ["outbounds": [["protocol": "http", "settings": ["address": "Proxy.Example.", "port": 443]]]]
        XCTAssertNotNil(TunnelDNSPolicy.apply(to: &config, managedInboundTag: "fixture-tun", resolveIPv4: { _ in "203.0.113.7" }))
        let dns = try XCTUnwrap(config["dns"] as? [String: Any])
        XCTAssertNil(dns["hosts"])
        let rules = try XCTUnwrap((config["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
        XCTAssertTrue(rules.contains { ($0["domain"] as? [String])?.contains("full:proxy.example") == true })
        let outbounds = try XCTUnwrap(config["outbounds"] as? [[String: Any]])
        XCTAssertEqual((outbounds[0]["settings"] as? [String: Any])?["address"] as? String, "Proxy.Example.")
    }

    func testModernEndpointAndExtraPrecedenceMatchXray() throws {
        var config: [String: Any] = ["outbounds": [[
            "protocol": "HTTP", "settings": ["address": "active.example", "port": 443,
                                                "servers": [["address": "ignored.example", "port": 443]]],
            "streamSettings": ["network": "xhttp", "xhttpSettings": [
                "downloadSettings": ["address": "ignored-download.example"],
                "extra": ["downloadSettings": ["address": "active-download.example", "port": 8443]]
            ]]
        ]]]
        var resolved: [String] = []
        XCTAssertNotNil(TunnelDNSPolicy.apply(to: &config, managedInboundTag: "fixture-tun", resolveIPv4: { host in
            resolved.append(host)
            return host.hasPrefix("active") ? "203.0.113.7" : nil
        }))
        XCTAssertEqual(Set(resolved), ["active.example", "active-download.example"])
    }

    func testCallerDNSRemainsTheRootPolicyWithoutBootstrapHostPollution() throws {
        let callerDNS: [String: Any] = [
            "hosts": ["proxy.example": "192.0.2.44", "static.example": ["192.0.2.10", "2001:db8::10"], "blocked.example": "rcode://success"],
            "servers": [
                ["address": "tcp://9.9.9.9", "domains": ["domain:private.example"], "tag": "caller-domain-dns", "skipFallback": true, "queryStrategy": "UseIPv4", "timeoutMs": 2300],
                ["address": "https://1.1.1.1/dns-query", "tag": "caller-doh", "disableCache": true]
            ],
            "tag": "caller-root-dns", "queryStrategy": "UseIP", "disableFallbackIfMatch": true,
            "clientIp": "192.0.2.12", "disableCache": true
        ]
        var config: [String: Any] = ["dns": callerDNS, "outbounds": [["tag": "proxy", "protocol": "http", "settings": ["address": "proxy.example", "port": 443]]]]
        XCTAssertEqual(TunnelDNSPolicy.apply(to: &config, managedInboundTag: "fixture-tun", resolveIPv4: { _ in "203.0.113.7" }), ["203.0.113.7"])
        XCTAssertEqual(config["dns"] as? NSDictionary, callerDNS as NSDictionary)
        let primary = try XCTUnwrap((config["outbounds"] as? [[String: Any]])?.first)
        XCTAssertEqual((primary["settings"] as? [String: Any])?["address"] as? String, "proxy.example")
    }

    func testSystemAQueriesUseRootClientAndUnsupportedTypesNeverDirectFromVirtualDNS() throws {
        var config: [String: Any] = ["outbounds": [["tag": "proxy", "protocol": "http", "settings": ["address": "203.0.113.7", "port": 443]]]]
        XCTAssertNotNil(TunnelDNSPolicy.apply(to: &config, managedInboundTag: "fixture-tun", resolveIPv4: { _ in XCTFail("Literal endpoint must not resolve"); return nil }))
        let relay = try XCTUnwrap((config["outbounds"] as? [[String: Any]])?.first { ($0["protocol"] as? String) == "dns" })
        let rules = try XCTUnwrap((relay["settings"] as? [String: Any])?["rules"] as? [[String: Any]])
        XCTAssertEqual(rules.first { ($0["qType"] as? String) == "1" }?["action"] as? String, "hijack")
        XCTAssertEqual(rules.first { ($0["qType"] as? String) == "28" }?["action"] as? String, "return")
        XCTAssertEqual(rules.last?["action"] as? String, "return")
        XCTAssertEqual(rules.last?["rCode"] as? Int, 5)
        XCTAssertFalse(rules.contains { ($0["action"] as? String) == "direct" })
    }

    func testPrivatePinsRetainEndpointIdentityPortsAndSocketSettings() throws {
        let settings: [String: Any] = ["address": "proxy.example", "port": 8443, "password": "unchanged"]
        let stream: [String: Any] = ["network": "ws", "security": "tls", "tlsSettings": ["serverName": "sni.example"], "wsSettings": ["headers": ["Host": "host.example"]], "sockopt": ["tcpKeepAliveIdle": 45]]
        var config: [String: Any] = ["dns": ["servers": ["9.9.9.9"]], "outbounds": [["tag": "proxy", "protocol": "http", "settings": settings, "streamSettings": stream, "sendThrough": "192.0.2.9"], ["tag": "direct", "protocol": "freedom"]]]
        XCTAssertNotNil(TunnelDNSPolicy.apply(to: &config, managedInboundTag: "tun", resolveIPv4: { _ in "203.0.113.7" }))
        let outputs = try XCTUnwrap(config["outbounds"] as? [[String: Any]])
        XCTAssertEqual(outputs[0]["settings"] as? NSDictionary, settings as NSDictionary)
        let actual = try XCTUnwrap(outputs[0]["streamSettings"] as? [String: Any])
        XCTAssertEqual(actual["tlsSettings"] as? NSDictionary, stream["tlsSettings"] as? NSDictionary)
        XCTAssertEqual(actual["wsSettings"] as? NSDictionary, stream["wsSettings"] as? NSDictionary)
        let socket = try XCTUnwrap(actual["sockopt"] as? [String: Any])
        XCTAssertEqual(socket["domainStrategy"] as? String, "AsIs")
        let loop = try XCTUnwrap(outputs.first { ($0["tag"] as? String) == socket["dialerProxy"] as? String })
        let scope = try XCTUnwrap((loop["settings"] as? [String: Any])?["inboundTag"] as? String)
        let rules = try XCTUnwrap((config["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
        let scoped = rules.filter { ($0["inboundTag"] as? [String]) == [scope] }
        XCTAssertEqual(scoped.count, 2)
        XCTAssertEqual(scoped[0]["domain"] as? [String], ["full:proxy.example"])
        XCTAssertEqual(scoped[0]["port"] as? String, "8443")
        let leaf = try XCTUnwrap(outputs.first { ($0["tag"] as? String) == scoped[0]["outboundTag"] as? String })
        XCTAssertEqual((leaf["settings"] as? [String: Any])?["redirect"] as? String, "203.0.113.7:0")
        XCTAssertEqual(leaf["sendThrough"] as? String, "192.0.2.9")
        XCTAssertEqual(((leaf["streamSettings"] as? [String: Any])?["sockopt"] as? [String: Any])?["tcpKeepAliveIdle"] as? Int, 45)
        XCTAssertEqual(outputs.first { ($0["tag"] as? String) == scoped.last?["outboundTag"] as? String }?["protocol"] as? String, "blackhole")
    }

    func testLogicalDialerChainUsesOnlyThePhysicalHandlersPins() throws {
        let first: [String: Any] = ["tag": "proxy", "protocol": "http", "settings": ["address": "remote-only.example", "port": 443], "streamSettings": ["sockopt": ["dialerProxy": "carrier", "domainStrategy": "ForceIP"]]]
        var config: [String: Any] = ["outbounds": [first, ["tag": "carrier", "protocol": "socks", "settings": ["address": "carrier.example", "port": 1080]]]]
        var names: [String] = []
        XCTAssertNotNil(TunnelDNSPolicy.apply(to: &config, managedInboundTag: "tun", resolveIPv4: { names.append($0); return $0 == "carrier.example" ? "203.0.113.7" : nil }))
        XCTAssertEqual(names, ["carrier.example"])
        let outputs = try XCTUnwrap(config["outbounds"] as? [[String: Any]])
        XCTAssertEqual(outputs[0]["settings"] as? NSDictionary, first["settings"] as? NSDictionary)
        XCTAssertEqual(((outputs[0]["streamSettings"] as? [String: Any])?["sockopt"] as? [String: String]), ["dialerProxy": "carrier", "domainStrategy": "AsIs"])
        for target in ["proxy", "missing"] {
            var bad: [String: Any] = ["outbounds": [["tag": "proxy", "protocol": "http", "settings": ["address": "logical.example", "port": 443], "streamSettings": ["sockopt": ["dialerProxy": target]]]]]
            let original = bad as NSDictionary
            XCTAssertNil(TunnelDNSPolicy.apply(to: &bad, managedInboundTag: "tun", resolveIPv4: { _ in XCTFail("Invalid chain must not resolve"); return nil }))
            XCTAssertEqual(bad as NSDictionary, original)
        }
    }

    func testMissingAndCyclicDownloadChainsCannotReachPhysicalFallback() {
        for target in ["missing", "proxy"] {
            var config: [String: Any] = ["outbounds": [["tag": "proxy", "protocol": "http", "settings": ["address": "proxy.example", "port": 443], "streamSettings": ["network": "xhttp", "xhttpSettings": ["downloadSettings": ["address": "download.example", "port": 8443, "sockopt": ["dialerProxy": target]]]]]]]
            let original = config as NSDictionary
            XCTAssertNil(TunnelDNSPolicy.apply(to: &config, managedInboundTag: "tun", resolveIPv4: { _ in XCTFail("Invalid chain must reject before lookup"); return nil }))
            XCTAssertEqual(config as NSDictionary, original)
        }
    }

    func testLocalDefaultRetainsPerDomainFieldsAndCallerTag() throws {
        let local: [String: Any] = ["Address": "localhost", "Tag": "caller-local", "domains": ["domain:home"], "skipFallback": true, "timeoutMs": 1900, "queryStrategy": "UseIPv4"]
        let remote: [String: Any] = ["address": "tcp://9.9.9.9", "tag": "caller-remote"]
        var config: [String: Any] = ["dns": ["queryStrategy": "UseIPv4", "hosts": ["static.example": "192.0.2.3"], "servers": [local, remote]], "outbounds": [["tag": "proxy", "protocol": "http", "settings": ["address": "203.0.113.7", "port": 443]]]]
        XCTAssertNotNil(TunnelDNSPolicy.apply(to: &config, managedInboundTag: "tun", resolveIPv4: { _ in nil }))
        let dns = try XCTUnwrap(config["dns"] as? [String: Any])
        let entries = try XCTUnwrap(dns["servers"] as? [[String: Any]])
        var expected = local; expected["Address"] = "tcp://1.1.1.1"
        XCTAssertEqual(entries[0] as NSDictionary, expected as NSDictionary)
        XCTAssertEqual(entries[1] as NSDictionary, remote as NSDictionary)
        XCTAssertEqual(dns["hosts"] as? [String: String], ["static.example": "192.0.2.3"])
        let rules = try XCTUnwrap((config["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
        XCTAssertTrue(rules.contains { ($0["inboundTag"] as? [String]) == ["caller-local"] && ($0["ip"] as? [String]) == ["1.1.1.1/32"] && ($0["port"] as? String) == "53" })
    }

    func testUnsafeDNSPathsAndAmbiguityRejectWithoutMutation() {
        let unsafe: [[String: Any]] = [
            ["servers": ["https+local://1.1.1.1/dns-query"]], ["servers": ["tcp+local://1.1.1.1"]],
            ["servers": ["quic+local://1.1.1.1"]], ["servers": ["tls://1.1.1.1"]], ["servers": ["fakedns"]], ["servers": ["2001:db8::1"]], ["servers": ["https://[2001:db8::1]/dns-query"]],
            ["servers": ["https://unmapped.example/dns-query"]], ["servers": ["1.1.1.1"], "useSystemHosts": true],
            ["servers": ["1.1.1.1"], "queryStrategy": "UseSystem"], ["servers": [], "Servers": []],
            ["servers": [["address": "1.1.1.1", "Address": "9.9.9.9"]]], ["script": "caller-script"],
            ["hosts": ["doh.example": "alias.example"], "servers": ["https://doh.example/dns-query"]]
        ]
        for dns in unsafe {
            var config: [String: Any] = ["dns": dns, "outbounds": [["protocol": "http", "settings": ["address": "proxy.example", "port": 443]]]]
            let original = config as NSDictionary
            XCTAssertNil(TunnelDNSPolicy.apply(to: &config, managedInboundTag: "tun", resolveIPv4: { _ in XCTFail("Unsafe DNS must reject before bootstrap"); return nil }))
            XCTAssertEqual(config as NSDictionary, original)
        }
    }

    func testStaticMappedDoHPreservesURLAndCallerHosts() throws {
        for mapping: Any in ["192.0.2.80", ["192.0.2.80", "192.0.2.81"]] {
            let dns: [String: Any] = ["hosts": ["doh.example": mapping], "servers": [["address": "https://doh.example/dns-query", "domains": ["domain:private.example"], "tag": "caller-doh"]], "queryStrategy": "UseIPv4"]
            var config: [String: Any] = ["dns": dns, "outbounds": [["tag": "proxy", "protocol": "http", "settings": ["address": "203.0.113.7", "port": 443]], ["tag": "direct", "protocol": "freedom"]]]
            XCTAssertNotNil(TunnelDNSPolicy.apply(to: &config, managedInboundTag: "tun", resolveIPv4: { _ in nil }))
            XCTAssertEqual(config["dns"] as? NSDictionary, dns as NSDictionary)
            let direct = try XCTUnwrap((config["outbounds"] as? [[String: Any]])?.first { ($0["tag"] as? String) == "direct" })
            XCTAssertEqual(((direct["streamSettings"] as? [String: Any])?["sockopt"] as? [String: Any])?["domainStrategy"] as? String, "ForceIPv4")
            XCTAssertEqual((direct["settings"] as? [String: Any])?["domainStrategy"] as? String, "ForceIPv4")
            XCTAssertNil((direct["settings"] as? [String: Any])?["targetStrategy"])
        }
    }

    func testSystemStrategyAliasesRejectAndNullOrEmptyDefaultsRemainProtected() throws {
        let proxy: [String: Any] = ["protocol": "http", "settings": ["address": "203.0.113.7", "port": 443]]
        for spelling in ["UseSys", "UseSystem", "use_sys", "use_system", "use-sys", "use-system"] {
            for dns in [["queryStrategy": spelling], ["servers": [["address": "1.1.1.1", "queryStrategy": spelling]]]] as [[String: Any]] {
                var config: [String: Any] = ["dns": dns, "outbounds": [proxy]]
                XCTAssertNil(TunnelDNSPolicy.apply(to: &config, managedInboundTag: "tun", resolveIPv4: { _ in nil }))
            }
        }
        for servers: Any in [NSNull(), [Any]()] {
            for script: Any in [NSNull(), ""] {
                var config: [String: Any] = ["dns": ["servers": servers, "script": script], "outbounds": [proxy]]
                XCTAssertNotNil(TunnelDNSPolicy.apply(to: &config, managedInboundTag: "tun", resolveIPv4: { _ in nil }))
                XCTAssertEqual((((config["dns"] as? [String: Any])?["servers"] as? [[String: Any]])?.first)?["address"] as? String, "tcp://1.1.1.1")
            }
        }
    }

    func testNativeDNSFixtureExport() throws {
        let env = ProcessInfo.processInfo.environment
        guard let source = env["TUNNEL_DNS_SOURCE_JSON"], let destination = env["TUNNEL_DNS_OUTPUT_JSON"] else { return }
        let credentials = try LocalProxyCredentials(username: "session-user", password: "session-password")
        let host = env["TUNNEL_DNS_BOOTSTRAP_HOST"] ?? "endpoint.test.invalid"
        let ip = env["TUNNEL_DNS_BOOTSTRAP_IPV4"] ?? "127.0.0.1"
        let prepared = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: Data(contentsOf: URL(fileURLWithPath: source)), credentials: credentials, resolveIPv4: { name in
            XCTAssertEqual(name, host, "Fixture must never perform an OS bootstrap lookup")
            return name == host ? ip : nil
        }))
        try prepared.data.write(to: URL(fileURLWithPath: destination))
        XCTAssertFalse(prepared.data.isEmpty)
    }
}

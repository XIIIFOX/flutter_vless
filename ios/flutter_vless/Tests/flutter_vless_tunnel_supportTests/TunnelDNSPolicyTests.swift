import XCTest
import Darwin
@testable import flutter_vless_tunnel_support

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

    func testSystemAddressQueriesUseRootClientAndUnsupportedTypesNeverDirectFromVirtualDNS() throws {
        var config: [String: Any] = ["outbounds": [["tag": "proxy", "protocol": "http", "settings": ["address": "203.0.113.7", "port": 443]]]]
        XCTAssertNotNil(TunnelDNSPolicy.apply(to: &config, managedInboundTag: "fixture-tun", resolveIPv4: { _ in XCTFail("Literal endpoint must not resolve"); return nil }))
        let relay = try XCTUnwrap((config["outbounds"] as? [[String: Any]])?.first { ($0["protocol"] as? String) == "dns" })
        let rules = try XCTUnwrap((relay["settings"] as? [String: Any])?["rules"] as? [[String: Any]])
        XCTAssertEqual(rules.first { ($0["qType"] as? String) == "1" }?["action"] as? String, "hijack")
        XCTAssertEqual(rules.first { ($0["qType"] as? String) == "28" }?["action"] as? String, "hijack")
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

    func testLocalDefaultRejectsInvalidTagTypesWithoutMutation() throws {
        let invalid: [Any] = [false, true, 7, ["tag"], ["value": "tag"]]
        for value in invalid {
            let original: [String: Any] = ["dns": ["servers": [["address": "localhost", "tag": value]]],
                "outbounds": [["tag": "proxy", "protocol": "http", "settings": ["address": "203.0.113.7", "port": 443]]]]
            var config = original
            XCTAssertNil(TunnelDNSPolicy.apply(to: &config, managedInboundTag: "tun", resolveIPv4: { _ in
                XCTFail("Invalid local tag must reject before bootstrap"); return nil
            }), "Invalid tag: \(value)")
            XCTAssertEqual(config as NSDictionary, original as NSDictionary)
        }
    }

    func testSharedLocalDefaultTagFormsHaveEquivalentEffectiveConfiguration() throws {
        var root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<10 {
            if FileManager.default.fileExists(atPath: root.appendingPathComponent("tool/fixtures/compatibility/dns-default-tags.json").path) { break }
            root.deleteLastPathComponent()
        }
        let cases = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: root.appendingPathComponent("tool/fixtures/compatibility/dns-default-tags.json"))) as? [[String: Any]])
        XCTAssertEqual(cases.count, 3)
        var baseline: Data?
        for item in cases {
            let original = try XCTUnwrap(item["config"] as? [String: Any])
            let source = try JSONSerialization.data(withJSONObject: original, options: [.sortedKeys])
            let prepared = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: source, credentials: Self.credentials, resolveIPv4: { _ in "203.0.113.7" }))
            let output = try XCTUnwrap(JSONSerialization.jsonObject(with: prepared.data) as? [String: Any])
            let effective = try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys])
            if let baseline { XCTAssertEqual(effective, baseline, item["name"] as? String ?? "") }
            else { baseline = effective }
            let dns = try XCTUnwrap(output["dns"] as? [String: Any])
            let server = try XCTUnwrap((dns["servers"] as? [[String: Any]])?.first)
            let sourceDNS = try XCTUnwrap(original["dns"] as? [String: Any])
            var expected = try XCTUnwrap((sourceDNS["servers"] as? [[String: Any]])?.first)
            expected["address"] = "tcp://1.1.1.1"
            expected["tag"] = "flutter-vless-dns-upstream"
            XCTAssertEqual(server as NSDictionary, expected as NSDictionary)
            XCTAssertEqual(dns["hosts"] as? NSDictionary, sourceDNS["hosts"] as? NSDictionary)
            XCTAssertEqual(dns["tag"] as? String, "caller-root-dns")
            XCTAssertEqual(try JSONSerialization.data(withJSONObject: original, options: [.sortedKeys]), source)
        }
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

    func testMappedDoHValidFullPrefixKeepsCallerPolicy() throws {
        for key in ["full:doh.example", "full:DOH.Example", "DOH.Example"] {
            let dns: [String: Any] = ["hosts": [key: ["192.0.2.53", "192.0.2.54"]],
                "servers": [["address": "https://doh.example/dns-query", "tag": "caller-doh", "domains": ["full:private.example"]]], "queryStrategy": "UseIP"]
            let original: [String: Any] = ["dns": dns, "outbounds": [["tag": "proxy", "protocol": "http", "settings": ["address": "endpoint.invalid", "port": 443]]]]
            let before = try JSONSerialization.data(withJSONObject: original, options: [.sortedKeys])
            var output = original; var lookups: [String] = []
            XCTAssertNotNil(TunnelDNSPolicy.apply(to: &output, managedInboundTag: "tun", resolveIPv4: { host in
                lookups.append(host); return host == "endpoint.invalid" ? "203.0.113.7" : nil
            }), key)
            XCTAssertEqual(lookups, ["endpoint.invalid"], "DoH must use caller hosts, not native bootstrap")
            XCTAssertEqual(output["dns"] as? NSDictionary, dns as NSDictionary)
            XCTAssertEqual(try JSONSerialization.data(withJSONObject: original, options: [.sortedKeys]), before)
        }
    }

    func testMappedDoHRejectsNonliteralFullPrefixBeforeBootstrap() throws {
        let badHosts: [[String: Any]] = [
            ["FULL:doh.example": "192.0.2.53"], ["Full:doh.example": "192.0.2.53"],
            ["full:doh.example.": "192.0.2.53"], ["doh.example.": "192.0.2.53"],
            ["domain:doh.example": "192.0.2.53"], ["full:doh.example": "alias.example"],
            ["full:doh.example": "2001:db8::53"], ["full:doh.example": ["192.0.2.53", "2001:db8::53"]]
        ]
        for hosts in badHosts {
            var source: [String: Any] = ["dns": ["hosts": hosts, "servers": ["https://doh.example/dns-query"]],
                "outbounds": [["tag": "proxy", "protocol": "http", "settings": ["address": "endpoint.invalid", "port": 443]]]]
            let before = try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys])
            XCTAssertNil(TunnelDNSPolicy.apply(to: &source, managedInboundTag: "tun", resolveIPv4: { _ in
                XCTFail("Unsafe DoH mapping must reject before endpoint bootstrap"); return "203.0.113.7"
            }))
            XCTAssertEqual(try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys]), before)
        }
    }

    func testMappedDoHGoCaseMappingDoesNotApplySchemaFold() throws {
        let cases = [("full:İnternal.invalid", "internal.invalid", true),
                     ("full:Key.invalid", "key.invalid", true),
                     ("full:doſ.invalid", "dos.invalid", false),
                     ("full:I\u{0307}nternal.invalid", "internal.invalid", false)]
        for (key, host, allowed) in cases {
            let dns: [String: Any] = ["hosts": [key: "192.0.2.53"], "servers": ["https://\(host)/dns-query"]]
            let original: [String: Any] = ["dns": dns, "outbounds": [["tag": "proxy", "protocol": "http", "settings": ["address": "endpoint.invalid", "port": 443]]]]
            let before = try JSONSerialization.data(withJSONObject: original, options: [.sortedKeys])
            var output = original; var lookups: [String] = []
            let result = TunnelDNSPolicy.apply(to: &output, managedInboundTag: "tun", resolveIPv4: { host in
                lookups.append(host); return "203.0.113.7"
            })
            if allowed {
                XCTAssertNotNil(result, key)
                XCTAssertEqual(lookups, ["endpoint.invalid"], key)
                XCTAssertEqual(output["dns"] as? NSDictionary, dns as NSDictionary)
            } else {
                XCTAssertNil(result, key)
                XCTAssertEqual(lookups, [], "A schema-only long-s fold must not authorize DNS")
                XCTAssertEqual(try JSONSerialization.data(withJSONObject: output, options: [.sortedKeys]), before)
            }
            XCTAssertEqual(try JSONSerialization.data(withJSONObject: original, options: [.sortedKeys]), before)
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

    func testMasquePrimaryUsesProtectedPinsAndPreservesTransportIdentity() throws {
        let settings: [String: Any] = ["address": "masque.example", "port": 8443, "remoteDNS": ["1.1.1.1", "9.9.9.9"]]
        let tls: [String: Any] = ["serverName": "masque-sni.example", "alpn": ["h2"]]
        let transport: [String: Any] = ["user": "fixture-user", "pass": "fixture-password", "host": "masque-host.example", "path": "/connect-ip/", "headers": ["X-Fixture": "masque-value"]]
        let original: [String: Any] = ["tag": "proxy", "protocol": "masque", "settings": settings, "streamSettings": ["network": "masque", "security": "tls", "tlsSettings": tls, "masqueSettings": transport]]
        var config: [String: Any] = ["dns": ["servers": ["tcp://9.9.9.9"]], "outbounds": [original]]
        var requests: [String] = []
        XCTAssertEqual(TunnelDNSPolicy.apply(to: &config, managedInboundTag: "tun", resolveIPv4: { requests.append($0); return "203.0.113.9" }), ["203.0.113.9"])
        XCTAssertEqual(requests, ["masque.example"])
        let primary = try XCTUnwrap((config["outbounds"] as? [[String: Any]])?.first)
        XCTAssertEqual(primary["settings"] as? NSDictionary, settings as NSDictionary)
        let stream = try XCTUnwrap(primary["streamSettings"] as? [String: Any])
        XCTAssertEqual(stream["tlsSettings"] as? NSDictionary, tls as NSDictionary)
        XCTAssertEqual(stream["masqueSettings"] as? NSDictionary, transport as NSDictionary)
        XCTAssertEqual((stream["sockopt"] as? [String: Any])?["domainStrategy"] as? String, "AsIs")
        XCTAssertNotNil((stream["sockopt"] as? [String: Any])?["dialerProxy"] as? String)
        let rules = try XCTUnwrap((config["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
        XCTAssertTrue(rules.contains { ($0["domain"] as? [String]) == ["full:masque.example"] && ($0["port"] as? String) == "8443" })
    }

    func testInternalHandlersBeforeSelectedProxyDoNotSuppressXHTTPProtection() throws {
        let internalDNS: [String: Any] = ["tag": "caller-dns", "protocol": "dns", "settings": ["rules": [["action": "return", "rCode": 5]]]]
        let loop: [String: Any] = ["tag": "caller-loop", "protocol": "loopback", "settings": ["inboundTag": "caller-loop-input"]]
        let other: [String: Any] = ["tag": "backup", "protocol": "http", "settings": ["address": "backup.example", "port": 8080]]
        for network in ["xhttp", "splithttp"] {
            let selected: [String: Any] = ["tag": "proxy", "protocol": "vless", "settings": ["address": "selected.example", "port": 443, "id": "22222222-2222-4222-8222-222222222222", "encryption": "none"], "streamSettings": ["network": "tcp", "method": network, "xhttpSettings": ["path": "/fixture"]]]
            let raw: [String: Any] = ["inbounds": [["protocol": "socks", "port": 10808]], "dns": ["servers": ["tcp://9.9.9.9"]], "outbounds": [internalDNS, loop, other, selected]]
            let prepared = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: JSONSerialization.data(withJSONObject: raw), credentials: Self.credentials, resolveIPv4: { _ in "203.0.113.9" }))
            XCTAssertTrue(prepared.proxyUsesXhttp)
            let output = try XCTUnwrap(JSONSerialization.jsonObject(with: prepared.data) as? [String: Any])
            let outbounds = try XCTUnwrap(output["outbounds"] as? [[String: Any]])
            XCTAssertEqual(outbounds[0] as NSDictionary, internalDNS as NSDictionary)
            XCTAssertEqual(outbounds[1] as NSDictionary, loop as NSDictionary)
            XCTAssertEqual(Array(outbounds.prefix(4)).compactMap { $0["tag"] as? String }, ["caller-dns", "caller-loop", "backup", "proxy"])
            let rules = try XCTUnwrap((output["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
            XCTAssertEqual(rules.filter { ($0["network"] as? String) == "udp" && ($0["port"] as? String) == "443" }.count, 1)
            let blockRule = try XCTUnwrap(rules.first { ($0["network"] as? String) == "udp" && ($0["port"] as? String) == "443" })
            let blocked = try XCTUnwrap(outbounds.first { ($0["tag"] as? String) == (blockRule["outboundTag"] as? String) })
            XCTAssertTrue(["blackhole", "block"].contains(blocked["protocol"] as? String ?? ""))
            XCTAssertEqual(TunnelXrayConfigPreparer.parseServerAddress(configJSON: output), "selected.example")
        }
    }

    func testExistingTransportMetadataAndMultipleOriginalOutboundsStayIntact() throws {
        let transports: [(String, String, [String: Any])] = [
            ("ws", "wsSettings", ["path": "/ws", "headers": ["Host": "ws-host.example"]]),
            ("grpc", "grpcSettings", ["serviceName": "caller-service", "authority": "grpc-host.example", "multiMode": true]),
            ("httpupgrade", "httpupgradeSettings", ["path": "/upgrade", "host": "upgrade-host.example"])
        ]
        var inputs: [[String: Any]] = []
        for (index, transport) in transports.enumerated() {
            inputs.append(["tag": index == 0 ? "proxy" : "backup-\(index)", "protocol": "http", "settings": ["address": "shared.example", "port": 8443 + index, "user": "user-\(index)", "pass": "pass-\(index)"], "streamSettings": ["network": transport.0, "security": "tls", "tlsSettings": ["serverName": "sni-\(index).example"], transport.1: transport.2]])
        }
        var config: [String: Any] = ["outbounds": inputs]
        var resolved: [String] = []
        XCTAssertEqual(TunnelDNSPolicy.apply(to: &config, managedInboundTag: "tun", resolveIPv4: { resolved.append($0); return "203.0.113.9" }), ["203.0.113.9"])
        XCTAssertEqual(resolved, ["shared.example"])
        let outputs = try XCTUnwrap(config["outbounds"] as? [[String: Any]])
        for (index, transport) in transports.enumerated() {
            XCTAssertEqual(outputs[index]["tag"] as? String, inputs[index]["tag"] as? String)
            XCTAssertEqual(outputs[index]["settings"] as? NSDictionary, inputs[index]["settings"] as? NSDictionary)
            let stream = try XCTUnwrap(outputs[index]["streamSettings"] as? [String: Any])
            XCTAssertEqual(stream[transport.1] as? NSDictionary, transport.2 as NSDictionary)
            XCTAssertEqual(stream["tlsSettings"] as? NSDictionary, (inputs[index]["streamSettings"] as? [String: Any])?["tlsSettings"] as? NSDictionary)
        }
        let rules = try XCTUnwrap((config["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
        XCTAssertEqual(Set(rules.compactMap { ($0["domain"] as? [String]) == ["full:shared.example"] ? $0["port"] as? String : nil }), ["8443", "8444", "8445"])
    }

    func testSharedEndpointEnvironmentMatchesLiteralControlWithoutChangingEditorFields() throws {
        func replace(_ object: Any, path: ArraySlice<String>, value: String) -> Any {
            guard let head = path.first else { return value }
            if var map = object as? [String: Any], let child = map[head] {
                map[head] = replace(child, path: path.dropFirst(), value: value); return map
            }
            var list = object as! [Any]; let index = Int(head)!
            list[index] = replace(list[index], path: path.dropFirst(), value: value); return list
        }
        var root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<10 {
            if FileManager.default.fileExists(atPath: root.appendingPathComponent("tool/fixtures/compatibility/endpoint-addresses.json").path) { break }
            root.deleteLastPathComponent()
        }
        let cases = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: root.appendingPathComponent("tool/fixtures/compatibility/endpoint-addresses.json"))) as? [[String: Any]])
        XCTAssertEqual(cases.count, 3)
        for item in cases {
            let original = try XCTUnwrap(item["config"] as? [String: Any])
            let environment = try XCTUnwrap(item["environment"] as? [String: String])
            let previous = environment.keys.map { ($0, getenv($0).map { String(cString: $0) }) }
            for (key, value) in environment { setenv(key, value, 1) }
            defer { for (key, value) in previous { if let value { setenv(key, value, 1) } else { unsetenv(key) } } }
            let input = try JSONSerialization.data(withJSONObject: original, options: [.sortedKeys])
            var literal: Any = original
            for (path, value) in try XCTUnwrap(item["resolvedAddresses"] as? [String: String]) {
                literal = replace(literal, path: ArraySlice(path.split(separator: ".").map(String.init)), value: value)
            }
            let control = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: JSONSerialization.data(withJSONObject: literal), credentials: Self.credentials, resolveIPv4: { $0 == "endpoint.invalid" ? "203.0.113.9" : nil }))
            guard let prepared = TunnelXrayConfigPreparer.prepare(jsonData: input, credentials: Self.credentials, resolveIPv4: { $0 == "endpoint.invalid" ? "203.0.113.9" : nil }) else {
                XCTFail("Core-valid endpoint environment rejected: \(item["name"] ?? "")"); continue
            }
            XCTAssertEqual(try JSONSerialization.jsonObject(with: prepared.data) as? NSDictionary, try JSONSerialization.jsonObject(with: control.data) as? NSDictionary)
            let output = try XCTUnwrap(JSONSerialization.jsonObject(with: prepared.data) as? [String: Any])
            XCTAssertEqual(output["dns"] as? NSDictionary, original["dns"] as? NSDictionary)
            XCTAssertEqual(output["custom"] as? NSDictionary, original["custom"] as? NSDictionary)
            XCTAssertEqual(output["remarks"] as? String, original["remarks"] as? String)
            XCTAssertEqual(try JSONSerialization.data(withJSONObject: original, options: [.sortedKeys]), input)
        }
    }

    func testSharedLogicalAddressEnvironmentMatchesLiteralAndKeepsHandlerContext() throws {
        func replace(_ object: Any, path: ArraySlice<String>, value: String) -> Any {
            guard let head = path.first else { return value }
            if var map = object as? [String: Any], let child = map[head] {
                map[head] = replace(child, path: path.dropFirst(), value: value); return map
            }
            var list = object as! [Any]; let index = Int(head)!
            list[index] = replace(list[index], path: path.dropFirst(), value: value); return list
        }
        var root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<10 {
            if FileManager.default.fileExists(atPath: root.appendingPathComponent("tool/fixtures/compatibility/logical-addresses.json").path) { break }
            root.deleteLastPathComponent()
        }
        let cases = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: root.appendingPathComponent("tool/fixtures/compatibility/logical-addresses.json"))) as? [[String: Any]])
        XCTAssertEqual(cases.count, 4)
        for item in cases {
            let original = try XCTUnwrap(item["config"] as? [String: Any])
            let environment = try XCTUnwrap(item["environment"] as? [String: String])
            let previous = environment.keys.map { ($0, getenv($0).map { String(cString: $0) }) }
            for (key, value) in environment { setenv(key, value, 1) }
            defer { for (key, value) in previous { if let value { setenv(key, value, 1) } else { unsetenv(key) } } }
            let input = try JSONSerialization.data(withJSONObject: original, options: [.sortedKeys])
            var literal: Any = original
            for binding in try XCTUnwrap(item["bindings"] as? [[String: Any]]) {
                literal = replace(literal, path: ArraySlice(try XCTUnwrap(binding["path"] as? [String])), value: try XCTUnwrap(binding["value"] as? String))
            }
            let expected = try XCTUnwrap(literal as? [String: Any])
            let control = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: JSONSerialization.data(withJSONObject: expected), credentials: Self.credentials,
                resolveIPv4: { _ in XCTFail("Logical targets must not cause transport bootstrap"); return nil }))
            let frozen = try TunnelXrayConfigPreparer.bindingEndpointEnvironment(configData: input, environment: environment)
            XCTAssertEqual(try JSONSerialization.jsonObject(with: frozen) as? NSDictionary, expected as NSDictionary)
            let prepared = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: input, credentials: Self.credentials,
                resolveIPv4: { _ in XCTFail("Logical targets must keep caller routing context"); return nil }))
            XCTAssertEqual(try JSONSerialization.jsonObject(with: prepared.data) as? NSDictionary, try JSONSerialization.jsonObject(with: control.data) as? NSDictionary)
            let changed = environment.mapValues { _ in "127.0.0.2" }
            for (key, value) in changed { setenv(key, value, 1) }
            XCTAssertEqual(try TunnelXrayConfigPreparer.bindingEndpointEnvironment(configData: frozen, environment: changed), frozen)
            let provider = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: frozen, credentials: Self.credentials,
                resolveIPv4: { _ in XCTFail("Frozen logical targets must not be resolved by native code"); return nil }))
            XCTAssertEqual(try JSONSerialization.jsonObject(with: provider.data) as? NSDictionary, try JSONSerialization.jsonObject(with: control.data) as? NSDictionary)
            XCTAssertEqual(try JSONSerialization.data(withJSONObject: original, options: [.sortedKeys]), input)
        }
    }

    func testLogicalAddressEnvironmentUsesEffectiveAliasWithoutOutboundRequirement() throws {
        for proto in ["dokodemo-door", "tunnel"] {
            for includeNull in [false, true] {
                var settings: [String: Any] = ["ReWrItEaDdReSs": "env: target.name ", "rewritePort": 18083, "allowedNetwork": "tcp", "custom": ["address": "env:OPAQUE"]]
                if includeNull { settings["AdDrEsS"] = NSNull() }
                let source: [String: Any] = ["inbounds": [["protocol": proto, "tag": "caller", "settings": settings]]]
                let data = try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys])
                let frozen = try TunnelXrayConfigPreparer.bindingEndpointEnvironment(configData: data, environment: ["TARGET_NAME": "[ logical.invalid ]"])
                let output = try XCTUnwrap(JSONSerialization.jsonObject(with: frozen) as? [String: Any])
                let target = try XCTUnwrap((output["inbounds"] as? [[String: Any]])?.first?["settings"] as? [String: Any])
                XCTAssertEqual(target["ReWrItEaDdReSs"] as? String, "[ logical.invalid ]")
                XCTAssertEqual(target["custom"] as? NSDictionary, settings["custom"] as? NSDictionary)
                XCTAssertNil(output["outbounds"])
                XCTAssertEqual(try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys]), data)
            }
        }
    }

    func testLogicalAddressEnvironmentNeverFallsBackFromNonnullPrimary() throws {
        for proto in ["dns", "dokodemo-door", "tunnel"] {
            let key = proto == "dns" ? "outbounds" : "inbounds"
            let primaries: [Any] = [false, 42, ["opaque": "env:PRIMARY"], ["env:PRIMARY"], ""]
            for primary in primaries {
                let source: [String: Any] = [key: [["protocol": proto, "settings": ["address": primary, "rewriteAddress": "env:DORMANT"]]]]
                let data = try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys])
                XCTAssertEqual(try TunnelXrayConfigPreparer.bindingEndpointEnvironment(configData: data, environment: ["DORMANT": "env:SECOND"]), data,
                    "Nonnull invalid primary remains Core preflight input; never select or expand a dormant alias")
            }
            let settings: [String: Any] = ["address": "env: target.name ", "rewriteAddress": "env:DORMANT"]
            let source: [String: Any] = [key: [["protocol": proto, "settings": settings]]]
            let frozen = try TunnelXrayConfigPreparer.bindingEndpointEnvironment(configData: JSONSerialization.data(withJSONObject: source), environment: [" target.name ": "", "TARGET_NAME": "wrong.invalid", "DORMANT": "env:SECOND"])
            let output = try XCTUnwrap(JSONSerialization.jsonObject(with: frozen) as? [String: Any])
            let bound = try XCTUnwrap((output[key] as? [[String: Any]])?.first?["settings"] as? [String: Any])
            XCTAssertEqual(bound["address"] as? String, "")
            XCTAssertEqual(bound["rewriteAddress"] as? String, "env:DORMANT")
            XCTAssertEqual(try TunnelXrayConfigPreparer.bindingEndpointEnvironment(configData: frozen, environment: ["TARGET_NAME": "different.invalid", "DORMANT": "127.0.0.2"]), frozen)
        }
    }

    func testLogicalAddressEnvironmentFailureIsAtomicBeforeEndpointBootstrap() throws {
        let source: [String: Any] = ["dns": ["servers": ["tcp://127.0.0.1"], "clientIp": "env:FLUTTER_VLESS_LOGICAL_EARLY"],
            "inbounds": [["protocol": "tunnel", "settings": ["rewriteAddress": "env:FLUTTER_VLESS_LOGICAL_LATE"]]],
            "outbounds": [["protocol": "http", "settings": ["address": "endpoint.invalid", "port": 443]]]]
        let environment = ["FLUTTER_VLESS_LOGICAL_EARLY": "198.51.100.1", "FLUTTER_VLESS_LOGICAL_LATE": "env:SECOND"]
        var transaction = source
        XCTAssertThrowsError(try TunnelDNSPolicy.bindEndpointEnvironment(to: &transaction, environment: environment))
        XCTAssertEqual(transaction as NSDictionary, source as NSDictionary)
        let previous = environment.keys.map { ($0, getenv($0).map { String(cString: $0) }) }
        for (key, value) in environment { setenv(key, value, 1) }
        defer { for (key, value) in previous { if let value { setenv(key, value, 1) } else { unsetenv(key) } } }
        XCTAssertNil(TunnelDNSPolicy.apply(to: &transaction, managedInboundTag: "managed", resolveIPv4: { _ in XCTFail("Failed logical binding must precede bootstrap"); return nil }))
        XCTAssertEqual(transaction as NSDictionary, source as NSDictionary)
        let duplicate: [String: Any] = ["inbounds": [["protocol": "dokodemo-door", "settings": ["rewriteAddress": "env:TARGET", "REWRITEADDRESS": "127.0.0.1"]]]]
        XCTAssertThrowsError(try TunnelXrayConfigPreparer.bindingEndpointEnvironment(configData: JSONSerialization.data(withJSONObject: duplicate), environment: ["TARGET": "127.0.0.1"]))
        let opaque: [String: Any] = ["inbounds": [["protocol": "socks", "settings": ["address": "env:TARGET", "rewriteAddress": "env:TARGET"]]],
            "outbounds": [["protocol": "blackhole", "settings": ["address": "env:TARGET"]]], "custom": ["rewriteAddress": "env:TARGET"]]
        let opaqueData = try JSONSerialization.data(withJSONObject: opaque, options: [.sortedKeys])
        XCTAssertEqual(try TunnelXrayConfigPreparer.bindingEndpointEnvironment(configData: opaqueData, environment: ["TARGET": "wrong.invalid"]), opaqueData)
    }

    func testRootDNSEnvironmentBindsOnlyTypedValuesAndRejectsPartialPublication() throws {
        let source: [String: Any] = ["DNS": ["SeRvErS": ["env:SERVER", ["AdDrEsS": "env:OBJECT", "ClIeNtIp": "env:ECS", "tag": "env:OPAQUE", "domains": ["full:env:OPAQUE.invalid"]]] as [Any],
            "cLiEnTiP": "env:ECS", "HoStS": ["env:KEY": "env:ALIAS", "full:array.invalid": ["127.0.0.7", "env:ALIAS", "env:IP", "second.invalid"]]],
            "custom": ["address": "env:OPAQUE"]]
        let input = try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys])
        let environment = ["SERVER": "tcp://127.0.0.1", "OBJECT": "https://127.0.0.1/env:OPAQUE", "ECS": "198.51.100.1", "ALIAS": "alias.invalid", "IP": "127.0.0.8", "OPAQUE": "wrong"]
        let frozen = try TunnelXrayConfigPreparer.bindingEndpointEnvironment(configData: input, environment: environment)
        let output = try XCTUnwrap(JSONSerialization.jsonObject(with: frozen) as? [String: Any])
        let dns = try XCTUnwrap(output["dns"] as? [String: Any])
        let servers = try XCTUnwrap(dns["SeRvErS"] as? [Any])
        XCTAssertEqual(servers[0] as? String, "tcp://127.0.0.1")
        XCTAssertEqual(servers[1] as? NSDictionary, ["AdDrEsS": "https://127.0.0.1/env:OPAQUE", "ClIeNtIp": "198.51.100.1", "tag": "env:OPAQUE", "domains": ["full:env:OPAQUE.invalid"]] as NSDictionary)
        XCTAssertEqual(dns["cLiEnTiP"] as? String, "198.51.100.1")
        XCTAssertEqual(dns["HoStS"] as? NSDictionary, ["env:KEY": "alias.invalid", "full:array.invalid": ["127.0.0.7", "alias.invalid", "127.0.0.8", "second.invalid"]] as NSDictionary)
        XCTAssertEqual(output["custom"] as? NSDictionary, source["custom"] as? NSDictionary)
        XCTAssertNil(output["outbounds"], "DNS binding must not insert an absent outbound list")
        var transaction = source
        let before = transaction as NSDictionary
        var nested = environment; nested["IP"] = "env:SECOND"
        XCTAssertThrowsError(try TunnelDNSPolicy.bindEndpointEnvironment(to: &transaction, environment: nested))
        XCTAssertEqual(transaction as NSDictionary, before)
        let duplicate: [String: Any] = ["dns": ["servers": ["tcp://127.0.0.1"], "clientIp": "env:ECS", "CLIENTIP": "env:ECS"]]
        XCTAssertThrowsError(try TunnelXrayConfigPreparer.bindingEndpointEnvironment(configData: JSONSerialization.data(withJSONObject: duplicate), environment: environment))
        XCTAssertEqual(try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys]), input)
    }

    func testRootDNSAdmissionUsesCoreParsedAddressWithoutLosingRawExpandedValue() throws {
        for (server, hosts) in [
            ("[ 127.0.0.1 ]", [String: Any]()),
            ("https://resolver.invalid/dns-query?opaque=env:UNCHANGED", ["full:resolver.invalid": ["[ 127.0.0.1 ]", "127.0.0.9"]] as [String: Any])
        ] {
            let source: [String: Any] = ["dns": ["servers": ["env:SERVER"], "hosts": hosts], "outbounds": [["tag": "direct", "protocol": "freedom"]]]
            let frozen = try TunnelXrayConfigPreparer.bindingEndpointEnvironment(configData: JSONSerialization.data(withJSONObject: source), environment: ["SERVER": server])
            let prepared = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: frozen, credentials: Self.credentials,
                resolveIPv4: { _ in XCTFail("Caller DNS is not endpoint bootstrap"); return nil }))
            let output = try XCTUnwrap(JSONSerialization.jsonObject(with: prepared.data) as? [String: Any])
            XCTAssertEqual((output["dns"] as? [String: Any])?["servers"] as? [String], [server])
            XCTAssertEqual((output["dns"] as? [String: Any])?["hosts"] as? NSDictionary, hosts as NSDictionary)
        }
        for server in ["fakedns", "[ fakedns ]", "tcp+local://1.1.1.1", "https+local://1.1.1.1/dns-query", "[ ::1 ]"] {
            let parsed = LocalProxyAccessPolicy.coreAddressText(server)
            let source: [String: Any] = ["dns": ["servers": [server], "hosts": [parsed: "127.0.0.1"]], "outbounds": [["tag": "direct", "protocol": "freedom"]]]
            XCTAssertNil(TunnelXrayConfigPreparer.prepare(jsonData: try JSONSerialization.data(withJSONObject: source), credentials: Self.credentials), "Static hosts cannot qualify a special mode or IPv6 DNS underlay")
        }
    }

    func testSharedRootDNSEnvironmentMatchesLiteralControlAndFreezesAcrossProcesses() throws {
        func replace(_ object: Any, path: ArraySlice<String>, value: String) -> Any {
            guard let head = path.first else { return value }
            if var map = object as? [String: Any], let child = map[head] {
                map[head] = replace(child, path: path.dropFirst(), value: value); return map
            }
            var list = object as! [Any]; let index = Int(head)!
            list[index] = replace(list[index], path: path.dropFirst(), value: value); return list
        }
        var root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<10 {
            if FileManager.default.fileExists(atPath: root.appendingPathComponent("tool/fixtures/compatibility/dns-addresses.json").path) { break }
            root.deleteLastPathComponent()
        }
        let cases = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: root.appendingPathComponent("tool/fixtures/compatibility/dns-addresses.json"))) as? [[String: Any]])
        XCTAssertEqual(cases.count, 3)
        for item in cases {
            let original = try XCTUnwrap(item["config"] as? [String: Any])
            let environment = try XCTUnwrap(item["environment"] as? [String: String])
            let previous = environment.keys.map { ($0, getenv($0).map { String(cString: $0) }) }
            for (key, value) in environment { setenv(key, value, 1) }
            defer { for (key, value) in previous { if let value { setenv(key, value, 1) } else { unsetenv(key) } } }
            let input = try JSONSerialization.data(withJSONObject: original, options: [.sortedKeys])
            var literal: Any = original
            for binding in try XCTUnwrap(item["bindings"] as? [[String: Any]]) {
                let path = try XCTUnwrap(binding["path"] as? [String])
                literal = replace(literal, path: ArraySlice(path), value: try XCTUnwrap(binding["value"] as? String))
            }
            let expected = try XCTUnwrap(literal as? [String: Any])
            let control = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: JSONSerialization.data(withJSONObject: expected), credentials: Self.credentials,
                resolveIPv4: { _ in XCTFail("Explicit numeric caller DNS requires no endpoint bootstrap"); return nil }))
            let frozen = try TunnelXrayConfigPreparer.bindingEndpointEnvironment(configData: input, environment: environment)
            XCTAssertEqual(try JSONSerialization.jsonObject(with: frozen) as? NSDictionary, expected as NSDictionary, "Typed DNS references must bind before profile persistence")
            let prepared = TunnelXrayConfigPreparer.prepare(jsonData: input, credentials: Self.credentials,
                resolveIPv4: { _ in XCTFail("Caller DNS must remain independent from transport bootstrap"); return nil })
            XCTAssertNotNil(prepared, "Core-valid DNS environment rejected: \(item["name"] ?? "")")
            if let prepared {
                XCTAssertEqual(try JSONSerialization.jsonObject(with: prepared.data) as? NSDictionary, try JSONSerialization.jsonObject(with: control.data) as? NSDictionary)
            }
            let changed = environment.mapValues { _ in "different.invalid" }
            for (key, value) in changed { setenv(key, value, 1) }
            XCTAssertEqual(try TunnelXrayConfigPreparer.bindingEndpointEnvironment(configData: frozen, environment: changed), frozen)
            if let provider = TunnelXrayConfigPreparer.prepare(jsonData: frozen, credentials: Self.credentials) {
                XCTAssertEqual(try JSONSerialization.jsonObject(with: provider.data) as? NSDictionary, try JSONSerialization.jsonObject(with: control.data) as? NSDictionary)
            } else { XCTFail("Frozen DNS must not depend on the provider's environment") }
            XCTAssertEqual(try JSONSerialization.data(withJSONObject: original, options: [.sortedKeys]), input)
        }
    }

    func testEndpointEnvironmentBindsChainedDynamicParentDownload() throws {
        for proto in ["direct", "dns"] {
            let child: [String: Any] = ["address": "env:DOWNLOAD", "port": 8443, "network": "xhttp", "xhttpSettings": ["path": "/download"]]
            let source: [String: Any] = ["dns": ["servers": ["tcp://9.9.9.9"]], "outbounds": [
                ["tag": "dynamic", "protocol": proto, "streamSettings": ["network": "xhttp", "sockopt": ["penetrate": true, "dialerProxy": "carrier"], "xhttpSettings": ["downloadSettings": child]]],
                ["tag": "carrier", "protocol": "http", "settings": ["address": "192.0.2.9", "port": 443]]]]
            let input = try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys])
            let frozen = try TunnelXrayConfigPreparer.bindingEndpointEnvironment(configData: input, environment: ["DOWNLOAD": "download.invalid"])
            var expectedChild = child; expectedChild["address"] = "download.invalid"
            let output = try XCTUnwrap(JSONSerialization.jsonObject(with: frozen) as? [String: Any])
            let stream = try XCTUnwrap((output["outbounds"] as? [[String: Any]])?.first?["streamSettings"] as? [String: Any])
            XCTAssertEqual((stream["xhttpSettings"] as? [String: Any])?["downloadSettings"] as? NSDictionary, expectedChild as NSDictionary)
            XCTAssertEqual(try TunnelXrayConfigPreparer.bindingEndpointEnvironment(configData: frozen, environment: ["DOWNLOAD": "different.invalid"]), frozen)
            let prepared = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: frozen, credentials: Self.credentials, resolveIPv4: { _ in XCTFail("Caller chain targets remain logical"); return nil }))
            var literal = source
            var literalOutbounds = source["outbounds"] as! [[String: Any]]
            var literalStream = literalOutbounds[0]["streamSettings"] as! [String: Any]
            literalStream["xhttpSettings"] = ["downloadSettings": expectedChild]
            literalOutbounds[0]["streamSettings"] = literalStream; literal["outbounds"] = literalOutbounds
            let control = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: JSONSerialization.data(withJSONObject: literal), credentials: Self.credentials))
            XCTAssertEqual(try JSONSerialization.jsonObject(with: prepared.data) as? NSDictionary, try JSONSerialization.jsonObject(with: control.data) as? NSDictionary)
            XCTAssertEqual(try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys]), input)
        }
    }

    func testEndpointEnvironmentFreezesRawAddressAcrossProviderEnvironments() throws {
        let original: [String: Any] = ["dns": ["servers": ["tcp://9.9.9.9"]], "outbounds": [["tag": "proxy", "protocol": "http", "settings": ["address": "env:ENDPOINT", "port": 443]]]]
        let source = try JSONSerialization.data(withJSONObject: original, options: [.sortedKeys])
        for (raw, target) in [("[127.0.0.1]", "127.0.0.1"), ("[ endpoint.invalid ]", "endpoint.invalid"), ("\u{0085}endpoint.invalid\u{3000}", "endpoint.invalid")] {
            let frozen = try TunnelXrayConfigPreparer.bindingEndpointEnvironment(configData: source, environment: ["ENDPOINT": raw])
            XCTAssertEqual(try TunnelXrayConfigPreparer.bindingEndpointEnvironment(configData: frozen, environment: ["ENDPOINT": "different.invalid"]), frozen)
            var calls: [String] = []
            let prepared = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: frozen, credentials: Self.credentials, resolveIPv4: { calls.append($0); return $0 == "endpoint.invalid" ? "203.0.113.9" : nil }))
            let output = try XCTUnwrap(JSONSerialization.jsonObject(with: prepared.data) as? [String: Any])
            let settings = try XCTUnwrap((output["outbounds"] as? [[String: Any]])?.first?["settings"] as? [String: Any])
            XCTAssertEqual(settings["address"] as? String, raw)
            XCTAssertEqual(calls, target == "127.0.0.1" ? [] : [target])
            XCTAssertEqual(output["dns"] as? NSDictionary, original["dns"] as? NSDictionary)
        }
        XCTAssertEqual(try LocalProxyAccessPolicy.bindingAddressEnvironment("env: endpoint.name ", environment: ["ENDPOINT_NAME": "endpoint.invalid"]), "endpoint.invalid")
        XCTAssertEqual(try LocalProxyAccessPolicy.bindingAddressEnvironment("env: endpoint.name ", environment: [" endpoint.name ": "", "ENDPOINT_NAME": "wrong.invalid"]), "")
        XCTAssertEqual(try LocalProxyAccessPolicy.bindingAddressEnvironment("env:ABSENT", environment: [:]), "")
        XCTAssertEqual(try LocalProxyAccessPolicy.bindingAddressEnvironment(" env:ENDPOINT ", environment: ["ENDPOINT": "wrong.invalid"]), " env:ENDPOINT ")
        XCTAssertEqual(try LocalProxyAccessPolicy.bindingAddressEnvironment("env:ß", environment: ["ß": "endpoint.invalid", "SS": "wrong.invalid"]), "endpoint.invalid")
        XCTAssertThrowsError(try LocalProxyAccessPolicy.bindingAddressEnvironment("env:ß", environment: ["SS": "wrong.invalid"]))
        XCTAssertThrowsError(try TunnelXrayConfigPreparer.bindingEndpointEnvironment(configData: source, environment: ["ENDPOINT": "env:SECOND", "SECOND": "wrong.invalid"]))
        let empty = try TunnelXrayConfigPreparer.bindingEndpointEnvironment(configData: source, environment: [:])
        XCTAssertNil(TunnelXrayConfigPreparer.prepare(jsonData: empty, credentials: Self.credentials, resolveIPv4: { _ in XCTFail("Empty effective endpoint must reject before lookup"); return nil }))
        XCTAssertEqual(try JSONSerialization.data(withJSONObject: original, options: [.sortedKeys]), source)
    }

    func testEndpointEnvironmentVisitsEffectiveFieldsAndKeepsCallerChainLogical() throws {
        let child: [String: Any] = ["address": "env:DOWNLOAD", "port": 8443, "network": "xhttp", "sockopt": ["dialerProxy": "inactive-child"], "xhttpSettings": ["path": "env:PATH"]]
        let original: [String: Any] = ["dns": ["servers": ["tcp://9.9.9.9"]], "custom": ["address": "env:UPLOAD"], "outbounds": [
            ["tag": "proxy", "protocol": "http", "settings": ["address": "env:UPLOAD", "port": 443, "servers": [["address": "env:IGNORED", "port": 9443]]],
             "streamSettings": ["address": "env:IGNORED", "network": "xhttp", "sockopt": ["penetrate": true, "dialerProxy": "carrier"], "tlsSettings": ["serverName": "env:SNI"],
                "xhttpSettings": ["host": "env:HOST", "downloadSettings": ["address": "env:IGNORED", "port": 9443], "extra": ["downloadSettings": child]],
                "splithttpSettings": ["downloadSettings": ["address": "env:IGNORED", "port": 9443]]]],
            ["tag": "carrier", "protocol": "socks", "settings": ["address": "env:CARRIER", "port": 1080]]]]
        let source = try JSONSerialization.data(withJSONObject: original, options: [.sortedKeys])
        let frozen = try TunnelXrayConfigPreparer.bindingEndpointEnvironment(configData: source, environment: ["UPLOAD": "logical-upload.invalid", "DOWNLOAD": "logical-download.invalid", "CARRIER": "carrier.invalid"])
        let bound = try XCTUnwrap(JSONSerialization.jsonObject(with: frozen) as? [String: Any])
        let first = try XCTUnwrap((bound["outbounds"] as? [[String: Any]])?.first)
        let stream = try XCTUnwrap(first["streamSettings"] as? [String: Any])
        XCTAssertEqual((first["settings"] as? [String: Any])?["servers"] as? NSArray, [["address": "env:IGNORED", "port": 9443]] as NSArray)
        XCTAssertEqual(stream["address"] as? String, "env:IGNORED")
        XCTAssertEqual((stream["tlsSettings"] as? [String: Any])?["serverName"] as? String, "env:SNI")
        let xhttp = try XCTUnwrap(stream["xhttpSettings"] as? [String: Any])
        XCTAssertEqual(xhttp["host"] as? String, "env:HOST")
        XCTAssertEqual(xhttp["downloadSettings"] as? NSDictionary, ["address": "env:IGNORED", "port": 9443] as NSDictionary)
        XCTAssertEqual(stream["splithttpSettings"] as? NSDictionary, ["downloadSettings": ["address": "env:IGNORED", "port": 9443]] as NSDictionary)
        var expectedChild = child; expectedChild["address"] = "logical-download.invalid"
        XCTAssertEqual((xhttp["extra"] as? [String: Any])?["downloadSettings"] as? NSDictionary, expectedChild as NSDictionary)
        var calls: [String] = []
        XCTAssertNotNil(TunnelXrayConfigPreparer.prepare(jsonData: frozen, credentials: Self.credentials, resolveIPv4: { calls.append($0); return $0 == "carrier.invalid" ? "203.0.113.9" : nil }))
        XCTAssertEqual(calls, ["carrier.invalid"])
        XCTAssertEqual(bound["custom"] as? NSDictionary, original["custom"] as? NSDictionary)
        var transactional = original
        let before = transactional as NSDictionary
        XCTAssertThrowsError(try TunnelDNSPolicy.bindEndpointEnvironment(to: &transactional, environment: ["UPLOAD": "logical-upload.invalid", "DOWNLOAD": "env:SECOND", "CARRIER": "carrier.invalid"]))
        XCTAssertEqual(transactional as NSDictionary, before)
        XCTAssertEqual(try JSONSerialization.data(withJSONObject: original, options: [.sortedKeys]), source)
    }

    func testPenetratingDownloadSharesClosedParentPinsAndKeepsChildSocketPolicy() throws {
        for (upload, download) in [("upload.example", "download.example"), ("same.example", "same.example"), ("192.0.2.20", "download.example"), ("upload.example", "192.0.2.21")] {
            let child: [String: Any] = ["address": download, "port": 8443, "network": "xhttp", "security": "tls", "tlsSettings": ["serverName": "download-sni.example"], "xhttpSettings": ["host": "download-host.example", "path": "/download"], "sockopt": ["dialerProxy": "dormant-missing-handler", "tcpKeepAliveIdle": 7]]
            let original: [String: Any] = ["dns": ["servers": ["9.9.9.9"]], "outbounds": [["tag": "proxy", "protocol": "http", "settings": ["address": upload, "port": 443], "sendThrough": "192.0.2.9", "streamSettings": ["network": "xhttp", "sockopt": ["penetrate": true, "tcpKeepAliveIdle": 30], "xhttpSettings": ["downloadSettings": child]]]]]
            let before = try JSONSerialization.data(withJSONObject: original, options: [.sortedKeys])
            var config = original
            var names: [String] = []
            XCTAssertNotNil(TunnelDNSPolicy.apply(to: &config, managedInboundTag: "tun", resolveIPv4: { names.append($0); return "203.0.113.9" }))
            let outputs = try XCTUnwrap(config["outbounds"] as? [[String: Any]])
            let stream = try XCTUnwrap(outputs[0]["streamSettings"] as? [String: Any])
            XCTAssertEqual((stream["xhttpSettings"] as? [String: Any])?["downloadSettings"] as? NSDictionary, child as NSDictionary)
            let parentSocket = try XCTUnwrap(stream["sockopt"] as? [String: Any])
            XCTAssertEqual(parentSocket["domainStrategy"] as? String, "AsIs")
            let loops = outputs.filter { ($0["protocol"] as? String) == "loopback" }
            XCTAssertEqual(loops.count, 1)
            let loop = try XCTUnwrap(loops.first)
            XCTAssertEqual(parentSocket["dialerProxy"] as? String, loop["tag"] as? String)
            let scope = try XCTUnwrap((loop["settings"] as? [String: Any])?["inboundTag"] as? String)
            let rules = try XCTUnwrap((config["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
            let scoped = rules.filter { ($0["inboundTag"] as? [String]) == [scope] }
            XCTAssertEqual(scoped.count, 3)
            for (host, port) in [(upload, "443"), (download, "8443")] {
                let rule = try XCTUnwrap(scoped.first { ($0["port"] as? String) == port })
                if host.hasPrefix("192.") { XCTAssertEqual(rule["ip"] as? [String], [host]) }
                else { XCTAssertEqual(rule["domain"] as? [String], ["full:" + host]) }
                let leaf = try XCTUnwrap(outputs.first { ($0["tag"] as? String) == (rule["outboundTag"] as? String) })
                XCTAssertEqual((leaf["settings"] as? [String: Any])?["redirect"] as? String, (host.hasPrefix("192.") ? host : "203.0.113.9") + ":0")
                XCTAssertEqual(((leaf["streamSettings"] as? [String: Any])?["sockopt"] as? [String: Any])?["tcpKeepAliveIdle"] as? Int, 30)
                XCTAssertEqual(leaf["sendThrough"] as? String, "192.0.2.9")
            }
            let denied = try XCTUnwrap(outputs.first { ($0["tag"] as? String) == (scoped.last?["outboundTag"] as? String) })
            XCTAssertEqual(denied["protocol"] as? String, "blackhole")
            XCTAssertEqual(Set(names), Set([upload, download].filter { !$0.hasPrefix("192.") }))
            XCTAssertEqual(names.count, Set(names).count)
            XCTAssertEqual(config["dns"] as? NSDictionary, original["dns"] as? NSDictionary)
            XCTAssertEqual(try JSONSerialization.data(withJSONObject: original, options: [.sortedKeys]), before)
        }
    }

    func testPenetratingParentChainCarriesBothLogicalTargetsAndIgnoresChildChain() throws {
        let child: [String: Any] = ["address": "logical-download.example", "port": 8443, "network": "splithttp", "sockopt": ["dialerProxy": "dormant-missing-handler", "tcpKeepAliveIdle": 7]]
        let parent: [String: Any] = ["tag": "proxy", "protocol": "http", "settings": ["address": "logical-upload.example", "port": 443], "streamSettings": ["network": "xhttp", "sockopt": ["penetrate": true, "dialerProxy": "carrier"], "xhttpSettings": ["downloadSettings": child]]]
        let carrier: [String: Any] = ["tag": "carrier", "protocol": "socks", "settings": ["address": "carrier.example", "port": 1080]]
        var config: [String: Any] = ["dns": ["servers": ["9.9.9.9"]], "outbounds": [parent, carrier]]
        var names: [String] = []
        XCTAssertNotNil(TunnelDNSPolicy.apply(to: &config, managedInboundTag: "tun", resolveIPv4: { names.append($0); return $0 == "carrier.example" ? "203.0.113.9" : nil }))
        XCTAssertEqual(names, ["carrier.example"])
        let outputs = try XCTUnwrap(config["outbounds"] as? [[String: Any]])
        let stream = try XCTUnwrap(outputs[0]["streamSettings"] as? [String: Any])
        XCTAssertEqual((stream["sockopt"] as? [String: Any])?["dialerProxy"] as? String, "carrier")
        XCTAssertEqual((stream["xhttpSettings"] as? [String: Any])?["downloadSettings"] as? NSDictionary, child as NSDictionary)
        for (penetrate, chain) in [(false, "carrier"), (true, "missing-parent")] {
            var invalidParent = parent; var invalidStream = parent["streamSettings"] as! [String: Any]
            invalidStream["sockopt"] = ["penetrate": penetrate, "dialerProxy": chain]
            invalidParent["streamSettings"] = invalidStream
            var invalid: [String: Any] = ["dns": ["servers": ["9.9.9.9"]], "outbounds": [invalidParent, carrier]]
            let before = invalid as NSDictionary
            XCTAssertNil(TunnelDNSPolicy.apply(to: &invalid, managedInboundTag: "tun", resolveIPv4: { _ in XCTFail("Invalid active chain must reject before bootstrap"); return nil }))
            XCTAssertEqual(invalid as NSDictionary, before)
        }
    }

    func testPenetratingDownloadUsesOnlyEffectiveExtraAndRetainsAdmission() throws {
        let child: [String: Any] = ["address": "download.example", "port": 8443, "network": "xhttp", "sockopt": ["dialerProxy": "ignored-child"]]
        let parent: [String: Any] = ["tag": "proxy", "protocol": "http", "settings": ["address": "upload.example", "port": 443], "streamSettings": ["network": "xhttp", "sockopt": ["penetrate": true], "xhttpSettings": ["downloadSettings": ["address": "inactive.example", "port": 9443], "extra": ["downloadSettings": child]]]]
        var config: [String: Any] = ["dns": ["servers": ["9.9.9.9"]], "outbounds": [parent]]
        var names: [String] = []
        XCTAssertNotNil(TunnelDNSPolicy.apply(to: &config, managedInboundTag: "tun", resolveIPv4: { names.append($0); return "203.0.113.9" }))
        XCTAssertEqual(Set(names), ["upload.example", "download.example"])
        let output = try XCTUnwrap((config["outbounds"] as? [[String: Any]])?.first)
        XCTAssertEqual((output["streamSettings"] as? [String: Any])?["xhttpSettings"] as? NSDictionary, (parent["streamSettings"] as? [String: Any])?["xhttpSettings"] as? NSDictionary)
        for childOverride: [String: Any] in [["address": "download.example", "port": 8443, "network": "tcp"], ["address": "download.example", "port": 8443], ["address": "download.example", "port": 8443, "network": "xhttp", "tlsSettings": ["echConfigList": "https://unsafe.example/ech"]]] {
            var invalidParent = parent; var invalidStream = parent["streamSettings"] as! [String: Any]
            invalidStream["xhttpSettings"] = ["downloadSettings": childOverride]
            invalidParent["streamSettings"] = invalidStream
            var invalid: [String: Any] = ["dns": ["servers": ["9.9.9.9"]], "outbounds": [invalidParent]]
            let before = invalid as NSDictionary
            XCTAssertNil(TunnelDNSPolicy.apply(to: &invalid, managedInboundTag: "tun", resolveIPv4: { _ in XCTFail("Invalid effective download must reject before bootstrap"); return nil }))
            XCTAssertEqual(invalid as NSDictionary, before)
        }
        var unresolved: [String: Any] = ["dns": ["servers": ["9.9.9.9"]], "outbounds": [parent]]
        let before = unresolved as NSDictionary
        XCTAssertNil(TunnelDNSPolicy.apply(to: &unresolved, managedInboundTag: "tun", resolveIPv4: { $0 == "upload.example" ? "203.0.113.9" : nil }))
        XCTAssertEqual(unresolved as NSDictionary, before)
    }

    func testCoreProtocolAliasesAndNullTransportPointersKeepProtection() throws {
        let sourceDirect: [String: Any] = ["tag": "caller-direct", "protocol": "direct", "settings": ["targetStrategy": "AsIs"], "streamSettings": ["sockopt": ["dialerProxy": NSNull()]]]
        let sourceBlock: [String: Any] = ["tag": "caller-block", "protocol": "block"]
        let primary: [String: Any] = ["tag": "proxy", "protocol": "http", "settings": ["address": "proxy.example", "port": 443], "streamSettings": ["method": NSNull(), "network": "xhttp", "xhttpSettings": ["downloadSettings": ["address": "download.example", "port": 8443]], "sockopt": ["dialerProxy": NSNull()]]]
        let raw: [String: Any] = ["inbounds": [["protocol": "socks", "port": 10808]], "outbounds": [sourceDirect, sourceBlock, primary]]
        var names: [String] = []
        let prepared = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: JSONSerialization.data(withJSONObject: raw), credentials: Self.credentials, resolveIPv4: { names.append($0); return "203.0.113.9" }))
        XCTAssertTrue(prepared.proxyUsesXhttp)
        XCTAssertEqual(Set(names), ["proxy.example", "download.example"])
        let output = try XCTUnwrap(JSONSerialization.jsonObject(with: prepared.data) as? [String: Any])
        let outbounds = try XCTUnwrap(output["outbounds"] as? [[String: Any]])
        XCTAssertEqual(outbounds[0]["protocol"] as? String, "direct")
        XCTAssertEqual((outbounds[0]["settings"] as? [String: Any])?["domainStrategy"] as? String, "ForceIPv4")
        XCTAssertNil((outbounds[0]["settings"] as? [String: Any])?["targetStrategy"])
        XCTAssertEqual(outbounds[1] as NSDictionary, sourceBlock as NSDictionary)
        let rules = try XCTUnwrap((output["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
        XCTAssertTrue(rules.contains { ($0["port"] as? String) == "443" && ($0["network"] as? String) == "udp" && ($0["outboundTag"] as? String) == "caller-block" })
    }

    func testNullXHTTPPointersRespectCoreEffectiveDownloadSettings() throws {
        let active: [String: Any] = ["downloadSettings": ["address": "download.example", "port": 8443]]
        let dormant: [String: Any] = ["downloadSettings": ["address": "must-not-resolve.example", "port": 9443]]
        let streams: [[String: Any]] = [
            ["network": "xhttp", "xhttpSettings": NSNull(), "splithttpSettings": active],
            ["network": "xhttp", "xhttpSettings": ["extra": NSNull(), "downloadSettings": dormant["downloadSettings"]!], "splithttpSettings": dormant]
        ]
        for (index, stream) in streams.enumerated() {
            var config: [String: Any] = ["outbounds": [["tag": "proxy", "protocol": "http", "settings": ["address": "proxy.example", "port": 443], "streamSettings": stream]]]
            var names: [String] = []
            XCTAssertNotNil(TunnelDNSPolicy.apply(to: &config, managedInboundTag: "tun", resolveIPv4: { name in
                names.append(name)
                XCTAssertNotEqual(name, "must-not-resolve.example")
                return name == "must-not-resolve.example" ? nil : "203.0.113.9"
            }))
            XCTAssertEqual(Set(names), index == 0 ? ["proxy.example", "download.example"] : ["proxy.example"])
            let output = try XCTUnwrap(((config["outbounds"] as? [[String: Any]])?.first)?["streamSettings"] as? [String: Any])
            if index == 1 { XCTAssertEqual(output["splithttpSettings"] as? NSDictionary, dormant as NSDictionary) }
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

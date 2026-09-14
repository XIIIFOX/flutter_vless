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
        XCTAssertEqual(TunnelXrayConfigPreparer.parseConfig(jsonData: prepared.data)?.inboundPort, 10808)
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

    func testHTTPAndSocksDNSUseTCPProxyAndKeepApplicationRules() throws {
        for proto in ["http", "socks"] {
            let applicationRule: [String: Any] = ["inboundTag": ["socks-direct"], "outboundTag": "direct"]
            let input: [String: Any] = [
                "inbounds": [["tag": "socks-in", "listen": "127.0.0.1", "protocol": "socks", "port": 10808]],
                "outbounds": [
                    ["tag": "proxy", "protocol": proto, "settings": ["servers": [["address": "proxy.example", "port": 443]]]],
                    ["tag": "direct", "protocol": "freedom"]
                ],
                "routing": ["rules": [applicationRule]]
            ]
            let data = try JSONSerialization.data(withJSONObject: input)
            let prepared = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: data, credentials: Self.credentials, resolveIPv4: { _ in "203.0.113.7" }))
            let output = try XCTUnwrap(JSONSerialization.jsonObject(with: prepared.data) as? [String: Any])
            let dns = try XCTUnwrap(output["dns"] as? [String: Any])
            XCTAssertEqual(dns["servers"] as? [String], ["tcp://1.1.1.1"])
            XCTAssertEqual((dns["hosts"] as? [String: String])?["proxy.example"], "203.0.113.7")
            let outbounds = try XCTUnwrap(output["outbounds"] as? [[String: Any]])
            let relay = try XCTUnwrap(outbounds.first(where: { ($0["protocol"] as? String) == "dns" }))
            XCTAssertNil(relay["proxySettings"])
            let stream = try XCTUnwrap(relay["streamSettings"] as? [String: Any])
            XCTAssertEqual((stream["sockopt"] as? [String: String])?["dialerProxy"], "proxy")
            let relaySettings = try XCTUnwrap(relay["settings"] as? [String: Any])
            XCTAssertEqual(relaySettings["rewriteNetwork"] as? String, "tcp")
            let relayRules = try XCTUnwrap(relaySettings["rules"] as? [[String: Any]])
            XCTAssertEqual(relayRules.count, 2)
            XCTAssertEqual(relayRules[0] as NSDictionary, ["action": "return", "qType": "28", "rCode": 0] as NSDictionary)
            XCTAssertEqual(relayRules[1] as NSDictionary, ["action": "direct"] as NSDictionary)
            let rules = try XCTUnwrap((output["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
            XCTAssertEqual(rules[1]["outboundTag"] as? String, "proxy")
            XCTAssertEqual(rules[2]["ip"] as? [String], ["198.18.0.2/32"])
            XCTAssertEqual(rules[2]["network"] as? String, "tcp,udp")
            XCTAssertEqual(rules.last! as NSDictionary, applicationRule as NSDictionary)
            XCTAssertEqual(prepared.bootstrapAddresses, ["203.0.113.7"])
            if let directory = ProcessInfo.processInfo.environment["TUNNEL_DNS_FIXTURES"] {
                try prepared.data.write(to: URL(fileURLWithPath: directory).appendingPathComponent(proto + ".json"))
            }
        }
    }

    func testBootstrapFailureAndTagCollisionsRejectPreparation() {
        var config: [String: Any] = ["outbounds": [["protocol": "http", "settings": ["address": "unresolved.example", "port": 443]]]]
        XCTAssertNil(TunnelDNSPolicy.apply(to: &config, resolveIPv4: { _ in nil }))
        config["inbounds"] = [["tag": "flutter-vless-dns-upstream"]]
        XCTAssertNil(TunnelDNSPolicy.apply(to: &config, resolveIPv4: { _ in "203.0.113.7" }))
    }

    func testNestedXHTTPDownloadBootstrapAndCredentialsStayIntact() throws {
        var config: [String: Any] = ["outbounds": [[
            "protocol": "vless", "settings": ["vnext": [["address": "primary.example", "port": 443, "users": [["id": "test-uuid", "encryption": "preserve-exactly"]]]]],
            "streamSettings": ["network": "xhttp", "xhttpSettings": ["extra": ["downloadSettings": [
                "address": "download.example", "port": 443, "sockopt": ["tcpKeepAliveIdle": 30]
            ]]]]
        ]]]
        var resolved: [String] = []
        XCTAssertNotNil(TunnelDNSPolicy.apply(to: &config, resolveIPv4: { host in
            resolved.append(host)
            return "203.0.113.7"
        }))
        XCTAssertEqual(Set(resolved), ["primary.example", "download.example"])
        let output = String(decoding: try JSONSerialization.data(withJSONObject: config), as: UTF8.self)
        XCTAssertTrue(output.contains("preserve-exactly"))
        XCTAssertTrue(output.contains("test-uuid"))
        XCTAssertTrue(output.contains("tcpKeepAliveIdle"))
        XCTAssertEqual(output.components(separatedBy: "ForceIP").count - 1, 2)
    }

    func testDNSAddressCannotBeExcludedButServerAndLANBypassesRemain() {
        for subnet in ["198.18.0.2/32", "198.18.0.0/16", "0.0.0.0/0"] {
            XCTAssertFalse(TunnelDNSPolicy.allowsRouteExclusions([subnet]))
        }
        XCTAssertTrue(TunnelDNSPolicy.allowsRouteExclusions(["203.0.113.7/32", "192.168.0.0/16", "1.1.1.1/32"]))
    }

    func testWireGuardPeersBootstrapWithoutChangingKeysOrEndpoints() throws {
        let settings: [String: Any] = ["secretKey": "private-key-marker", "peers": [
            ["endpoint": "wg.example:51820", "publicKey": "public-key-marker"],
            ["endpoint": "[2001:db8::1]:51820", "publicKey": "second-key"]
        ]]
        var config: [String: Any] = ["outbounds": [["protocol": "wireguard", "settings": settings]]]
        XCTAssertEqual(TunnelDNSPolicy.apply(to: &config, resolveIPv4: { _ in "203.0.113.7" }),
                       ["2001:db8::1", "203.0.113.7"])
        let outbounds = try XCTUnwrap(config["outbounds"] as? [[String: Any]])
        XCTAssertEqual(outbounds[0]["settings"] as? NSDictionary, settings as NSDictionary)
    }

    func testAbsoluteDNSNameMatchesXrayHostLookup() throws {
        var config: [String: Any] = ["outbounds": [["protocol": "http", "settings": ["address": "Proxy.Example.", "port": 443]]]]
        XCTAssertNotNil(TunnelDNSPolicy.apply(to: &config, resolveIPv4: { _ in "203.0.113.7" }))
        let dns = try XCTUnwrap(config["dns"] as? [String: Any])
        XCTAssertEqual(dns["hosts"] as? [String: String], ["proxy.example": "203.0.113.7"])
        let outbounds = try XCTUnwrap(config["outbounds"] as? [[String: Any]])
        XCTAssertEqual((outbounds[0]["settings"] as? [String: Any])?["address"] as? String, "Proxy.Example.")
    }

    func testModernEndpointAndExtraPrecedenceMatchXray() throws {
        var config: [String: Any] = ["outbounds": [[
            "protocol": "HTTP", "settings": ["address": "active.example", "port": 443,
                                                "servers": [["address": "ignored.example", "port": 443]]],
            "streamSettings": ["xhttpSettings": [
                "downloadSettings": ["address": "ignored-download.example"],
                "extra": ["downloadSettings": ["address": "active-download.example"]]
            ]]
        ]]]
        var resolved: [String] = []
        XCTAssertNotNil(TunnelDNSPolicy.apply(to: &config, resolveIPv4: { host in
            resolved.append(host)
            return host.hasPrefix("active") ? "203.0.113.7" : nil
        }))
        XCTAssertEqual(Set(resolved), ["active.example", "active-download.example"])
    }
}

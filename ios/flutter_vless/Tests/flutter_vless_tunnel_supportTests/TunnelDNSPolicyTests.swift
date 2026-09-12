import XCTest
@testable import flutter_vless_tunnel_support

final class TunnelDNSPolicyTests: XCTestCase {
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
            let prepared = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: data, resolveIPv4: { _ in "203.0.113.7" }))
            let output = try XCTUnwrap(JSONSerialization.jsonObject(with: prepared.data) as? [String: Any])
            let dns = try XCTUnwrap(output["dns"] as? [String: Any])
            XCTAssertEqual(dns["servers"] as? [String], ["tcp://1.1.1.1"])
            XCTAssertEqual((dns["hosts"] as? [String: String])?["proxy.example"], "203.0.113.7")
            let outbounds = try XCTUnwrap(output["outbounds"] as? [[String: Any]])
            let relay = try XCTUnwrap(outbounds.first(where: { ($0["protocol"] as? String) == "dns" }))
            XCTAssertEqual((relay["proxySettings"] as? [String: String])?["tag"], "proxy")
            let relaySettings = try XCTUnwrap(relay["settings"] as? [String: Any])
            XCTAssertEqual(relaySettings["rewriteNetwork"] as? String, "tcp")
            XCTAssertEqual(relaySettings["rules"] as? [[String: String]], [["action": "direct"]])
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

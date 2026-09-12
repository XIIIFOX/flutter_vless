import XCTest
@testable import flutter_vless_tunnel_support

final class TunnelIPv6PolicyTests: XCTestCase {
    func testIPv6IsCapturedWithOnlyLiteralProxyHostExceptions() throws {
        let settings = TunnelIPv6Policy.networkSettings(proxyAddresses: ["203.0.113.7", "2001:db8::7", "proxy.example"])
        XCTAssertEqual(settings.addresses, ["fd00:198:18::1"])
        XCTAssertEqual(settings.networkPrefixLengths, [64])
        let route = try XCTUnwrap(settings.includedRoutes?.first)
        XCTAssertEqual(route.destinationAddress, "::")
        XCTAssertEqual(route.destinationNetworkPrefixLength, 0)
        XCTAssertEqual(settings.excludedRoutes?.count, 1)
        XCTAssertEqual(settings.excludedRoutes?.first?.destinationAddress, "2001:db8::7")
        XCTAssertEqual(settings.excludedRoutes?.first?.destinationNetworkPrefixLength, 128)
    }

    func testIPv6BlockPrecedesAppDirectRuleAndSniffingPreservesIP() throws {
        let direct: [String: Any] = ["type": "field", "domain": ["full:control.example"], "outboundTag": "direct"]
        var config: [String: Any] = [
            "inbounds": [["protocol": "socks", "sniffing": ["enabled": true, "routeOnly": false]]],
            "outbounds": [["protocol": "freedom", "tag": "direct"]],
            "routing": ["rules": [direct]]
        ]
        XCTAssertTrue(TunnelIPv6Policy.apply(to: &config))
        let rules = try XCTUnwrap((config["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
        XCTAssertEqual(rules.first?["ip"] as? [String], ["::/0"])
        XCTAssertEqual(rules.first?["outboundTag"] as? String, TunnelIPv6Policy.blockTag)
        XCTAssertEqual(rules.last! as NSDictionary, direct as NSDictionary)
        let inbound = try XCTUnwrap((config["inbounds"] as? [[String: Any]])?.first)
        XCTAssertEqual((inbound["sniffing"] as? [String: Any])?["routeOnly"] as? Bool, true)
        XCTAssertFalse(TunnelIPv6Policy.apply(to: &config), "A conflicting block tag must fail preparation")
    }

    func testFakeDNSCannotReplaceIPv6TargetDuringSniffing() {
        for key in ["fakeDns", "fakedns", "FakeDNS"] {
            var config: [String: Any] = [key: [["ipPool": "fc00::/18", "poolSize": 1000]]]
            XCTAssertFalse(TunnelIPv6Policy.apply(to: &config))
        }
    }

    func testGoJSONAliasesCannotOverwritePolicy() throws {
        var config: [String: Any] = [
            "Inbounds": [["Protocol": "socks", "port": 10808, "Sniffing": ["RouteOnly": false]]],
            "Outbounds": [
                ["Tag": "proxy", "Protocol": "http", "Settings": ["Address": "203.0.113.7", "port": 443]],
                ["Tag": "direct", "Protocol": "freedom"]
            ],
            "Routing": ["Rules": [["network": "tcp,udp", "outboundTag": "direct"]]]
        ]
        let data = try JSONSerialization.data(withJSONObject: config)
        let prepared = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: data))
        let output = try XCTUnwrap(JSONSerialization.jsonObject(with: prepared.data) as? [String: Any])
        XCTAssertNil(output["Routing"])
        XCTAssertNil(output["Inbounds"])
        let rules = try XCTUnwrap((output["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
        XCTAssertEqual(rules.first?["outboundTag"] as? String, TunnelIPv6Policy.blockTag)
        let inbounds = try XCTUnwrap(output["inbounds"] as? [[String: Any]])
        XCTAssertEqual((inbounds[0]["sniffing"] as? [String: Any])?["routeOnly"] as? Bool, true)
        if let directory = ProcessInfo.processInfo.environment["TUNNEL_DNS_FIXTURES"] {
            try prepared.data.write(to: URL(fileURLWithPath: directory).appendingPathComponent("aliases.json"))
        }
        config["routing"] = ["rules": []]
        XCTAssertNil(TunnelXrayConfigPreparer.prepare(jsonData: try JSONSerialization.data(withJSONObject: config)))
    }
}

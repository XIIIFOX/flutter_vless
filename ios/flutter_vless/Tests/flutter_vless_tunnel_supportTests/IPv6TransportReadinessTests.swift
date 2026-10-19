import XCTest
@testable import flutter_vless_tunnel_support

/// Test-first contract for a qualified IPv6-over-IPv4 proxy packet path.
/// These tests prepare JSON only; they never start Core, HEV or a tunnel.
final class IPv6TransportReadinessTests: XCTestCase {
    private static let credentials = try! LocalProxyCredentials(username: "ipv6-session", password: "ipv6-session-password")

    private func prepared(strategy: String) throws -> (TunnelPreparedConfig, [String: Any], [String: Any]) {
        let dns: [String: Any] = ["queryStrategy": strategy, "hosts": ["v6-target.invalid": "2001:db8:1234::7"],
            "servers": ["tcp://1.1.1.1"], "disableCache": true]
        let callerRule: [String: Any] = ["type": "field", "ip": ["2001:db8:ffff::/48"], "outboundTag": "caller-block"]
        let source: [String: Any] = ["dns": dns,
            "outbounds": [["protocol": "http", "tag": "proxy", "settings": ["address": "edge.invalid", "port": 443]],
                ["protocol": "blackhole", "tag": "caller-block"]],
            "routing": ["rules": [callerRule]]]
        let before = try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys])
        let result = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: before, credentials: Self.credentials,
            resolveIPv4: { host in XCTAssertEqual(host, "edge.invalid"); return "203.0.113.7" }))
        XCTAssertEqual(try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys]), before)
        let output = try XCTUnwrap(JSONSerialization.jsonObject(with: result.data) as? [String: Any])
        XCTAssertEqual(output["dns"] as? NSDictionary, dns as NSDictionary, "Core owns the caller's address-family query policy")
        return (result, output, callerRule)
    }

    func testBothAddressFamiliesReachCoreWithoutOverridingCallerQueryStrategy() throws {
        for strategy in ["UseIP", "UseIPv4"] {
            let (_, output, _) = try prepared(strategy: strategy)
            let outbounds = try XCTUnwrap(output["outbounds"] as? [[String: Any]])
            let relay = try XCTUnwrap(outbounds.first { ($0["protocol"] as? String) == "dns" })
            let rules = try XCTUnwrap((relay["settings"] as? [String: Any])?["rules"] as? [[String: Any]])
            func firstRule(for type: String) throws -> [String: Any] {
                try XCTUnwrap(rules.first { rule in
                    guard let types = rule["qType"] as? String else { return true }
                    return types.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.contains(type)
                })
            }
            for queryType in ["1", "28"] {
                let rule = try firstRule(for: queryType)
                XCTAssertEqual(rule["action"] as? String, "hijack", "\(strategy): Core must choose A/AAAA results, including IPv4-only NODATA")
            }
            let nonAddress = try firstRule(for: "15")
            XCTAssertEqual(nonAddress["action"] as? String, "return")
            XCTAssertEqual(nonAddress["rCode"] as? Int, 5)
        }
    }

    func testQualifiedIPv6ProxyPathRetainsIPv4BootstrapAndCallerBlocks() throws {
        let (result, output, callerRule) = try prepared(strategy: "UseIP")
        XCTAssertEqual(result.bootstrapAddresses, ["203.0.113.7"])
        let inbounds = try XCTUnwrap(output["inbounds"] as? [[String: Any]])
        let managedTag = try XCTUnwrap(inbounds.first?["tag"] as? String)
        let outbounds = try XCTUnwrap(output["outbounds"] as? [[String: Any]])
        let proxy = try XCTUnwrap(outbounds.first { ($0["tag"] as? String) == "proxy" })
        XCTAssertEqual((proxy["settings"] as? [String: Any])?["address"] as? String, "edge.invalid")
        let routing = try XCTUnwrap((output["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
        XCTAssertTrue(routing.contains { ($0 as NSDictionary) == (callerRule as NSDictionary) })
        XCTAssertFalse(routing.contains {
            ($0["ip"] as? [String]) == ["::/0"] && ($0["inboundTag"] as? [String]) == [managedTag]
        }, "A qualified IPv6 destination must reach the IPv4 proxy rather than the old blanket block")
        let leaves = outbounds.filter { (($0["settings"] as? [String: Any])?["redirect"] as? String) == "203.0.113.7:0" }
        XCTAssertEqual(leaves.count, 1)
        let privateDeny = try XCTUnwrap(outbounds.first { ($0["tag"] as? String)?.hasPrefix("flutter-vless-bootstrap-block") == true })
        XCTAssertEqual(privateDeny["protocol"] as? String, "blackhole")
        XCTAssertTrue(routing.contains { ($0["outboundTag"] as? String) == (privateDeny["tag"] as? String) && $0["inboundTag"] != nil })
    }
}

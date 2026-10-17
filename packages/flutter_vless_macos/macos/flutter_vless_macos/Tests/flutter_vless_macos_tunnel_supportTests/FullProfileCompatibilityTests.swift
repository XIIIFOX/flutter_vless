import XCTest
@testable import flutter_vless_macos_tunnel_support

final class FullProfileCompatibilityTests: XCTestCase {
    func testFullProfileKeepsAdditionalListenersAuthenticationSniffingAndDirectRoute() throws {
        let userSniffing: [String: Any] = ["enabled": true, "routeOnly": false,
            "destOverride": ["quic", "tls", "http"], "domainsExcluded": ["excluded.invalid"], "metadataOnly": false]
        let inputs: [[String: Any]] = [
            ["listen": "127.0.0.1", "port": 10808, "protocol": "socks", "tag": "socks-in",
             "settings": ["auth": "noauth", "udp": true], "sniffing": userSniffing],
            ["listen": "127.0.0.1", "port": 10820, "protocol": "socks", "tag": "socks-direct",
             "settings": ["auth": "noauth", "udp": true], "sniffing": userSniffing],
            ["listen": "127.0.0.1", "port": "10809-10811", "protocol": "http", "tag": "flutter-vless-tun",
             "settings": ["accounts": [["user": "app-user", "pass": "app-password"]]]]
        ]
        let route: [String: Any] = ["inboundTag": ["socks-direct"], "outboundTag": "direct"]
        let remote: [String: Any] = ["address": "endpoint.invalid", "port": 443,
            "id": "22222222-2222-4222-8222-222222222222", "flow": "xtls-rprx-vision", "encryption": "none"]
        let original: [String: Any] = ["inbounds": inputs,
            "outbounds": [["tag": "proxy", "protocol": "vless", "settings": remote], ["tag": "direct", "protocol": "freedom"]],
            "routing": ["domainStrategy": "AsIs", "rules": [route]]]
        let data = try JSONSerialization.data(withJSONObject: original)
        XCTAssertNoThrow(try LocalProxyAccessPolicy.validateVPN(configData: data))
        let secret = try LocalProxyCredentials(username: "native-user", password: "native-password")
        let prepared = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: data, credentials: secret, resolveIPv4: { _ in "203.0.113.1" }))
        let output = try JSONSerialization.jsonObject(with: prepared.data) as! [String: Any]
        let all = output["inbounds"] as! [[String: Any]]
        XCTAssertEqual(Array(all.dropFirst()) as NSArray, inputs as NSArray)
        XCTAssertEqual(all[0]["tag"] as? String, "flutter-vless-tun-1")
        XCTAssertEqual(all[0]["port"] as? Int, 10812)
        XCTAssertEqual(TunnelXrayConfigPreparer.parseConfig(jsonData: prepared.data)?.inboundPort, 10812)
        let settings = all[0]["settings"] as! [String: Any]
        XCTAssertEqual(settings["auth"] as? String, "password")
        XCTAssertEqual(settings["accounts"] as? [[String: String]], [["user": "native-user", "pass": "native-password"]])
        let rules = (output["routing"] as! [String: Any])["rules"] as! [[String: Any]]
        XCTAssertEqual(rules.last! as NSDictionary, route as NSDictionary)
        XCTAssertEqual(rules[0]["inboundTag"] as? [String], ["flutter-vless-tun-1"])
        XCTAssertEqual(((output["outbounds"] as! [[String: Any]])[0]["settings"] as! NSDictionary), remote as NSDictionary)
        XCTAssertEqual(try JSONSerialization.jsonObject(with: data) as! NSDictionary, original as NSDictionary)
    }
    func testDelayProbeAcceptsFullProfileWithoutOpeningImportedPortsOrUsingTheirRoute() throws {
        var profile: [String: Any] = [
            "inbounds": [["protocol": "socks", "port": 10808, "tag": "flutter-vless-delay"],
                         ["protocol": "http", "port": 10820, "tag": "socks-direct"]],
            "outbounds": [["protocol": "freedom", "tag": "proxy"]],
            "routing": ["rules": [["inboundTag": ["socks-direct"], "outboundTag": "direct"]]]]
        let routing = profile["routing"] as! NSDictionary
        let credentials = try LocalProxyCredentials(username: "probe-user", password: "probe-password")
        try LocalProxyAccessPolicy.applyDelayProbe(to: &profile, port: 18080, credentials: credentials)
        let inputs = profile["inbounds"] as! [[String: Any]]
        XCTAssertEqual(inputs.count, 1)
        XCTAssertEqual(inputs[0]["tag"] as? String, "flutter-vless-delay-1")
        XCTAssertEqual(inputs[0]["port"] as? Int, 18080)
        XCTAssertEqual(inputs[0]["listen"] as? String, "127.0.0.1")
        XCTAssertEqual((inputs[0]["settings"] as! [String: Any])["accounts"] as? [[String: String]],
                       [["user": "probe-user", "pass": "probe-password"]])
        XCTAssertEqual(profile["routing"] as! NSDictionary, routing)
    }

}

import XCTest
import flutter_vless_macos_privacy
@testable import flutter_vless_macos_tunnel_support

final class DesktopListenerPolicyTests: XCTestCase {
    private let base: [String: Any] = [
        "inbounds": [["protocol": "socks", "listen": "127.0.0.1", "port": 10808]],
        "outbounds": [["protocol": "http", "tag": "proxy", "settings": ["address": "127.0.0.1", "port": 18090]]]
    ]
    func testAdditionalUserInboundsRemainIntactBesidePrivateAdapter() throws {
        let credentials = try LocalProxyCredentials(username: "test", password: "test-password")
        for kind in ["dokodemo-door", "http", "socks", "vless", "vmess", "trojan"] {
            var json = base
            var listeners = json["inbounds"] as! [[String: Any]]
            listeners.append(["protocol": kind, "listen": "127.0.0.1", "port": 18081])
            json["inbounds"] = listeners
            let data = try JSONSerialization.data(withJSONObject: json)
            XCTAssertNoThrow(try LocalProxyAccessPolicy.validateVPN(configData: data), kind)
            let result = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: data, credentials: credentials), kind)
            let prepared = try JSONSerialization.jsonObject(with: result.data) as! [String: Any]
            let imported = Array((prepared["inbounds"] as! [[String: Any]]).dropFirst())
            XCTAssertEqual(imported as NSArray, listeners as NSArray)
        }
        XCTAssertNotNil(TunnelXrayConfigPreparer.prepare(jsonData: try JSONSerialization.data(withJSONObject: base), credentials: credentials))
    }
    func testManagementAliasesArePreservedAlongsidePrivateLoggingAndNativeCounters() throws {
        let api: [String: Any] = ["tag": "caller-api", "listen": "127.0.0.1:18081",
                                  "services": ["HandlerService", "RoutingService", "StatsService"],
                                  "caller-extension": ["CaseSensitiveKey": "unchanged"]]
        for field in ["api", "Api", "API", "aPI"] {
            var source = base
            source[field] = api
            source["log"] = ["access": "/private/access-canary", "error": "/private/error-canary",
                             "loglevel": "debug", "dnsLog": true]
            let before = try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys])
            var json = source
            XCTAssertTrue(XrayPrivacyConfig.apply(to: &json))
            XCTAssertEqual(json["api"] as? NSDictionary, api as NSDictionary)
            if field != "api" { XCTAssertNil(json[field]) }
            XCTAssertEqual(try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys]), before)
            let log = try XCTUnwrap(json["log"] as? [String: Any])
            XCTAssertEqual(log["access"] as? String, "none")
            XCTAssertEqual(log["error"] as? String, "none")
            XCTAssertEqual(log["loglevel"] as? String, "warning")
            XCTAssertEqual(log["dnsLog"] as? Bool, false)
            XCTAssertNotNil(json["stats"])
            let policy = json["policy"] as! [String: Any]
            XCTAssertEqual((policy["system"] as! [String: Any])["statsOutboundUplink"] as? Bool, true)
            XCTAssertEqual((policy["system"] as! [String: Any])["statsOutboundDownlink"] as? Bool, true)
        }
    }

    func testManagementAliasAmbiguityFails() {
        var ambiguous = base; ambiguous["api"] = [:] as [String: Any]; ambiguous["API"] = [:] as [String: Any]
        XCTAssertFalse(XrayPrivacyConfig.apply(to: &ambiguous))
    }

    func testTunnelPreparationPreservesManagementAPIAndReservesItsListenerPort() throws {
        let api: [String: Any] = ["tag": "caller-api", "listen": "127.0.0.1:10808",
                                  "services": ["HandlerService", "RoutingService", "StatsService"]]
        var source = base
        source["inbounds"] = [["protocol": "socks", "listen": "127.0.0.1", "port": 18095]]
        source["api"] = api
        source["log"] = ["access": "/private/access-canary", "error": "/private/error-canary",
                         "loglevel": "debug", "dnsLog": true]
        let data = try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys])
        let credentials = try LocalProxyCredentials(username: "test", password: "test-password")
        let result = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: data, credentials: credentials))
        let prepared = try XCTUnwrap(JSONSerialization.jsonObject(with: result.data) as? [String: Any])
        XCTAssertEqual(prepared["api"] as? NSDictionary, api as NSDictionary)
        let inputs = try XCTUnwrap(prepared["inbounds"] as? [[String: Any]])
        XCTAssertEqual(inputs.first?["port"] as? Int, 10809)
        XCTAssertEqual(Array(inputs.dropFirst()) as NSArray, source["inbounds"] as? NSArray)
        let log = try XCTUnwrap(prepared["log"] as? [String: Any])
        XCTAssertEqual(log["access"] as? String, "none")
        XCTAssertEqual(log["error"] as? String, "none")
        XCTAssertEqual(log["dnsLog"] as? Bool, false)
        XCTAssertEqual(try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys]), data)
    }
}

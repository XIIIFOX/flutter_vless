import XCTest
@testable import flutter_vless_tunnel_support

final class TunnelXrayConfigPreparerTests: XCTestCase {
    private static let credentials = try! LocalProxyCredentials(username: "test-session", password: "test-session-password")
    func testPreparesXhttpNoneWithoutDroppingVlessEncryption() throws {
        let input = try jsonData([
            "dns": ["queryStrategy": "UseIPv4"],
            "log": [
                "access": "/desktop/access.log",
                "error": "/desktop/error.log",
                "loglevel": "warning",
                "dnsLog": true
            ],
            "inbounds": [
                [
                    "tag": "socks-in",
                    "listen": "127.0.0.1",
                    "port": 10808,
                    "protocol": "socks",
                    "settings": ["auth": "noauth", "udp": true]
                ]
            ],
            "outbounds": [
                [
                    "tag": "proxy",
                    "protocol": "vless",
                    "settings": [
                        "vnext": [
                            [
                                "address": "proxy.example.com",
                                "port": 2043,
                                "users": [
                                    [
                                        "id": "22222222-2222-4222-8222-222222222222",
                                        "encryption": Self.vlessEncryption,
                                        "level": 8,
                                        "security": "auto"
                                    ]
                                ]
                            ]
                        ]
                    ],
                    "streamSettings": [
                        "network": "XHTTP",
                        "security": "none",
                        "tlsSettings": ["allowInsecure": false],
                        "xHTTPSettings": [
                            "host": "storage.example.com",
                            "path": "/my-bucket",
                            "mode": "stream-up"
                        ],
                        "sockopt": ["domainStrategy": "UseIP"]
                    ]
                ],
                ["tag": "direct", "protocol": "freedom"],
                ["tag": "block", "protocol": "blackhole"]
            ],
            "routing": ["domainStrategy": "IPIfNonMatch", "rules": []]
        ])

        let result = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: input, credentials: Self.credentials, resolveIPv4: { _ in "203.0.113.10" }))
        let output = try decodedObject(result.data)
        let log = try XCTUnwrap(output["log"] as? [String: Any])
        let routing = try XCTUnwrap(output["routing"] as? [String: Any])
        let inbounds = try XCTUnwrap(output["inbounds"] as? [[String: Any]])
        let outbounds = try XCTUnwrap(output["outbounds"] as? [[String: Any]])
        let proxy = outbounds[0]
        let settings = try XCTUnwrap(proxy["settings"] as? [String: Any])
        let vnext = try XCTUnwrap(settings["vnext"] as? [[String: Any]])
        let users = try XCTUnwrap(vnext[0]["users"] as? [[String: Any]])
        let streamSettings = try XCTUnwrap(proxy["streamSettings"] as? [String: Any])
        let rules = try XCTUnwrap(routing["rules"] as? [[String: Any]])

        XCTAssertTrue(result.proxyUsesXhttp)
        XCTAssertEqual(log["access"] as? String, "none")
        XCTAssertEqual(log["error"] as? String, "none")
        XCTAssertEqual(log["loglevel"] as? String, "warning")
        XCTAssertEqual(log["dnsLog"] as? Bool, false)
        XCTAssertNotNil(output["dns"])
        XCTAssertEqual(routing["domainStrategy"] as? String, "IPIfNonMatch")
        XCTAssertEqual(users[0]["encryption"] as? String, Self.vlessEncryption)
        XCTAssertEqual(vnext[0]["address"] as? String, "proxy.example.com")
        XCTAssertEqual(streamSettings["network"] as? String, "xhttp")
        XCTAssertNil(streamSettings["xHTTPSettings"])
        XCTAssertNotNil(streamSettings["xhttpSettings"])
        XCTAssertNil((streamSettings["tlsSettings"] as? [String: Any])?["allowInsecure"])
        XCTAssertEqual((streamSettings["sockopt"] as? [String: Any])?["domainStrategy"] as? String, "AsIs")
        XCTAssertEqual(rules.first(where: { String(describing: $0["port"] ?? "") == "443" })?["network"] as? String, "udp")
        XCTAssertEqual(String(describing: rules.first(where: { String(describing: $0["port"] ?? "") == "443" })?["port"] ?? ""), "443")
        XCTAssertEqual(rules.first(where: { String(describing: $0["port"] ?? "") == "443" })?["outboundTag"] as? String, "block")

        let sniffing = try XCTUnwrap(inbounds[0]["sniffing"] as? [String: Any])
        XCTAssertEqual(sniffing["enabled"] as? Bool, true)
        XCTAssertEqual(sniffing["routeOnly"] as? Bool, true)
        XCTAssertEqual(sniffing["destOverride"] as? [String], ["http", "tls", "quic"])
    }

    func testResolvesNonXhttpNoneProxyDomainsForRouteBootstrap() throws {
        let input = try jsonData([
            "inbounds": [["port": 10807, "protocol": "socks"]],
            "outbounds": [
                [
                    "tag": "proxy",
                    "protocol": "vless",
                    "settings": [
                        "vnext": [
                            [
                                "address": "reality.example.com",
                                "port": 443,
                                "users": [["id": "22222222-2222-4222-8222-222222222222", "encryption": "none"]]
                            ]
                        ]
                    ],
                    "streamSettings": ["network": "tcp", "security": "reality"]
                ]
            ]
        ])

        let result = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: input, credentials: Self.credentials) { host in
            host == "reality.example.com" ? "203.0.113.10" : nil
        })
        let output = try decodedObject(result.data)
        let proxy = try XCTUnwrap((output["outbounds"] as? [[String: Any]])?.first)
        let settings = try XCTUnwrap(proxy["settings"] as? [String: Any])
        let vnext = try XCTUnwrap(settings["vnext"] as? [[String: Any]])

        XCTAssertFalse(result.proxyUsesXhttp)
        XCTAssertEqual(vnext[0]["address"] as? String, "reality.example.com")
        XCTAssertEqual(result.bootstrapAddresses, ["203.0.113.10"])
        XCTAssertTrue(result.logMessages.contains("Configured system address DNS through the caller Core DNS policy"))
    }

    func testParsesInboundPortAndProxyServerAcrossProtocols() throws {
        let shadowsocks = try jsonData([
            "inbounds": [
                ["port": 10000, "protocol": "dokodemo-door"],
                ["port": 10820, "protocol": "http"]
            ],
            "outbounds": [
                ["tag": "direct", "protocol": "freedom"],
                [
                    "tag": "proxy",
                    "protocol": "shadowsocks",
                    "settings": [
                        "servers": [["address": "ss.example.com", "port": 8388]]
                    ]
                ]
            ]
        ])

        XCTAssertEqual(
            TunnelXrayConfigPreparer.parseConfig(jsonData: shadowsocks),
            TunnelParsedConfig(inboundPort: 10820, serverAddress: "ss.example.com")
        )
    }

    func testKeepsUdp443RuleIdempotent() throws {
        let input = try jsonData([
            "inbounds": [["port": 10807, "protocol": "socks"]],
            "outbounds": [
                [
                    "tag": "proxy",
                    "protocol": "vless",
                    "settings": [
                        "vnext": [
                            [
                                "address": "proxy.example.com",
                                "port": 2043,
                                "users": [["id": "22222222-2222-4222-8222-222222222222", "encryption": "none"]]
                            ]
                        ]
                    ],
                    "streamSettings": ["network": "xhttp", "security": "none"]
                ],
                ["tag": "blackhole", "protocol": "blackhole"]
            ],
            "routing": [
                "rules": [
                    [
                        "type": "field",
                        "network": "udp",
                        "port": "443",
                        "outboundTag": "blackhole"
                    ]
                ]
            ]
        ])

        let result = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: input, credentials: Self.credentials, resolveIPv4: { _ in "203.0.113.10" }))
        let output = try decodedObject(result.data)
        let routing = try XCTUnwrap(output["routing"] as? [String: Any])
        let rules = try XCTUnwrap(routing["rules"] as? [[String: Any]])

        XCTAssertEqual(rules.filter { ($0["network"] as? String) == "udp" && ($0["port"] as? String) == "443" && ($0["outboundTag"] as? String) == "blackhole" }.count, 1)
        XCTAssertFalse(result.logMessages.contains("Added XHTTP UDP/443 block rule to force browser TCP fallback"))
    }

    func testSharedOpaqueFieldsStayDataThroughActualPreparation() throws {
        var root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<10 {
            if FileManager.default.fileExists(atPath: root.appendingPathComponent("tool/fixtures/compatibility/opaque-fields.json").path) { break }
            root.deleteLastPathComponent()
        }
        let corpus = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: root.appendingPathComponent("tool/fixtures/compatibility/opaque-fields.json"))) as? [[String: Any]])
        XCTAssertEqual(corpus.count, 6)
        var checkedPaths = 0
        for fixture in corpus {
            let source = try XCTUnwrap(fixture["config"] as? [String: Any])
            let sourceData = try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys])
            let paths = try XCTUnwrap(fixture["opaquePaths"] as? [[String]])
            var calls = 0
            let prepared = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: sourceData, credentials: Self.credentials,
                resolveIPv4: { _ in calls += 1; return nil }), "Opaque data became an active feature: \(fixture["name"] ?? "")")
            var callerView = try decodedObject(prepared.data)
            var inbounds = try XCTUnwrap(callerView["inbounds"] as? [[String: Any]])
            let sourceInbounds = try XCTUnwrap(source["inbounds"] as? [[String: Any]])
            XCTAssertEqual(inbounds.count, sourceInbounds.count + 1)
            inbounds.removeFirst()
            callerView["inbounds"] = inbounds
            // DNS/transport guards precede the unchanged imported rule suffix.
            if let sourceRouting = source["routing"] as? [String: Any], let sourceRules = sourceRouting["rules"] as? [Any] {
                var routing = try XCTUnwrap(callerView["routing"] as? [String: Any])
                let rules = try XCTUnwrap(routing["rules"] as? [Any])
                XCTAssertGreaterThanOrEqual(rules.count, sourceRules.count)
                routing["rules"] = Array(rules.suffix(sourceRules.count))
                callerView["routing"] = routing
            }
            func subtree(_ object: Any, _ path: [String]) throws -> NSDictionary {
                var value: Any = object
                for component in path {
                    if let array = value as? [Any], let index = Int(component), array.indices.contains(index) { value = array[index] }
                    else { value = try XCTUnwrap((value as? [String: Any])?[component]) }
                }
                return try XCTUnwrap(value as? NSDictionary)
            }
            for path in paths {
                XCTAssertEqual(try subtree(callerView, path), try subtree(source, path), "Opaque subtree changed: \(path.joined(separator: "."))")
                checkedPaths += 1
            }
            XCTAssertEqual(calls, 0, "Numeric profiles must not invoke endpoint bootstrap")
            XCTAssertEqual(try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys]), sourceData)
        }
        XCTAssertEqual(checkedPaths, 18)
    }

    func testOpaqueDataDoesNotBypassRealTLSPrivacyOrLocalQUICDNSRefusal() throws {
        let opaque: [String: Any] = ["network": "MiXeD", "allowInsecure": "metadata", "type": "xicmp", "Origin": "quic+local://literal.invalid"]
        var source: [String: Any] = [
            "custom": opaque,
            "dns": ["servers": ["tcp://9.9.9.9"]],
            "inbounds": [["protocol": "http", "port": 10807, "listen": "127.0.0.1"]],
            "outbounds": [["tag": "proxy", "protocol": "socks", "settings": ["servers": [["address": "198.51.100.7", "port": 19090]]],
                "streamSettings": ["network": "tcp", "security": "tls", "tlsSettings": ["serverName": "tls.invalid", "allowInsecure": true, "masterKeyLog": "private-key.log"]]]]
        ]
        let before = try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys])
        var calls = 0
        let prepared = try XCTUnwrap(TunnelXrayConfigPreparer.prepare(jsonData: before, credentials: Self.credentials,
            resolveIPv4: { _ in calls += 1; return nil }))
        let output = try decodedObject(prepared.data)
        let outbound = try XCTUnwrap((output["outbounds"] as? [[String: Any]])?.first)
        let stream = try XCTUnwrap(outbound["streamSettings"] as? [String: Any])
        let tls = try XCTUnwrap(stream["tlsSettings"] as? [String: Any])
        XCTAssertNil(tls["allowInsecure"])
        XCTAssertEqual(tls["masterKeyLog"] as? String, "")
        XCTAssertEqual(output["custom"] as? NSDictionary, opaque as NSDictionary)
        XCTAssertEqual(try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys]), before)
        XCTAssertEqual(calls, 0)
        source["dns"] = ["servers": ["quic+local://9.9.9.9"]]
        let unsafe = try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys])
        XCTAssertNil(TunnelXrayConfigPreparer.prepare(jsonData: unsafe, credentials: Self.credentials,
            resolveIPv4: { _ in calls += 1; return nil }))
        XCTAssertEqual(calls, 0)
        XCTAssertEqual(try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys]), unsafe)
    }

    private static let vlessEncryption =
        "mlkem768x25519plus.native.1rtt.100-500-2000.75-0-100.80-0-5000.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

    private func jsonData(_ object: Any) throws -> Data {
        try JSONSerialization.data(withJSONObject: object, options: [])
    }

    private func decodedObject(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data, options: []) as? [String: Any])
    }
}

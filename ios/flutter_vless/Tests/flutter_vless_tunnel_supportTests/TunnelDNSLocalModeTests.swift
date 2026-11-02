import XCTest
@testable import flutter_vless_tunnel_support

final class TunnelDNSLocalModeTests: XCTestCase {
    private let path = TunnelEndpointPath(generation: 7, interfaceIndex: 4, interfaceName: "en0", supportsIPv4: true, supportsIPv6: true, supportsDNS: true)

    private func prepare(_ dns: [String: Any], path: TunnelEndpointPath?) -> [String: Any]? {
        var config: [String: Any] = ["dns": dns, "outbounds": [["tag": "blocked", "protocol": "blackhole"]],
            "routing": ["rules": [["inboundTag": ["caller-dns"], "outboundTag": "blocked"]]]]
        guard TunnelDNSPolicy.apply(to: &config, managedInboundTag: "managed", endpointPath: path, resolveIPv4: { _ in
            XCTFail("Static/numeric DNS must not use the physical resolver"); return nil
        }) != nil else { return nil }
        return config
    }

    func testLocalTCPDNSUsesClosedBoundPhysicalBranch() throws {
        for address in ["tcp+local://192.0.2.53", "TcP+LoCaL://[2001:db8::53]:5353"] {
            let source: [String: Any] = ["address": address, "tag": "caller-dns", "domains": ["domain:private.invalid"], "skipFallback": true, "queryStrategy": "UseIP"]
            let output = try XCTUnwrap(prepare(["servers": [source]], path: path))
            let dns = try XCTUnwrap(output["dns"] as? [String: Any])
            let entry = try XCTUnwrap((dns["servers"] as? [[String: Any]])?.first)
            let tag = try XCTUnwrap(entry["tag"] as? String)
            XCTAssertNotEqual(tag, "caller-dns")
            XCTAssertEqual(entry["address"] as? String, address.replacingOccurrences(of: "TcP+LoCaL", with: "tcp").replacingOccurrences(of: "tcp+local", with: "tcp"))
            XCTAssertEqual(entry["domains"] as? [String], source["domains"] as? [String])
            XCTAssertEqual(entry["skipFallback"] as? Bool, true)
            XCTAssertEqual(entry["queryStrategy"] as? String, "UseIP")
            let rules = try XCTUnwrap((output["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
            let owned = rules.filter { ($0["inboundTag"] as? [String]) == [tag] }
            XCTAssertEqual(owned.count, 2)
            let allow = owned[0], deny = owned[1]
            XCTAssertEqual(allow["network"] as? String, "tcp")
            XCTAssertEqual(allow["port"] as? String, address.contains("5353") ? "5353" : "53")
            XCTAssertEqual((allow["ip"] as? [String])?.count, 1)
            XCTAssertNil(allow["domain"])
            XCTAssertNotEqual(allow["outboundTag"] as? String, deny["outboundTag"] as? String)
            let physical = try XCTUnwrap((output["outbounds"] as? [[String: Any]])?.first { $0["tag"] as? String == allow["outboundTag"] as? String })
            XCTAssertEqual(physical["protocol"] as? String, "freedom")
            XCTAssertEqual(((physical["streamSettings"] as? [String: Any])?["sockopt"] as? [String: Any])?["interface"] as? String, "en0")
            let settings = try XCTUnwrap(physical["settings"] as? [String: Any])
            XCTAssertEqual(settings["domainStrategy"] as? String, address.contains("2001:") ? "ForceIPv6" : "ForceIPv4")
            let final = try XCTUnwrap(settings["finalRules"] as? [[String: Any]])
            XCTAssertEqual(final.count, 2)
            XCTAssertEqual(final[0]["ip"] as? [String], allow["ip"] as? [String])
            XCTAssertEqual(final[0]["action"] as? String, "allow")
            XCTAssertEqual(final[1]["action"] as? String, "block")
            XCTAssertEqual(rules.last?["outboundTag"] as? String, "blocked")
        }
    }

    func testLocalNamedHTTPSKeepsAuthorityTLSAndSelectionFields() throws {
        for scheme in ["https+local", "h2c+local"] {
            let address = "\(scheme)://resolver.invalid:8443/dns%2Fquery?tenant=one%2Btwo"
            let hosts: [String: Any] = ["resolver.invalid": "alias.invalid", "alias.invalid": ["192.0.2.53"]]
            let original: [String: Any] = ["AdDrEsS": address, "TaG": "caller-dns", "domains": [], "expectedIPs": ["192.0.2.0/24"], "timeoutMs": 1700, "skipFallback": true]
            let output = try XCTUnwrap(prepare(["hosts": hosts, "servers": [original]], path: path))
            let dns = try XCTUnwrap(output["dns"] as? [String: Any])
            XCTAssertEqual(dns["hosts"] as? NSDictionary, hosts as NSDictionary)
            let entry = try XCTUnwrap((dns["servers"] as? [[String: Any]])?.first)
            let remote = String(scheme.dropLast(6))
            XCTAssertEqual(entry["AdDrEsS"] as? String, address.replacingOccurrences(of: scheme + ":", with: remote + ":"))
            XCTAssertNil(entry["address"])
            XCTAssertNil(entry["tag"])
            XCTAssertNotEqual(entry["TaG"] as? String, "caller-dns")
            for name in ["domains", "expectedIPs", "timeoutMs", "skipFallback"] {
                XCTAssertEqual(entry[name] as? NSObject, original[name] as? NSObject)
            }
            let tag = try XCTUnwrap(entry["TaG"] as? String)
            let rules = try XCTUnwrap((output["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
            let allow = try XCTUnwrap(rules.first { ($0["inboundTag"] as? [String]) == [tag] })
            XCTAssertEqual(allow["domain"] as? [String], ["full:resolver.invalid"])
            XCTAssertEqual(allow["port"] as? String, "8443")
        }
    }

    func testLocalModesRequirePhysicalContextAndSafeStaticDestinationTransactionally() throws {
        let invalidPaths: [TunnelEndpointPath?] = [nil,
            .init(generation: 1, interfaceIndex: 0, interfaceName: "en0", supportsIPv4: true, supportsIPv6: true, supportsDNS: true),
            .init(generation: 1, interfaceIndex: 4, interfaceName: nil, supportsIPv4: true, supportsIPv6: true, supportsDNS: true)]
        for path in invalidPaths { XCTAssertNil(prepare(["servers": ["tcp+local://192.0.2.53"]], path: path)) }
        for dns: [String: Any] in [
            ["servers": ["tcp+local://unmapped.invalid"]],
            ["servers": ["https+local://unmapped.invalid/dns-query"]],
            ["hosts": ["resolver.invalid": "missing.invalid"], "servers": ["tcp+local://resolver.invalid"]],
            ["hosts": ["resolver.invalid": "resolver.invalid"], "servers": ["tcp+local://resolver.invalid"]],
            ["hosts": ["resolver.invalid": "192.0.2.53"], "servers": ["quic+local://resolver.invalid"]],
            ["servers": ["tcp+local://192.0.2.53:0"]],
            ["servers": ["tcp+local://192.0.2.53:65536"]]
        ] {
            var source: [String: Any] = ["dns": dns, "outbounds": [["tag": "blocked", "protocol": "blackhole"]]]
            let before = try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys])
            XCTAssertNil(TunnelDNSPolicy.apply(to: &source, managedInboundTag: "managed", endpointPath: path, resolveIPv4: { _ in XCTFail("Unsafe local DNS must fail before resolver"); return nil }))
            XCTAssertEqual(try JSONSerialization.data(withJSONObject: source, options: [.sortedKeys]), before)
        }
    }

    func testLocalDNSGeneratedTagsCannotAcquireCallerDefinitionsOrReferences() throws {
        var config: [String: Any] = ["dns": ["servers": [["address": "tcp+local://192.0.2.53", "tag": "shared"], ["address": "tcp://192.0.2.53", "tag": "shared"]]],
            "inbounds": [["protocol": "socks", "tag": "flutter-vless-local-dns-input"]],
            "outbounds": [["tag": "flutter-vless-local-dns-direct", "protocol": "blackhole"]],
            "routing": ["rules": [["inboundTag": ["flutter-vless-local-dns-input-1"], "outboundTag": "flutter-vless-bootstrap-block"], ["inboundTag": ["shared"], "outboundTag": "flutter-vless-local-dns-direct"]]]]
        _ = try XCTUnwrap(TunnelDNSPolicy.apply(to: &config, managedInboundTag: "managed", endpointPath: path, resolveIPv4: { _ in XCTFail("Numeric only"); return nil }))
        let entries = try XCTUnwrap((config["dns"] as? [String: Any])?["servers"] as? [[String: Any]])
        let tag = try XCTUnwrap(entries[0]["tag"] as? String)
        XCTAssertEqual(tag, "flutter-vless-local-dns-input-2")
        XCTAssertEqual(entries[1]["tag"] as? String, "shared")
        XCTAssertEqual(entries[1]["address"] as? String, "tcp://192.0.2.53")
        let outputs = try XCTUnwrap(config["outbounds"] as? [[String: Any]])
        XCTAssertEqual(Set(outputs.compactMap { $0["tag"] as? String }).count, outputs.count)
        let rules = try XCTUnwrap((config["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
        XCTAssertEqual(rules[1]["outboundTag"] as? String, "flutter-vless-local-dns-direct-1")
        XCTAssertEqual(rules[2]["outboundTag"] as? String, "flutter-vless-bootstrap-block-1")
    }

    func testURLPortHasCorePrecedenceAndOpaqueAuthoritySurvives() throws {
        for (url, expected) in [("tcp+local://192.0.2.53", "53"), ("tcp+local://192.0.2.53:", "53"),
                                ("tcp+local://192.0.2.53:5354", "5354"),
                                ("https+local://user:p%40ss@resolver.invalid:8443/dns-query?opaque=one%2Btwo", "8443")] {
            let source: [String: Any] = ["address": url, "port": 5353]
            let output = try XCTUnwrap(prepare(["servers": [source], "hosts": ["resolver.invalid": "192.0.2.53"]], path: path))
            let entry = try XCTUnwrap(((output["dns"] as? [String: Any])?["servers"] as? [[String: Any]])?.first)
            XCTAssertEqual(entry["port"] as? Int, 5353)
            XCTAssertEqual(entry["address"] as? String, url.replacingOccurrences(of: "+local:", with: ":"))
            let tag = try XCTUnwrap(entry["tag"] as? String)
            let rules = try XCTUnwrap((output["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
            XCTAssertEqual(rules.first { ($0["inboundTag"] as? [String]) == [tag] }?["port"] as? String, expected)
        }
        for server: [String: Any] in [["address": "tcp+local://192.0.2.53", "tag": 3],
            ["address": "tcp+local://192.0.2.53", "port": true],
            ["address": "tcp+local://192.0.2.53", "port": 3.5],
            ["address": "tcp+local://192.0.2.53", "port": -1],
            ["address": "tcp+local://192.0.2.53", "port": 65536],
            ["address": "tcp+local://192.0.2.53", "port": 53, "PORT": 5353],
            ["address": "tcp+local://192.0.2.53", "tag": "first", "TAG": "other"],
            ["address": "tcp+local://192.0.2.53:bad"], ["address": "tcp+local://192.0.2.53:-1"]] {
            XCTAssertNil(prepare(["servers": [server]], path: path))
        }
    }

    func testLocalDNSFamilySelectionHonorsUnderlayAndFiniteHosts() throws {
        let v4 = TunnelEndpointPath(generation: 1, interfaceIndex: 4, interfaceName: "en0", supportsIPv4: true, supportsIPv6: false, supportsDNS: true)
        let v6 = TunnelEndpointPath(generation: 1, interfaceIndex: 4, interfaceName: "en0", supportsIPv4: false, supportsIPv6: true, supportsDNS: true)
        for (path, expected, strategy) in [(v4, "192.0.2.53/32", "ForceIPv4"), (v6, "2001:db8::53/128", "ForceIPv6")] {
            let output = try XCTUnwrap(prepare(["servers": ["tcp+local://resolver.invalid"], "hosts": ["resolver.invalid": ["192.0.2.53", "2001:db8::53"]]], path: path))
            let physical = try XCTUnwrap((output["outbounds"] as? [[String: Any]])?.first { $0["protocol"] as? String == "freedom" })
            let settings = try XCTUnwrap(physical["settings"] as? [String: Any])
            XCTAssertEqual(settings["domainStrategy"] as? String, strategy)
            XCTAssertEqual((settings["finalRules"] as? [[String: Any]])?.first?["ip"] as? [String], [expected])
        }
        XCTAssertNil(prepare(["servers": ["tcp+local://[2001:db8::53]"]], path: v4))
        XCTAssertNil(prepare(["servers": ["tcp+local://192.0.2.53"]], path: v6))
    }

    func testMappedAddressesAreCanonicalAndMixedLoopbackBindingsRefuse() throws {
        let mapped = try XCTUnwrap(prepare(["servers": ["tcp+local://[::ffff:192.0.2.53]"]], path: path))
        let rules = try XCTUnwrap((mapped["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
        XCTAssertEqual(rules[1]["ip"] as? [String], ["192.0.2.53/32"])
        for mapping in [["127.0.0.1", "192.0.2.53"], ["::ffff:127.0.0.1", "192.0.2.53"]] {
            XCTAssertNil(prepare(["servers": ["tcp+local://resolver.invalid"], "hosts": ["resolver.invalid": mapping]], path: path))
        }
        let physical = try XCTUnwrap(prepare(["servers": ["tcp+local://192.0.2.53"]], path: path))
        XCTAssertTrue(TunnelDNSPolicy.requiresPhysicalInterfaceBinding(in: try JSONSerialization.data(withJSONObject: physical)))
        let loopback = try XCTUnwrap(prepare(["servers": ["tcp+local://127.0.0.1"]], path: path))
        XCTAssertFalse(TunnelDNSPolicy.requiresPhysicalInterfaceBinding(in: try JSONSerialization.data(withJSONObject: loopback)))
        let remote = try XCTUnwrap(prepare(["servers": ["tcp://192.0.2.53"]], path: nil))
        XCTAssertFalse(TunnelDNSPolicy.requiresPhysicalInterfaceBinding(in: try JSONSerialization.data(withJSONObject: remote)))
    }

    func testPhysicalBindingCapabilityInspectionFoldsKeysAndFailsClosed() throws {
        for document in [#"{"OUTBOUNDS":[{"STREAMSETTINGS":{"SOCKOPT":{"INTERFACE":"en0"}}}]}"#,
            #"{"outbounds":[{"streamSettings":{"sockopt":{"interface":"", "INTERFACE":"en0"}}}]}"#,
            #"{"outbounds":[{"streamSettings":{"sockopt":{"interface":3}}}]}"#,
            #"{"outbounds":[] ,"OUTBOUNDS":[]}"#, #"{"outbounds":{}}"#, #"{}"#, "broken JSON"] {
            XCTAssertTrue(TunnelDNSPolicy.requiresPhysicalInterfaceBinding(in: Data(document.utf8)), document)
        }
        for document in [#"{"outbounds":[{"streamSettings":{"sockopt":{"INTERFACE":""}}}]}"#,
            #"{"outbounds":[{"streamSettings":{"sockopt":{"INTERFACE":null}}}]}"#,
            #"{"outbounds":[{"protocol":"blackhole"}]}"#] {
            XCTAssertFalse(TunnelDNSPolicy.requiresPhysicalInterfaceBinding(in: Data(document.utf8)), document)
        }
    }

    func testRoutedDoHHostsAndSplitPolicyRemainCallerOwned() throws {
        let dns: [String: Any] = ["hosts": ["cloudflare-dns.com": "1.1.1.1", "dns.google": "8.8.8.8"], "queryStrategy": "UseIPv4",
            "servers": ["https://cloudflare-dns.com/dns-query", ["address": "https://cloudflare-dns.com/dns-query", "domains": []], ["address": "https://dns.google/dns-query", "domains": ["domain:1cfresh.com"]]]]
        let caller: [[String: Any]] = [["domain": ["domain:1cfresh.com"], "outboundTag": "direct"],
            ["type": "field", "ip": ["1.1.1.1"], "port": "443", "outboundTag": "proxy"],
            ["type": "field", "ip": ["8.8.8.8"], "port": "443", "outboundTag": "direct"]]
        var config: [String: Any] = ["dns": dns, "routing": ["rules": caller], "outbounds": [["protocol": "blackhole", "tag": "proxy"], ["protocol": "freedom", "tag": "direct"]]]
        XCTAssertNotNil(TunnelDNSPolicy.apply(to: &config, managedInboundTag: "managed", endpointPath: path, resolveIPv4: { _ in XCTFail("Explicit static DoH has no native lookup"); return nil }))
        XCTAssertEqual(config["dns"] as? NSDictionary, dns as NSDictionary)
        let rules = try XCTUnwrap((config["routing"] as? [String: Any])?["rules"] as? [[String: Any]])
        XCTAssertEqual(Array(rules.dropFirst()) as NSArray, caller as NSArray)
        XCTAssertEqual(rules[0]["ip"] as? [String], [TunnelDNSPolicy.virtualServer + "/32"])
        XCTAssertEqual((config["outbounds"] as? [[String: Any]])?.count, 3)
    }
}

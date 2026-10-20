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

final class TunnelCandidatePreparationTests: XCTestCase {
    private let credentials = try! LocalProxyCredentials(username: "candidate-session", password: "candidate-password")
    private func path(_ generation: UInt64 = 7, ipv4: Bool = false) -> TunnelEndpointPath {
        TunnelEndpointPath(generation: generation, interfaceIndex: 4, interfaceName: "en0", supportsIPv4: ipv4,
                           supportsIPv6: true, supportsDNS: true)
    }
    private func source(_ hosts: [String], interface: String? = nil, sendThrough: String? = nil) throws -> Data {
        let outbounds: [[String: Any]] = hosts.enumerated().map { index, host in
            var stream: [String: Any] = ["network": "tcp", "security": "tls",
                "tlsSettings": ["serverName": "identity.fixture.invalid", "masterKeyLog": "", "alpn": ["h2"]]]
            if let interface { stream["sockopt"] = ["interface": interface] }
            var outbound: [String: Any] = ["tag": index == 0 ? "proxy" : "secondary-\(index)", "protocol": "socks",
                "settings": ["servers": [["address": host, "port": 443]]], "streamSettings": stream]
            if let sendThrough { outbound["sendThrough"] = sendThrough }
            return outbound
        }
        return try JSONSerialization.data(withJSONObject: [
            "inbounds": [["tag": "caller", "protocol": "socks", "listen": "127.0.0.1", "port": 10808]],
            "dns": ["queryStrategy": "UseIP", "servers": [["address": "tcp://9.9.9.9", "domains": ["domain:caller.invalid"]]],
                    "hosts": ["full:caller.invalid": "192.0.2.53"]],
            "outbounds": outbounds, "routing": ["rules": [["domain": ["full:caller.invalid"], "outboundTag": "proxy"]]]
        ], options: [.sortedKeys])
    }
    private func named(_ text: String, received: Double = 100, until: Double? = 200) throws -> TunnelEndpointCandidate {
        TunnelEndpointCandidate(address: try XCTUnwrap(TunnelEndpointAddress(text: text, source: .systemNameAnswer)),
            origin: .systemNameAnswer, receivedAt: received, validUntil: until)
    }
    private func translated(_ text: String, original: String = "192.0.2.7") throws -> TunnelEndpointCandidate {
        TunnelEndpointCandidate(address: try XCTUnwrap(TunnelEndpointAddress(text: text, source: .systemIPv4Translation)),
            origin: .systemIPv4Translation(originalIPv4: original), receivedAt: 100)
    }
    private func object(_ data: Data) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }
    private func prepare(_ data: Data, on path: TunnelEndpointPath, selectedAttempt: UInt64 = 0,
                         now: @escaping () -> TimeInterval = { 100 },
                         resolve: (String) async throws -> TunnelEndpointCandidates) async throws -> TunnelPreparedConfig {
        try await TunnelXrayConfigPreparer.prepareForStartup(jsonData: data, credentials: credentials,
            tcpPortAvailable: { _ in true }, environmentSnapshot: XrayEnvironmentSnapshot(rawEntries: []),
            endpointPath: path, selectedAttempt: selectedAttempt, resolveCandidates: resolve,
            attempts: 1, retryDelay: { XCTFail("One candidate attempt must not retry") }, now: now)
    }

    func testCandidateNumericIPv4TranslationUsesPrivateIPv6PinAndExactExclusion() async throws {
        let input = try source(["192.0.2.7"]), underlay = path()
        var queries: [String] = []
        let answer = try translated("64:ff9b::c000:207")
        let prepared = try await prepare(input, on: underlay) { host in
            queries.append(host); return TunnelEndpointCandidates(path: underlay, candidates: [answer])
        }
        XCTAssertEqual(queries, ["192.0.2.7"])
        XCTAssertEqual(prepared.endpointPath, underlay)
        XCTAssertEqual(prepared.endpointSelections.map(\.selected), [answer])
        XCTAssertEqual(prepared.bootstrapAddresses, ["64:ff9b::c000:207"])
        let before = try object(input), after = try object(prepared.data)
        XCTAssertEqual(before["dns"] as? NSDictionary, after["dns"] as? NSDictionary)
        let caller = try XCTUnwrap((before["outbounds"] as? [[String: Any]])?.first)
        let outbounds = try XCTUnwrap(after["outbounds"] as? [[String: Any]])
        XCTAssertEqual(outbounds[0]["settings"] as? NSDictionary, caller["settings"] as? NSDictionary)
        XCTAssertEqual((outbounds[0]["streamSettings"] as? [String: Any])?["tlsSettings"] as? NSDictionary,
                       (caller["streamSettings"] as? [String: Any])?["tlsSettings"] as? NSDictionary)
        let leaf = try XCTUnwrap(outbounds.first { ($0["settings"] as? [String: Any])?["redirect"] as? String == "[64:ff9b::c000:207]:0" })
        XCTAssertEqual(((leaf["streamSettings"] as? [String: Any])?["sockopt"] as? [String: Any])?["interface"] as? String, "en0")
        let excluded = TunnelIPv6Policy.networkSettings(proxyAddresses: prepared.bootstrapAddresses).excludedRoutes ?? []
        XCTAssertEqual(excluded.count, 1)
        XCTAssertEqual(excluded.first?.destinationAddress, "64:ff9b::c000:207")
        XCTAssertEqual(excluded.first?.destinationNetworkPrefixLength, 128)
        XCTAssertEqual(try source(["192.0.2.7"]), input)
    }

    func testCandidateMixedRadixVisitsAllEndpointCombinations() async throws {
        let input = try source(["a.invalid", "b.invalid"]), underlay = path()
        let a = try [named("2001:db8::a"), named("2001:db8::b")]
        let b = try [named("2001:db8:1::a"), named("2001:db8:1::b")]
        let expected = [[a[0], b[0]], [a[1], b[0]], [a[0], b[1]], [a[1], b[1]]]
        for ordinal in 0..<4 {
            var queries: [String] = []
            let prepared = try await prepare(input, on: underlay, selectedAttempt: UInt64(ordinal)) { host in
                queries.append(host)
                return TunnelEndpointCandidates(path: underlay, candidates: host == "a.invalid" ? a : b)
            }
            XCTAssertEqual(queries, ["a.invalid", "b.invalid"])
            XCTAssertEqual(prepared.endpointSelections.map(\.logicalHost), queries)
            XCTAssertEqual(prepared.endpointSelections.map(\.selected), expected[ordinal])
            XCTAssertEqual(prepared.bootstrapAddresses, expected[ordinal].map { $0.address.text }.sorted())
        }
    }

    func testCandidateWrongGenerationNeverPublishesConfiguration() async throws {
        let input = try source(["a.invalid"]), requested = path(), stale = path(6)
        do {
            _ = try await prepare(input, on: requested) { _ in
                TunnelEndpointCandidates(path: stale, candidates: [try self.named("2001:db8::7")])
            }
            XCTFail("A stale path's answer was published")
        } catch TunnelXrayConfigPreparer.StartupError.endpointUnavailable {}
    }

    func testCandidateRevokedLookupIsCancellation() async throws {
        let admission = TunnelSessionAdmission(), underlay = path()
        let epoch = admission.begin(), input = try source(["a.invalid"])
        do {
            _ = try await TunnelXrayConfigPreparer.prepareForStartup(jsonData: input, credentials: credentials,
                tcpPortAvailable: { _ in true }, endpointPath: underlay, resolveCandidates: { _ in
                    admission.revoke(); await Task.yield()
                    return TunnelEndpointCandidates(path: underlay, candidates: [try self.named("2001:db8::7")])
                }, isCurrent: { admission.isCurrent(epoch) }, attempts: 1,
                retryDelay: { XCTFail("Revoked lookup retried") }, now: { 100 })
            XCTFail("Stopped session published candidates")
        } catch { XCTAssertTrue(error is CancellationError) }
    }

    func testCandidateExpiryDuringAnotherLookupCannotPublishStalePin() async throws {
        let input = try source(["a.invalid", "b.invalid"]), underlay = path()
        var clock: Double = 100
        do {
            _ = try await prepare(input, on: underlay, now: { clock }) { host in
                if host == "a.invalid" { return TunnelEndpointCandidates(path: underlay, candidates: [try self.named("2001:db8::a", until: 101)]) }
                clock = 102
                return TunnelEndpointCandidates(path: underlay, candidates: [try self.named("2001:db8::b", received: 102)])
            }
            XCTFail("Expired earlier endpoint was retained")
        } catch TunnelXrayConfigPreparer.StartupError.endpointUnavailable {}
    }

    func testCandidateZeroTTLIsFreshSingleAttemptOnly() async throws {
        let input = try source(["a.invalid"]), underlay = path()
        let fresh = try named("2001:db8::7", until: 100)
        var queries = 0
        for ordinal: UInt64 in [0, 1] {
            let prepared = try await prepare(input, on: underlay, selectedAttempt: ordinal) { _ in
                queries += 1; return TunnelEndpointCandidates(path: underlay, candidates: [fresh])
            }
            XCTAssertEqual(prepared.endpointSelections.first?.selected, fresh)
            XCTAssertTrue(try XCTUnwrap(prepared.endpointSelections.first?.selected).isSingleAttemptOnly)
        }
        XCTAssertEqual(queries, 2, "A later worker attempt must query again")
        do {
            _ = try await prepare(input, on: underlay) { _ in
                TunnelEndpointCandidates(path: underlay, candidates: [try self.named("2001:db8::7", received: 99, until: 99)])
            }
            XCTFail("Old zero-TTL answer was reused")
        } catch TunnelXrayConfigPreparer.StartupError.endpointUnavailable {}
    }

    func testCandidateFiltersUnavailableFamiliesWithoutChangingLogicalName() async throws {
        let input = try source(["a.invalid"]), underlay = path()
        let ipv4 = try named("192.0.2.7"), ipv6 = try named("2001:db8::7")
        let prepared = try await prepare(input, on: underlay) { _ in
            TunnelEndpointCandidates(path: underlay, candidates: [ipv4, ipv6])
        }
        XCTAssertEqual(prepared.endpointSelections.map(\.selected), [ipv6])
        XCTAssertEqual(prepared.bootstrapAddresses, [ipv6.address.text])
        let caller = try XCTUnwrap((try object(prepared.data)["outbounds"] as? [[String: Any]])?.first)
        XCTAssertEqual((((caller["settings"] as? [String: Any])?["servers"] as? [[String: Any]])?.first)?["address"] as? String, "a.invalid")
    }

    func testCandidateLiteralTranslationRequiresMatchingWitness() async throws {
        let input = try source(["192.0.2.7"]), underlay = path()
        for answer in [try translated("64:ff9b::c000:208", original: "192.0.2.8"), try named("2001:db8::7")] {
            do {
                _ = try await prepare(input, on: underlay) { _ in TunnelEndpointCandidates(path: underlay, candidates: [answer]) }
                XCTFail("Literal endpoint used an unrelated address")
            } catch TunnelXrayConfigPreparer.StartupError.endpointUnavailable {}
        }
    }

    func testCandidateConflictingCallerInterfaceOrSourceRefusesWithoutMutation() async throws {
        let underlay = path(), answer = try translated("64:ff9b::c000:207")
        for input in [try source(["192.0.2.7"], interface: "en8"), try source(["192.0.2.7"], sendThrough: "192.0.2.88")] {
            let before = input
            do {
                _ = try await prepare(input, on: underlay) { _ in TunnelEndpointCandidates(path: underlay, candidates: [answer]) }
                XCTFail("A conflicting caller binding was silently replaced")
            } catch TunnelXrayConfigPreparer.StartupError.invalidConfiguration {}
            XCTAssertEqual(before, input)
        }
    }

    func testCandidateLegacyTypedAPIStillSkipsNumericResolution() async throws {
        let input = try source(["192.0.2.7"])
        let prepared = try await TunnelXrayConfigPreparer.prepareForStartup(jsonData: input, credentials: credentials,
            tcpPortAvailable: { _ in true }, resolveEndpoint: { _ in XCTFail("Legacy numeric endpoint performed lookup"); return nil },
            attempts: 1, retryDelay: { XCTFail("Legacy numeric preparation retried") })
        XCTAssertEqual(prepared.bootstrapAddresses, ["192.0.2.7"])
        XCTAssertNil(prepared.endpointPath)
        XCTAssertTrue(prepared.endpointSelections.isEmpty)
    }

    func testCandidateLoopbackStaysLocalWithoutPhysicalFamilyOrInterface() async throws {
        let localPath = TunnelEndpointPath(generation: 7, interfaceIndex: 0, supportsIPv4: false,
                                           supportsIPv6: false, supportsDNS: false)
        for host in ["127.9.8.7", "::1"] {
            let input = try source([host])
            let local = TunnelEndpointCandidate(address: try XCTUnwrap(TunnelEndpointAddress(text: host, source: .literal)),
                origin: .literal, receivedAt: 100)
            var queries: [String] = []
            let prepared = try await prepare(input, on: localPath) { name in
                queries.append(name); return TunnelEndpointCandidates(path: localPath, candidates: [local])
            }
            XCTAssertEqual(queries, [host])
            XCTAssertEqual(prepared.endpointSelections.map(\.selected), [local])
            XCTAssertEqual(prepared.bootstrapAddresses, [host])
            let outbounds = try XCTUnwrap(try object(prepared.data)["outbounds"] as? [[String: Any]])
            XCTAssertFalse(outbounds.contains { ($0["settings"] as? [String: Any])?["redirect"] != nil })
            let sockopt = (outbounds[0]["streamSettings"] as? [String: Any])?["sockopt"] as? [String: Any]
            XCTAssertNil(sockopt?["interface"], "A local proxy must not be bound to the physical underlay")
        }
    }

    func testCandidateIndependentDownloadAndLogicalChainKeepTheirOwnPhysicalTargets() async throws {
        var config = try object(source(["logical.invalid"]))
        var outbounds = try XCTUnwrap(config["outbounds"] as? [[String: Any]])
        var parent = try XCTUnwrap(outbounds[0]["streamSettings"] as? [String: Any])
        parent["network"] = "xhttp"
        parent["sockopt"] = ["dialerProxy": "carrier"]
        let childTLS: [String: Any] = ["serverName": "download.identity.invalid", "masterKeyLog": ""]
        parent["xhttpSettings"] = ["path": "/upload", "downloadSettings": ["network": "xhttp", "address": "192.0.2.7", "port": 8443,
            "security": "tls", "tlsSettings": childTLS,
            "xhttpSettings": ["path": "/download", "downloadSettings": ["network": "xhttp", "address": "dormant.invalid", "port": 443]]]]
        outbounds[0]["streamSettings"] = parent
        outbounds.append(["tag": "carrier", "protocol": "socks", "settings": ["servers": [["address": "127.0.0.1", "port": 25252]]]])
        config["outbounds"] = outbounds
        let input = try JSONSerialization.data(withJSONObject: config), underlay = path()
        let download = try translated("64:ff9b::c000:207")
        let local = TunnelEndpointCandidate(address: try XCTUnwrap(TunnelEndpointAddress(text: "127.0.0.1", source: .literal)),
            origin: .literal, receivedAt: 100)
        var queries: [String] = []
        let prepared = try await prepare(input, on: underlay) { host in
            queries.append(host)
            return TunnelEndpointCandidates(path: underlay, candidates: host == "192.0.2.7" ? [download] : [local])
        }
        XCTAssertEqual(queries, ["192.0.2.7", "127.0.0.1"])
        XCTAssertEqual(prepared.endpointSelections.map(\.selected), [download, local])
        let preparedOutbounds = try XCTUnwrap(try object(prepared.data)["outbounds"] as? [[String: Any]])
        let preparedParent = try XCTUnwrap(preparedOutbounds[0]["streamSettings"] as? [String: Any])
        XCTAssertEqual((preparedParent["sockopt"] as? [String: Any])?["dialerProxy"] as? String, "carrier")
        let preparedChild = try XCTUnwrap((preparedParent["xhttpSettings"] as? [String: Any])?["downloadSettings"] as? [String: Any])
        XCTAssertEqual(preparedChild["address"] as? String, "192.0.2.7")
        XCTAssertEqual(preparedChild["tlsSettings"] as? NSDictionary, childTLS as NSDictionary)
        XCTAssertEqual((((preparedOutbounds[1]["streamSettings"] as? [String: Any])?["sockopt"]) as? [String: Any])?["interface"] as? String, nil)
    }


    func testCandidateDiscoveryUsesTheSameOrdinalAsFinalCallerSourceBinding() async throws {
        let underlay = path(ipv4: true)
        let input = try source(["a.invalid"], sendThrough: "192.0.2.88")
        let ipv6 = try named("2001:db8::7"), ipv4 = try named("192.0.2.7")
        let prepared = try await prepare(input, on: underlay, selectedAttempt: 1) { _ in
            TunnelEndpointCandidates(path: underlay, candidates: [ipv6, ipv4])
        }
        XCTAssertEqual(prepared.endpointSelections.map(\.selected), [ipv4])
        XCTAssertEqual(prepared.bootstrapAddresses, ["192.0.2.7"])
        let outbounds = try XCTUnwrap(try object(prepared.data)["outbounds"] as? [[String: Any]])
        let leaf = try XCTUnwrap(outbounds.first { ($0["settings"] as? [String: Any])?["redirect"] as? String == "192.0.2.7:0" })
        XCTAssertEqual(leaf["sendThrough"] as? String, "192.0.2.88")
    }

}
